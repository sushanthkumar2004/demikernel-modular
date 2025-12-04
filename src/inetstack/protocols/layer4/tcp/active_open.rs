// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    collections::{async_queue::SharedAsyncQueue, async_value::SharedAsyncValue},
    expect_some,
    inetstack::{
        config::TcpConfig,
        consts::{FALLBACK_MSS, MAX_HEADER_SIZE, MAX_WINDOW_SCALE},
        protocols::{
            layer3::SharedLayer3Endpoint,
            layer4::tcp::{
                established::{
                    congestion_control::{self, CongestionControl},
                    ctrlblk::ControlBlock,
                    tcp_events::{
                        create_control_block_for_syn_sent, dispatch_synack_in_synsent,
                        ActiveOpenConfig,
                    },
                    SharedEstablishedSocket,
                },
                header::{TcpHeader, TcpOptions2},
                SeqNumber,
            },
        },
    },
    runtime::{
        fail::Fail, memory::DemiBuffer, network::socket::option::TcpSocketOptions, SharedDemiRuntime, SharedObject,
    },
};
use ::futures::{select_biased, FutureExt};
use ::std::{
    net::{Ipv4Addr, SocketAddrV4},
    ops::{Deref, DerefMut},
};

//======================================================================================================================
// Structures
//======================================================================================================================

/// States of a connecting socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The socket is listening for new connections.
    Connecting,
    /// The socket is closed.
    Closed,
}

pub struct ActiveOpenSocket {
    local_isn: SeqNumber,
    local: SocketAddrV4,
    remote: SocketAddrV4,
    runtime: SharedDemiRuntime,
    layer3_endpoint: SharedLayer3Endpoint,
    recv_queue: SharedAsyncQueue<(Ipv4Addr, TcpHeader, DemiBuffer)>,
    tcp_config: TcpConfig,
    socket_options: TcpSocketOptions,
    state: SharedAsyncValue<State>,
}

#[derive(Clone)]
pub struct SharedActiveOpenSocket(SharedObject<ActiveOpenSocket>);

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl SharedActiveOpenSocket {
    pub fn new(
        local_isn: SeqNumber,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        runtime: SharedDemiRuntime,
        layer3_endpoint: SharedLayer3Endpoint,
        tcp_config: TcpConfig,
        default_socket_options: TcpSocketOptions,
    ) -> Result<Self, Fail> {
        // TODO: Add fast path here when remote is already in the ARP cache (and subtract one retry).

        Ok(Self(SharedObject::<ActiveOpenSocket>::new(ActiveOpenSocket {
            local_isn,
            local,
            remote,
            runtime: runtime.clone(),
            layer3_endpoint,
            recv_queue: SharedAsyncQueue::default(),
            tcp_config,
            socket_options: default_socket_options,
            state: SharedAsyncValue::new(State::Connecting),
        })))
    }

    /// Active open handshake using the modular component pattern.
    /// 
    /// Flow:
    ///   1. Create ControlBlock in SYN_SENT state
    ///   2. Send SYN
    ///   3. Wait for SYN+ACK
    ///   4. Process via dispatch_synack_in_synsent() (SYN_SENT → ESTABLISHED)
    ///   5. Send ACK
    ///   6. Create SharedEstablishedSocket from the evolved ControlBlock
    pub async fn connect(mut self) -> Result<SharedEstablishedSocket, Fail> {
        let handshake_retries: usize = self.tcp_config.get_handshake_retries();
        let handshake_timeout = self.tcp_config.get_handshake_timeout();

        // Calculate local window size
        let local_window_scale_bits = self.tcp_config.get_window_scale();
        debug_assert!((local_window_scale_bits as usize) <= MAX_WINDOW_SCALE);
        let local_window_size_bytes: u32 = expect_some!(
            (self.tcp_config.get_receive_window_size() as u32).checked_shl(local_window_scale_bits as u32),
            "Window size overflow"
        );

        // ========================================================================
        // STEP 1: Create ControlBlock in SYN_SENT state
        // ========================================================================
        let config = ActiveOpenConfig {
            local: self.local,
            remote: self.remote,
            tcp_config: self.tcp_config.clone(),
            socket_options: self.socket_options,
            local_isn: self.local_isn,
            ack_delay_timeout: self.tcp_config.get_ack_delay_timeout(),
            local_window_size_bytes,
            local_window_scale_bits,
        };
        let mut control_block = create_control_block_for_syn_sent(config, congestion_control::None::new);

        // Try to connect with retries
        for _ in 0..handshake_retries {
            // ========================================================================
            // STEP 2: Send SYN
            // ========================================================================
            let mut tcp_hdr = TcpHeader::new(self.local.port(), self.remote.port());
            tcp_hdr.syn = true;
            tcp_hdr.seq_num = self.local_isn;
            tcp_hdr.window_size = self.tcp_config.get_receive_window_size();

            let mss = self.tcp_config.get_advertised_mss() as u16;
            tcp_hdr.push_option(TcpOptions2::MaximumSegmentSize(mss));
            info!("Advertising MSS: {}", mss);

            tcp_hdr.push_option(TcpOptions2::WindowScale(self.tcp_config.get_window_scale()));
            info!("Advertising window scale: {}", self.tcp_config.get_window_scale());

            debug!("Sending SYN {:?}", tcp_hdr);
            let dst_ipv4_addr: Ipv4Addr = *self.remote.ip();
            let mut pkt: DemiBuffer = DemiBuffer::new_with_headroom(0, MAX_HEADER_SIZE as u16);
            tcp_hdr.serialize_and_attach(
                &mut pkt,
                self.local.ip(),
                self.remote.ip(),
                self.tcp_config.get_rx_checksum_offload(),
            );

            if let Err(e) = self
                .layer3_endpoint
                .transmit_tcp_packet_blocking(dst_ipv4_addr, pkt)
                .await
            {
                warn!("Could not send SYN: {:?}", e);
                continue;
            }

            // ========================================================================
            // STEP 3: Wait for SYN+ACK
            // ========================================================================
            let mut recv_queue: SharedAsyncQueue<(Ipv4Addr, TcpHeader, DemiBuffer)> = self.recv_queue.clone();
            let mut state: SharedAsyncValue<State> = self.state.clone();
            
            select_biased! {
                r = state.wait_for_change(None).fuse() => if let Ok(r) = r {
                    if r == State::Closed {
                        let cause: &'static str = "Closing socket while connecting";
                        warn!("{}", cause);
                        return Err(Fail::new(libc::ECONNABORTED, cause));
                    }
                },
                r = recv_queue.pop(Some(handshake_timeout)).fuse() => match r {
                    Ok((_, header, _)) => {
                        // Validate SYN+ACK
                        let expected_seq: SeqNumber = self.local_isn + SeqNumber::from(1);
                        
                        if !(header.ack && header.ack_num == expected_seq) {
                            let cause: String = format!(
                                "expected ack_num: {}, received ack_num: {}",
                                expected_seq, header.ack_num
                            );
                            error!("connect(): {}", cause);
                            continue; // Retry
                        }

                        if header.rst {
                            let cause: &'static str = "connection refused";
                            error!("connect(): {}", cause);
                            return Err(Fail::new(libc::ECONNREFUSED, cause));
                        }

                        if !header.syn {
                            let cause: &'static str = "is not a syn packet";
                            error!("connect(): {}", cause);
                            continue; // Retry
                        }

                        debug!("Received SYN+ACK: {:?}", header);

                        // Parse options
                        let mut remote_window_scale: Option<u8> = None;
                        let mut mss = FALLBACK_MSS;
                        for option in header.iter_options() {
                            match option {
                                TcpOptions2::WindowScale(w) => {
                                    info!("Received window scale: {}", w);
                                    remote_window_scale = Some(*w);
                                },
                                TcpOptions2::MaximumSegmentSize(m) => {
                                    info!("Received advertised MSS: {}", m);
                                    mss = *m as usize;
                                },
                                _ => continue,
                            }
                        }

                        let remote_window_scale_bits: u8 = match remote_window_scale {
                            Some(scale) => {
                                if scale as usize > MAX_WINDOW_SCALE {
                                    warn!(
                                        "remote window scale larger than {:?}, setting to {:?}. See RFC 1323.",
                                        MAX_WINDOW_SCALE, MAX_WINDOW_SCALE
                                    );
                                    MAX_WINDOW_SCALE as u8
                                } else {
                                    scale
                                }
                            },
                            None => 0,
                        };

                        // ========================================================================
                        // STEP 4: Process SYN+ACK using dispatcher (SYN_SENT → ESTABLISHED)
                        // Each component updates its own state:
                        //   - delivery.on_synack_in_synsent(): sets receive sequence numbers
                        //   - flow_control.on_synack_in_synsent(): sets peer's window info
                        //   - conn_mgmt.on_synack_in_synsent(): transitions to ESTABLISHED
                        // ========================================================================
                        if let Err(e) = dispatch_synack_in_synsent(
                            &mut control_block,
                            &header,
                            self.local_isn,
                            remote_window_scale_bits,
                            mss,
                        ) {
                            return Err(Fail::new(libc::EBADMSG, e));
                        }

                        // ========================================================================
                        // STEP 5: Send ACK
                        // ========================================================================
                        let remote_seq_num = header.seq_num + SeqNumber::from(1);
                        let mut ack_hdr = TcpHeader::new(self.local.port(), self.remote.port());
                        ack_hdr.ack = true;
                        ack_hdr.ack_num = remote_seq_num;
                        ack_hdr.window_size = self.tcp_config.get_receive_window_size();
                        ack_hdr.seq_num = self.local_isn + SeqNumber::from(1);
                        debug!("Sending ACK: {:?}", ack_hdr);

                        let mut ack_pkt: DemiBuffer = DemiBuffer::new_with_headroom(0, MAX_HEADER_SIZE as u16);
                        ack_hdr.serialize_and_attach(
                            &mut ack_pkt,
                            self.local.ip(),
                            self.remote.ip(),
                            self.tcp_config.get_rx_checksum_offload(),
                        );
                        self.layer3_endpoint
                            .transmit_tcp_packet_nonblocking(dst_ipv4_addr, ack_pkt)?;

                        // ========================================================================
                        // STEP 6: Create SharedEstablishedSocket from evolved ControlBlock
                        // ========================================================================
                        return SharedEstablishedSocket::new_from_control_block(
                            control_block,
                            self.runtime.clone(),
                            self.layer3_endpoint.clone(),
                            None,
                        );
                    },
                    Err(Fail { errno, cause: _ }) if errno == libc::ETIMEDOUT => continue,
                    Err(_) => {
                        unreachable!(
                            "either the ack deadline changed or the deadline passed, no other errors are possible!"
                        )
                    },
                }
            }
        }

        let cause: &'static str = "connection handshake timed out";
        error!("connect(): {}", cause);
        Err(Fail::new(libc::ECONNREFUSED, cause))
    }

    pub fn close(&mut self) {
        self.state.set(State::Closed);
    }

    /// Returns the addresses of the two ends of this connection.
    pub fn endpoints(&self) -> (SocketAddrV4, SocketAddrV4) {
        (self.local, self.remote)
    }

    pub fn receive(&mut self, ipv4_addr: Ipv4Addr, tcp_hdr: TcpHeader, buf: DemiBuffer) {
        self.recv_queue.push((ipv4_addr, tcp_hdr, buf))
    }
}

//======================================================================================================================
// Trait Implementations
//======================================================================================================================

impl Deref for SharedActiveOpenSocket {
    type Target = ActiveOpenSocket;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for SharedActiveOpenSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
