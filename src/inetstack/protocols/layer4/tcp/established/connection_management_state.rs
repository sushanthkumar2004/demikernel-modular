use std::net::SocketAddrV4;

use crate::{
    inetstack::{
        config::TcpConfig,
        protocols::layer4::tcp::{
            established::{ctrlblk::State, ordered_delivery_state::OrderedDeliveryState},
            header::TcpHeader,
            SeqNumber,
        },
    },
    runtime::network::socket::option::TcpSocketOptions,
};

/// State block representing connection management parameters in a TCP connection.
/// This struct has only public members since these parameters must be read by all TCP
/// modules.
pub struct ConnectionManagementState {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub tcp_config: TcpConfig,
    pub socket_options: TcpSocketOptions,
    pub state: State,
}

impl ConnectionManagementState {
    /// Create a new ConnectionManagementState in ESTABLISHED state.
    /// Used when ControlBlock is created at the end of the handshake.
    pub fn new(
        local: SocketAddrV4,
        remote: SocketAddrV4,
        tcp_config: TcpConfig,
        socket_options: TcpSocketOptions,
    ) -> Self {
        Self {
            local,
            remote,
            tcp_config,
            socket_options,
            state: State::Established,
        }
    }

    /// Create a new ConnectionManagementState in LISTEN state (passive open).
    /// Used when ControlBlock is created at the start of the handshake.
    pub fn new_listen(
        local: SocketAddrV4,
        tcp_config: TcpConfig,
        socket_options: TcpSocketOptions,
    ) -> Self {
        Self {
            local,
            remote: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            tcp_config,
            socket_options,
            state: State::Listen,
        }
    }

    /// Create a new ConnectionManagementState in SYN_SENT state (active open).
    /// Used when ControlBlock is created at the start of the handshake.
    pub fn new_syn_sent(
        local: SocketAddrV4,
        remote: SocketAddrV4,
        tcp_config: TcpConfig,
        socket_options: TcpSocketOptions,
    ) -> Self {
        Self {
            local,
            remote,
            tcp_config,
            socket_options,
            state: State::SynSent,
        }
    }

    fn process_acked_fin(&mut self, delivery_state: &OrderedDeliveryState, bytes_remaining: usize, ack_num: SeqNumber) {
        // This buffer is the end-of-send marker.  So we should only have one byte of acknowledged
        // sequence space remaining (corresponding to our FIN).
        debug_assert_eq!(bytes_remaining, 1);

        // Double check that the ack is for the FIN sequence number.
        debug_assert_eq!(
            ack_num,
            delivery_state
                .sender_fin_seq_no
                .map(|s| { s + 1.into() })
                .expect("should have a FIN set")
        );

        self.state = match self.state {
            State::FinWait1 => State::FinWait2,
            State::Closing => State::TimeWait,
            State::LastAck => State::Closed,
            state => unreachable!(
                "cannot receive a response to a FIN if one was not sent in state {:?}",
                state
            ),
        };
    }

    pub fn process_ack_state_change(&mut self, delivery_state: &OrderedDeliveryState, header: &TcpHeader) {
        let send_unacknowledged = delivery_state.send_unacked.get();

        // Check if ACK asserted something new
        if send_unacknowledged < header.ack_num {
            // Convert the difference in sequence numbers into a u32.
            let bytes_acknowledged_u32: u32 = (header.ack_num - delivery_state.send_unacked.get()).into();

            // Convert that into a usize for counting bytes to remove from the unacked queue.
            let bytes_acknowledged = bytes_acknowledged_u32 as usize;
            let mut bytes_processed_so_far = 0usize;

            for segment in delivery_state.unacked_queue.values() {
                // In this case we have finished processing the newly acknowledged bytes
                if bytes_processed_so_far >= bytes_acknowledged {
                    break;
                }

                // If we process an ACKED FIN before we finish processing all the bytes_acknowledged, then
                // we should state transition and instantly break. Furthermore, note that
                // bytes_acknowledged - bytes_processed_so_far must equal 1 for us to correctly process the FIN
                if segment.bytes.is_none() {
                    self.process_acked_fin(
                        delivery_state,
                        bytes_acknowledged - bytes_processed_so_far,
                        header.ack_num,
                    );
                    break;
                }

                // If there is data then it is not a FIN packet and we must add it to the number of bytes
                // we have seen so far.
                if let Some(ref data) = segment.bytes {
                    bytes_processed_so_far += data.len();
                }
            }
        } else {
            // Duplicate ACK received.
            trace!(
                "ConnectionManagementState::process_ack_state_change(): received duplicate ack ({:?}); unacked len = {:?}",
                header.ack_num,
                delivery_state.unacked_queue.len()
            );
        }
    }

    //======================================================================================================================
    // Handshake State Transitions - Component Methods
    //======================================================================================================================

    /// Handle SYN received while in LISTEN state.
    /// Transitions: LISTEN → SYN_RECEIVED
    /// Only modifies: self.remote, self.state
    pub fn on_syn_in_listen(&mut self, remote: SocketAddrV4) {
        debug_assert_eq!(self.state, State::Listen, "on_syn_in_listen called in wrong state");
        self.remote = remote;
        self.state = State::SynReceived;
    }

    /// Handle SYN+ACK received while in SYN_SENT state (active open completion).
    /// Transitions: SYN_SENT → ESTABLISHED
    /// Only modifies: self.state
    pub fn on_synack_in_synsent(&mut self) {
        debug_assert_eq!(self.state, State::SynSent, "on_synack_in_synsent called in wrong state");
        self.state = State::Established;
    }

    /// Handle ACK received while in SYN_RECEIVED state (passive open completion).
    /// Transitions: SYN_RECEIVED → ESTABLISHED
    /// Only modifies: self.state
    pub fn on_ack_in_synrcvd(&mut self) {
        debug_assert_eq!(self.state, State::SynReceived, "on_ack_in_synrcvd called in wrong state");
        self.state = State::Established;
    }
}

