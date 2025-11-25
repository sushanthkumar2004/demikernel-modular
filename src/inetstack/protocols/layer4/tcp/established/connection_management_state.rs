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
    runtime::{fail::Fail, network::socket::option::TcpSocketOptions},
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

    /// Component-specific event handler for ACK received in FIN_WAIT_1 state.
    /// This method only modifies ConnectionManagementState and enforces component isolation.
    /// Reads from delivery_state but only writes to self.state.
    pub fn on_ack_in_finwait1(&mut self, delivery_state: &OrderedDeliveryState, header: &TcpHeader) {
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
                "ConnectionManagementState::on_ack_in_finwait1(): received duplicate ack ({:?}); unacked len = {:?}",
                header.ack_num,
                delivery_state.unacked_queue.len()
            );
        }
    }

    /// Component-specific event handler for ACK received in CLOSING state.
    /// This method only modifies ConnectionManagementState and enforces component isolation.
    pub fn on_ack_in_closing(&mut self, delivery_state: &OrderedDeliveryState, header: &TcpHeader) {
        // Same logic as FinWait1 - check if FIN is ACKed
        self.on_ack_in_finwait1(delivery_state, header);
    }

    /// Component-specific event handler for ACK received in LAST_ACK state.
    /// This method only modifies ConnectionManagementState and enforces component isolation.
    pub fn on_ack_in_lastack(&mut self, delivery_state: &OrderedDeliveryState, header: &TcpHeader) {
        // Same logic as FinWait1 - check if FIN is ACKed
        self.on_ack_in_finwait1(delivery_state, header);
    }

    /// Component-specific event handler for FIN received in ESTABLISHED state.
    pub fn on_fin_in_established(&mut self) -> Result<(), Fail> {
        self.state = State::CloseWait;
        Ok(())
    }

    /// Component-specific event handler for FIN received in FIN_WAIT_1 state.
    pub fn on_fin_in_finwait1(&mut self) -> Result<(), Fail> {
        self.state = State::Closing;
        Ok(())
    }

    /// Component-specific event handler for FIN received in FIN_WAIT_2 state.
    pub fn on_fin_in_finwait2(&mut self) -> Result<(), Fail> {
        self.state = State::TimeWait;
        Ok(())
    }

    /// Component-specific event handler for SYN received in LISTEN state (passive open).
    /// Sets the remote endpoint.
    pub fn on_syn_in_listen(&mut self, remote: SocketAddrV4) -> Result<(), Fail> {
        self.remote = remote;
        Ok(())
    }

    /// Component-specific event handler for SYN+ACK received in SYN_SENT state (active open).
    /// Transitions to ESTABLISHED state (implicitly - ControlBlock is being created).
    pub fn on_synack_in_synsent(&mut self) -> Result<(), Fail> {
        // No state change needed - we're creating the ControlBlock for ESTABLISHED
        Ok(())
    }

    /// Component-specific event handler for initiating local close (active close).
    /// Transitions from Established to FinWait1.
    pub fn on_local_close_start(&mut self) -> Result<(), Fail> {
        if self.state != State::Established {
            return Err(Fail::new(libc::EBADF, "socket is not in Established state"));
        }
        self.state = State::FinWait1;
        Ok(())
    }

    /// Component-specific event handler for initiating remote close (passive close).
    /// Transitions from CloseWait to LastAck.
    pub fn on_remote_close_start(&mut self) -> Result<(), Fail> {
        if self.state != State::CloseWait {
            return Err(Fail::new(libc::EBADF, "socket is not in CloseWait state"));
        }
        self.state = State::LastAck;
        Ok(())
    }

    /// Component-specific event handler for TIME_WAIT timeout.
    /// Transitions from TimeWait to Closed.
    pub fn on_timewait_timeout(&mut self) -> Result<(), Fail> {
        if self.state != State::TimeWait {
            return Err(Fail::new(libc::EBADF, "socket is not in TimeWait state"));
        }
        self.state = State::Closed;
        Ok(())
    }

    /// Legacy method - kept for backward compatibility during refactoring.
    /// Use component-specific on_ack_in_* methods instead.
    #[deprecated(note = "Use on_ack_in_finwait1, on_ack_in_closing, or on_ack_in_lastack instead")]
    pub fn process_ack_state_change(&mut self, delivery_state: &OrderedDeliveryState, header: &TcpHeader) {
        self.on_ack_in_finwait1(delivery_state, header);
    }
}
