// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use crate::{
    inetstack::{
        config::TcpConfig,
        protocols::layer4::tcp::{
            established::{
                congestion_control_state::CongestionControlState, delivery_state::DeliveryState,
                flow_control_state::FlowControlState,
            },
            header::TcpHeader,
            SeqNumber,
        },
    },
    runtime::{fail::Fail, network::socket::option::TcpSocketOptions},
};
use ::std::net::SocketAddrV4;
use std::time::Instant;

//======================================================================================================================
// Structures
//======================================================================================================================

/// TCP Connection State.
/// Note: This ControlBlock structure is only used after we've reached the ESTABLISHED state, so states LISTEN,
/// SYN_RCVD, and SYN_SENT aren't included here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

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

    fn process_acked_fin(&mut self, delivery: &DeliveryState, bytes_remaining: usize, ack_num: SeqNumber) -> usize {
        // This buffer is the end-of-send marker.  So we should only have one byte of acknowledged
        // sequence space remaining (corresponding to our FIN).
        debug_assert_eq!(bytes_remaining, 1);

        // Double check that the ack is for the FIN sequence number.
        debug_assert_eq!(
            ack_num,
            delivery
                .sender
                .fin_seq_no
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

        0
    }

    pub fn process_multiple_acked_fins(&mut self, delivery_state: &DeliveryState, header: &TcpHeader) {
        // Start by checking that the ACK acknowledges something new.
        let send_unacknowledged = delivery_state.sender.send_unacked.get();
        if send_unacknowledged < header.ack_num {
            // Convert the difference in sequence numbers into a u32.
            let bytes_acknowledged_u32: u32 = (header.ack_num - delivery_state.sender.send_unacked.get()).into();
            // Convert that into a usize for counting bytes to remove from the unacked queue.
            let bytes_acknowledged = bytes_acknowledged_u32 as usize;

            // We will read over the data immutably, and add samples to our congestion control state
            let mut bytes_processed_so_far = 0usize;

            for segment in delivery_state.sender.unacked_queue.values() {
                if bytes_processed_so_far >= bytes_acknowledged {
                    // TODO: Add debug statement here since this means that we received a FIN
                    // before we finished processing all samples. In this case we should stop processing
                    // more samples in control state and prepare a state transition.
                    break;
                }

                // If we process an ACKED FIN before we finish processing all the bytes_acknowledged, then
                // we should state transition and instantly break
                if segment.bytes.is_none() {
                    self.process_acked_fin(
                        delivery_state,
                        bytes_acknowledged - bytes_processed_so_far,
                        header.ack_num,
                    );
                    break;
                }

                // If there is data then it is not a FIN packet and we must add a sample to congestion state
                if let Some(ref data) = segment.bytes {
                    bytes_processed_so_far += data.len();
                }
            }
        } else {
            // Duplicate ACK (doesn't acknowledge anything new).  We can mostly ignore this, except for fast-retransmit.
            // TODO: Implement fast-retransmit.  In which case, we'd increment our dup-ack counter here.
            trace!(
                "process_multiple_acked_fins(): received duplicate ack ({:?}); unacked len = {:?}",
                header.ack_num,
                delivery_state.sender.unacked_queue.len()
            );
        }
    }
}

/// Transmission control block for representing our TCP connection.
/// This struct has only public members because includes state for both the send and receive path and is accessed by
/// both.
pub struct ControlBlock {
    // Connection management state, which mainly includes
    // connection constants for TCP
    pub connection_management: ConnectionManagementState,
    pub delivery: DeliveryState,

    // Flow control state
    pub flow_control: FlowControlState,

    // Congestion control state
    pub congestion_control: CongestionControlState,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl ControlBlock {
    pub fn new(
        connection_management: ConnectionManagementState,
        delivery: DeliveryState,
        flow_control: FlowControlState,
        congestion_control: CongestionControlState,
    ) -> Self {
        Self {
            connection_management,
            delivery,
            flow_control,
            congestion_control,
        }
    }

    // Check the ACK bit.
    pub fn check_and_process_ack(&mut self, header: &TcpHeader, now: Instant) -> Result<(), Fail> {
        if !header.ack {
            // All segments on established connections should be ACKs.  Drop this segment.
            let cause = "Received non-ACK segment on established connection";
            error!("{}", cause);
            return Err(Fail::new(libc::EBADMSG, cause));
        }

        // TODO: RFC 5961 "Blind Data Injection Attack" prevention would have us perform additional ACK validation
        // checks here.

        self.process_ack(header, now);

        Ok(())
    }

    // Processing of ACK is done here since all 4 module's state must be updated on ACK ingress
    pub fn process_ack(&mut self, header: &TcpHeader, now: Instant) {
        // Check and update send window if necessary.
        self.flow_control.update_send_window(header);
        self.congestion_control
            .process_samples_on_ack(&self.delivery, header, now);
        self.connection_management
            .process_multiple_acked_fins(&self.delivery, header);
        self.delivery
            .sender
            .update_on_ack(&self.congestion_control, header, now);
    }
}
