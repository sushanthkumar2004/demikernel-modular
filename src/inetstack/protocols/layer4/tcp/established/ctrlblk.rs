// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use std::time::Instant;

use crate::{
    inetstack::protocols::{
        layer3::SharedLayer3Endpoint,
        layer4::tcp::{
            established::{
                congestion_control_state::CongestionControlState,
                connection_management_state::ConnectionManagementState, flow_control_state::FlowControlState,
                ordered_delivery_state::OrderedDeliveryState,
            },
            header::TcpHeader,
        },
    },
    runtime::{fail::Fail, memory::DemiBuffer},
};

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

/// Transmission control block for representing our TCP connection.
/// This struct has only public members because includes state for both the send and receive path and is accessed by
/// both.
pub struct ControlBlock {
    // Connection management state, which mainly includes
    // connection constants for TCP
    pub connection_management: ConnectionManagementState,
    pub delivery: OrderedDeliveryState,

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
        delivery: OrderedDeliveryState,
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

    fn process_ack(&mut self, header: &TcpHeader, now: Instant) {
        // Check and update send window if necessary.
        self.flow_control.update_send_window(header);
        self.connection_management
            .process_ack_state_change(&self.delivery, header);
        self.congestion_control
            .process_ack_state_change(&self.delivery, header, now);

        self.delivery
            .process_ack_state_change(&self.congestion_control, header, now);
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

    // Takes a segment and attempts to send it. The buffer must be non-zero length and the function returns the number
    // of bytes sent.
    pub fn send_segment(
        &mut self,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        now: Instant,
        segment: &mut DemiBuffer,
    ) -> usize {
        debug_assert!(!segment.is_empty());

        let max_frame_size_bytes = self
            .congestion_control
            .get_max_frame_size(&self.delivery, &self.flow_control);

        self.delivery.transmit_segment(
            &self.connection_management,
            &self.congestion_control,
            layer3_endpoint,
            now,
            segment,
            max_frame_size_bytes,
        )
    }
}
