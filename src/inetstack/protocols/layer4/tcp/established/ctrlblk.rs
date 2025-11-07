// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use std::time::Instant;

use futures::{never::Never, FutureExt};

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
    runtime::{fail::Fail, memory::DemiBuffer, SharedDemiRuntime},
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

    async fn send_buffer(
        &mut self,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        now: Instant,
        mut buffer: DemiBuffer,
    ) -> Result<(), Fail> {
        let mut send_unacked_watched = self.delivery.send_unacked.clone();
        let mut cwnd_watched = self.congestion_control.cc_algorithm.get_cwnd();

        // The limited transmit algorithm may increase the effective size of cwnd by up to 2 * mss.
        let mut ltci_watched = self
            .congestion_control
            .cc_algorithm
            .get_limited_transmit_cwnd_increase();
        let mut win_sz_watched = self.flow_control.send_window.clone();

        // Try in a loop until we send this segment.
        loop {
            // If we don't have any window size at all, we need to transition to PERSIST mode and
            // repeatedly send window probes until window opens up.
            if win_sz_watched.get() == 0 {
                // Send a window probe (this is a one-byte packet designed to elicit a window update from our peer).
                self.delivery
                    .send_window_probe(
                        &self.flow_control,
                        &self.connection_management,
                        layer3_endpoint,
                        now,
                        buffer.split_front(1)?,
                    )
                    .await?;
            } else {
                // TODO: Nagle's algorithm - We need to coalese small buffers together to send MSS sized packets.
                // TODO: Silly window syndrome - See RFC 1122's discussion of the SWS avoidance algorithm.

                // We have some window, try to send some or all of the segment.
                // NOTE: Following function modifies congestion control state, and then
                // the ordered delivery state in that order. Modularity still holds since within the loop
                // we will either only modify ROD state or we will modify CC, then ROD state.
                let _ = self.send_segment(layer3_endpoint, now, &mut buffer);
                // If the buffer is now empty, then we sent all of it.
                if buffer.is_empty() {
                    return Ok(());
                }
                // Otherwise, wait until something limiting the window changes and then try again to finish sending
                // the segment.
                futures::select_biased! {
                    _ = send_unacked_watched.wait_for_change(None).fuse() => (),
                    _ = self.delivery.send_next_seq_no.wait_for_change(None).fuse() => (),
                    _ = win_sz_watched.wait_for_change(None).fuse() => (),
                    _ = cwnd_watched.wait_for_change(None).fuse() => (),
                    _ = ltci_watched.wait_for_change(None).fuse() => (),
                };
            }
        }
    }

    pub async fn background_sender(
        &mut self,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        runtime: &mut SharedDemiRuntime,
    ) -> Result<Never, Fail> {
        loop {
            // Get next bit of unsent data.
            let buffer = self.delivery.unsent_queue.pop(None).await?;
            self.send_buffer(layer3_endpoint, runtime.now(), buffer).await?;
        }
    }
}
