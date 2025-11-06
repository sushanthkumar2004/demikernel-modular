// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use std::time::Instant;

use arrayvec::ArrayVec;

use crate::{
    inetstack::{
        consts::MAX_BATCH_SIZE_NUM_PACKETS,
        protocols::{
            layer3::SharedLayer3Endpoint,
            layer4::tcp::{
                established::{
                    congestion_control_state::CongestionControlState,
                    connection_management_state::ConnectionManagementState,
                    flow_control_state::FlowControlState,
                    ordered_delivery_state::{OrderedDeliveryState, UNSENT_QUEUE_CUTOFF},
                },
                header::TcpHeader,
            },
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

    // This function sends a list of packets (or FIN if empty) and waits for it to be acked.
    pub async fn push(
        &mut self,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        runtime: &mut SharedDemiRuntime,
        bufs: ArrayVec<DemiBuffer, MAX_BATCH_SIZE_NUM_PACKETS>,
    ) -> Result<(), Fail> {
        // If the user is done sending (i.e. has called close on this connection), then they shouldn't be sending.
        debug_assert!(self.delivery.sender_fin_seq_no.is_none());

        // TODO: We need to fix this the correct way: limit our send buffer size to the amount we're willing to buffer.
        if self.delivery.unsent_queue.len() > UNSENT_QUEUE_CUTOFF - 1 {
            return Err(Fail::new(libc::EBUSY, "too many packets to send"));
        }

        trace!("push(): total unsent segments={:?}", self.delivery.unsent_queue.len());

        // Check if closing the socket and sending FIN.
        if bufs.is_empty() {
            // We can always send the FIN immediately.
            self.delivery.sender_fin_seq_no = Some(self.delivery.unsent_next_seq_no);
            self.delivery.unsent_next_seq_no = self.delivery.unsent_next_seq_no + 1.into();
            self.delivery.send_fin(
                &self.congestion_control,
                &self.connection_management,
                layer3_endpoint,
                runtime.now(),
            )?;
        } else {
            for mut buf in bufs.into_iter() {
                self.delivery.unsent_next_seq_no = self.delivery.unsent_next_seq_no + (buf.len() as u32).into();
                if self.flow_control.send_window.get() > 0 {
                    self.send_segment(layer3_endpoint, runtime.now(), &mut buf);

                    if !buf.is_empty() {
                        self.delivery.unsent_queue.push(buf);
                    }
                }
            }
        }

        if !self.delivery.unacked_queue.is_empty() {
            trace!("push(): total unacked segments={:?}", self.delivery.unacked_queue.len());
        }

        // Wait until the sequnce number of the pushed buffer is acknowledged.
        let mut send_unacked_watched = self.delivery.send_unacked.clone();
        let ack_seq_no = self.delivery.unsent_next_seq_no;
        debug_assert!(send_unacked_watched.get() < ack_seq_no);
        while send_unacked_watched.get() < ack_seq_no {
            send_unacked_watched.wait_for_change(None).await?;
        }
        Ok(())
    }
}
