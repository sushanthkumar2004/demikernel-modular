use std::{cmp, time::Instant};
use futures::{never::Never, pin_mut, select_biased, FutureExt};

use crate::{
    runtime::{conditional_yield_until, fail::Fail},
    inetstack::protocols::{
        layer4::tcp::{
            established::{
                congestion_control, flow_control_state::FlowControlState, ordered_delivery_state::OrderedDeliveryState,
                ctrlblk::ControlBlock,
                rto::RtoCalculator,
            },
            header::TcpHeader,
        }
    }
};

/// Congestion Control Parameters for TCP connection state
/// This struct has only public members because it includes state that must be accessed
/// by the other TCP modules.
pub struct CongestionControlState {
    #[allow(dead_code)]
    // Retransmission Timeout (RTO) calculator.
    pub rto_calculator: RtoCalculator,
    pub cc_algorithm: Box<dyn congestion_control::CongestionControl>,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl CongestionControlState {
    pub fn new(congestion_control_algorithm: Box<dyn congestion_control::CongestionControl>) -> Self {
        Self {
            rto_calculator: RtoCalculator::new(),
            cc_algorithm: congestion_control_algorithm,
        }
    }

    pub fn add_sample(&mut self, segment_initial_tx: Option<Instant>, now: Instant) {
        // Add sample for RTO if we have an initial transmit time.
        // Note that in the case of repacketization, an ack for the first byte is enough for the time sample because it still represents the RTO for that single byte.
        // TODO: TCP timestamp support.
        if let Some(initial_tx) = segment_initial_tx {
            self.rto_calculator.add_sample(now - initial_tx);
        }
    }

    pub fn process_ack_state_change(
        &mut self,
        delivery_state: &OrderedDeliveryState,
        header: &TcpHeader,
        now: Instant,
    ) {
        let send_unacknowledged = delivery_state.send_unacked.get();
        if send_unacknowledged < header.ack_num {
            // Iterate over the now acknowledged data and process samples to modify our control state parameters.
            // Convert the difference in sequence numbers into a u32.
            let bytes_acknowledged_u32: u32 = (header.ack_num - delivery_state.send_unacked.get()).into();
            // Convert that into a usize for counting bytes to remove from the unacked queue.
            let bytes_acknowledged = bytes_acknowledged_u32 as usize;
            // We will read over the data immutably, and add samples to our congestion control state
            let mut bytes_processed_so_far = 0usize;
            for segment in delivery_state.unacked_queue.values() {
                if (bytes_processed_so_far >= bytes_acknowledged) || segment.bytes.is_none() {
                    if segment.bytes.is_none() {
                        trace!(
                            "CongestionControlState::process_ack_state_change(): received a FIN,
                            bytes_processed_so_far={:?}, bytes_acknowledged={:?}",
                            bytes_processed_so_far,
                            bytes_acknowledged
                        );
                    }
                    break;
                }
                // If there is data then it is not a FIN packet and we must add a sample to congestion state
                if let Some(ref data) = segment.bytes {
                    bytes_processed_so_far += data.len();
                    self.add_sample(segment.initial_tx, now);
                }
            }
        } else {
            // Duplicate ACK (doesn't acknowledge anything new). We can mostly ignore this, except for fast-retransmit.
            trace!(
                "CongestionControlState::process_samples_on_ack(): received duplicate ack ({:?}); unacked len = {:?}",
                header.ack_num,
                delivery_state.unacked_queue.len()
            );
        }
    }

    pub fn get_open_window_size_bytes(
        &mut self,
        delivery: &OrderedDeliveryState,
        flow_control: &FlowControlState,
    ) -> usize {
        // Calculate amount of data in flight (SND.NXT - SND.UNA).
        let send_unacknowledged = delivery.send_unacked.get();
        let send_next = delivery.send_next_seq_no.get();
        let sent_data = (send_next - send_unacknowledged).into();

        // Before we get cwnd for the check, we prompt it to shrink it if the connection has been idle.
        self.cc_algorithm.on_cwnd_check_before_send();
        let cwnd = self.cc_algorithm.get_cwnd();

        // The limited transmit algorithm can increase the effective size of cwnd by up to 2MSS.
        let effective_cwnd = cwnd.get() + self.cc_algorithm.get_limited_transmit_cwnd_increase().get();

        let win_sz = flow_control.send_window.get();

        if Self::has_open_window(win_sz, sent_data, effective_cwnd) {
            Self::calculate_open_window_bytes(win_sz, sent_data, flow_control.mss, effective_cwnd)
        } else {
            0
        }
    }

    fn has_open_window(win_sz: u32, sent_data: u32, effective_cwnd: u32) -> bool {
        win_sz > 0 && win_sz >= sent_data && effective_cwnd >= sent_data
    }

    fn calculate_open_window_bytes(win_sz: u32, sent_data: u32, mss: usize, effective_cwnd: u32) -> usize {
        cmp::min(
            cmp::min((win_sz - sent_data) as usize, mss),
            (effective_cwnd - sent_data) as usize,
        )
    }

    pub fn get_max_frame_size(&mut self, delivery: &OrderedDeliveryState, flow_control: &FlowControlState) -> usize {
        let max_frame_size_bytes = self.get_open_window_size_bytes(delivery, flow_control);
        let rto = self.rto_calculator.rto();
        self.cc_algorithm.on_send(
            rto,
            (delivery.send_next_seq_no.get() - delivery.send_unacked.get()).into(),
        );
        max_frame_size_bytes
    }

    pub async fn background_retransmitter_cc(
        cb: &mut ControlBlock
    ) -> Result<Never, Fail> {
        // Watch the retransmission deadline.
        let mut rtx_deadline_watched = cb.delivery.retransmit_deadline_time_secs.clone(); 
        // Watch the fast retransmit flag.
        let mut rtx_fast_retransmit_watched = cb.congestion_control.cc_algorithm.get_retransmit_now_flag();
        loop {
            let rtx_deadline = rtx_deadline_watched.get();
            let rtx_fast_retransmit = rtx_fast_retransmit_watched.get();
            if rtx_fast_retransmit {
                // Notify congestion control about fast retransmit.
                cb.congestion_control.cc_algorithm.on_fast_retransmit();
                continue;
            }

            // If either changed, wake up.
            let something_changed = async {
                select_biased!(
                    _ = rtx_deadline_watched.wait_for_change(None).fuse() => (),
                    _ = rtx_fast_retransmit_watched.wait_for_change(None).fuse() => (),
                )
            };
            pin_mut!(something_changed);
            match conditional_yield_until(something_changed, rtx_deadline).await {
                Ok(()) => match cb.delivery.sender_fin_seq_no {
                    Some(fin_seq_no) if cb.delivery.send_unacked.get() > fin_seq_no => {
                        return Err(Fail::new(libc::ECONNRESET, "connection closed"));
                    },
                    _ => continue,
                },
                Err(Fail { errno, cause: _ }) if errno == libc::ETIMEDOUT => {
                    // Retransmit timeout.
                    // Notify congestion control about RTO.
                    cb.congestion_control
                        .cc_algorithm
                        .on_rto(cb.delivery.send_unacked.get());

                    // RFC 6298 Section 5.5: Back off the retransmission timer.
                    cb.congestion_control.rto_calculator.back_off();
                },
                Err(_) => {
                    unreachable!(
                        "either the retransmit deadline changed or the deadline passed, no other errors are possible!"
                    )
                },
            }
        }
    }

}
