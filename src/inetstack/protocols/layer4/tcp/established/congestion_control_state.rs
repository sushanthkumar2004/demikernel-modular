use std::time::Instant;

use crate::inetstack::protocols::layer4::tcp::{
    established::{congestion_control, ordered_delivery_state::OrderedDeliveryState, rto::RtoCalculator},
    header::TcpHeader,
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
}
