use crate::{
    inetstack::{
        consts::MAX_HEADER_SIZE,
        protocols::{
            layer3::SharedLayer3Endpoint,
            layer4::tcp::{
                established::{
                    ctrlblk::{ConnectionManagementState, ControlBlock, State},
                    receiver::Receiver,
                    sender::Sender,
                },
                header::TcpHeader,
                SeqNumber,
            },
        },
    },
    runtime::{fail::Fail, memory::DemiBuffer},
};

pub struct DeliveryState {
    pub sender: Sender,
    pub receiver: Receiver,
}

/// Contains methods that modify both receiver and sender state. Methods that modify only one
/// substate (Sender or Receiver) will be in the corresponding class instead.
impl DeliveryState {
    pub fn new(sender: Sender, receiver: Receiver) -> Self {
        Self { sender, receiver }
    }

    /// Transmit this message to our connected peer.
    /// Required to be a method of DeliveryState since the emit
    /// resets the receiver's ACK deadline.
    pub fn emit(
        &mut self,
        connection_management: &ConnectionManagementState,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        header: TcpHeader,
        body: Option<DemiBuffer>,
    ) {
        // Only perform this debug print in debug builds.  debug_assertions is compiler set in non-optimized builds.
        let mut pkt = match body {
            Some(body) => {
                debug!(
                    "L4 OUTGOING {:?} Connection sending {} bytes + {:?}",
                    connection_management.state,
                    body.len(),
                    header
                );
                body
            },
            _ => {
                debug!(
                    "L4 OUTGOING {:?} Connection sending 0 bytes + {:?}",
                    connection_management.state, header
                );
                DemiBuffer::new_with_headroom(0, MAX_HEADER_SIZE as u16)
            },
        };

        // This routine should only ever be called to send TCP segments that contain a valid ACK value.
        debug_assert!(header.ack);

        let remote_ipv4_addr = *connection_management.remote.ip();
        header.serialize_and_attach(
            &mut pkt,
            connection_management.local.ip(),
            connection_management.remote.ip(),
            connection_management.tcp_config.get_tx_checksum_offload(),
        );

        // Call lower L3 layer to send the segment.
        if let Err(e) = layer3_endpoint.transmit_tcp_packet_nonblocking(remote_ipv4_addr, pkt) {
            warn!("could not emit packet: {:?}", e);
            return;
        }

        // Post-send operations follow.
        // Review: We perform these after the send, in order to keep send latency as low as possible.

        // Since we sent an ACK, cancel any outstanding delayed ACK request.
        self.receiver.ack_deadline_time_secs.set(None);
    }

    /// Send an ACK to our peer, reflecting our current state.
    pub fn send_ack(
        &mut self,
        connection_management: &ConnectionManagementState,
        layer3_endpoint: &mut SharedLayer3Endpoint,
    ) {
        let header = ControlBlock::tcp_header(connection_management, self, None);
        self.emit(connection_management, layer3_endpoint, header, None);
    }

    pub fn handle_data(
        &mut self,
        connection_management: &ConnectionManagementState,
        layer3_endpoint: &mut SharedLayer3Endpoint,
        data: DemiBuffer,
        seg_start: SeqNumber,
        seg_end: SeqNumber,
        seg_len: u32,
    ) -> Result<(), Fail> {
        // TCP dictates that we only receive data in these states.
        match connection_management.state {
            State::Established | State::FinWait1 | State::FinWait2 => (),
            state => {
                warn!("Ignoring data received after FIN (in state {:?}).", state);
                return Ok(());
            },
        };

        // Data is in order, so directly receive.
        if seg_start == self.receiver.receive_next_seq_no {
            self.receiver.receive_data(seg_start, data);
            return Ok(());
        }

        // This segment is out-of-order.  If it carries data, we should store it for later processing
        // after the "hole" in the sequence number space has been filled.
        debug!(
            "Received out-of-order segment; out_of_order_frames.len() = {:?}",
            self.receiver.out_of_order_frames.len()
        );
        debug_assert_ne!(seg_len, 0);
        debug_assert_eq!(seg_len, data.len() as u32);
        self.receiver.store_out_of_order_segment(seg_start, seg_end, data);
        // Sending an ACK here is only a "MAY" according to the RFCs, but helpful for fast retransmit.
        trace!("process_data(): send ack on out-of-order segment");
        self.send_ack(connection_management, layer3_endpoint);

        // We're done with this out-of-order segment.
        Ok(())
    }
}
