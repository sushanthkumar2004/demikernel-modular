// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================

use std::time::Instant;

use crate::inetstack::protocols::layer4::tcp::{
    established::ctrlblk::{ControlBlock, State},
    header::TcpHeader,
    SeqNumber,
};
use crate::{
    inetstack::protocols::layer3::SharedLayer3Endpoint,
    runtime::fail::Fail,
};

//======================================================================================================================
// Event Dispatchers
//======================================================================================================================

/// Dispatches ACK event to all relevant components.
/// This function orchestrates component method calls but does not modify state directly.
/// Each component method is responsible for updating only its own state.
pub fn dispatch_ack_event(cb: &mut ControlBlock, header: &TcpHeader, now: Instant) {
    // 1. Flow control: Update send window
    cb.flow_control.on_ack_received(header);

    // 2. Congestion control: Process RTT samples
    cb.congestion_control
        .on_ack_received(&cb.delivery, header, now);

    // 3. Connection management: Handle state transitions based on current state
    match cb.connection_management.state {
        State::FinWait1 => cb
            .connection_management
            .on_ack_in_finwait1(&cb.delivery, header),
        State::Closing => cb
            .connection_management
            .on_ack_in_closing(&cb.delivery, header),
        State::LastAck => cb
            .connection_management
            .on_ack_in_lastack(&cb.delivery, header),
        // In other states (Established, CloseWait, FinWait2, TimeWait), ACKs don't trigger state transitions
        _ => {},
    }

    // 4. Ordered delivery: Update unacked queue and sequence numbers
    cb.delivery
        .on_ack_received(&cb.congestion_control, header, now);
}

/// Dispatches FIN event to all relevant components.
/// This function orchestrates component method calls but does not modify state directly.
pub fn dispatch_fin_event(
    cb: &mut ControlBlock,
    header: &TcpHeader,
    seg_end: SeqNumber,
    layer3_endpoint: &mut SharedLayer3Endpoint,
) -> Result<(), Fail> {
    // 1. Ordered delivery: Update FIN state if FIN flag is present
    if header.fin {
        cb.delivery.on_fin_received(seg_end);
    }

    // 2. Check if we have received all data up to the FIN
    if cb.delivery.is_fin_complete() {
        // 3. Connection management: Handle state transitions
        match cb.connection_management.state {
            State::Established => cb.connection_management.on_fin_in_established()?,
            State::FinWait1 => cb.connection_management.on_fin_in_finwait1()?,
            State::FinWait2 => cb.connection_management.on_fin_in_finwait2()?,
            _ => {},
        }

        // 4. Ordered delivery: Process FIN (push EOF, increment RCV.NXT)
        cb.delivery.on_fin_processed();
    }

    // 5. Send ACK if the segment had a FIN flag
    if header.fin {
        cb.delivery
            .send_ack(&cb.connection_management, layer3_endpoint);
    }

    Ok(())
}

//======================================================================================================================
// Connection Setup Event Dispatchers
//======================================================================================================================

/// Dispatches SYN event to all relevant components during passive open.
/// This function orchestrates component method calls for connection setup.
pub fn dispatch_syn_event(
    cb: &mut ControlBlock,
    remote: std::net::SocketAddrV4,
    tcp_hdr: &TcpHeader,
    local_isn: SeqNumber,
) -> Result<(), Fail> {
    // Parse TCP options from SYN
    let (mss, remote_window_scale) = parse_syn_options(tcp_hdr);
    
    // Calculate window size with scaling
    let remote_window_size = calculate_window_size(
        tcp_hdr.window_size,
        remote_window_scale,
    );
    
    // 1. Connection management: set remote endpoint
    cb.connection_management.on_syn_in_listen(remote)?;
    
    // 2. Ordered delivery: set sequence numbers
    cb.delivery.on_syn_received(tcp_hdr.seq_num, local_isn);
    
    // 3. Flow control: set windows and MSS
    cb.flow_control.on_syn_received(
        remote_window_size,
        remote_window_scale.unwrap_or(0),
        mss,
    );
    
    // 4. Congestion control: initialize
    cb.congestion_control.on_syn_received(mss);
    
    Ok(())
}

/// Dispatches SYN+ACK event to all relevant components during active open.
/// This function orchestrates component method calls for connection setup.
pub fn dispatch_synack_event(
    cb: &mut ControlBlock,
    tcp_hdr: &TcpHeader,
    local_isn: SeqNumber,
) -> Result<(), Fail> {
    // Parse TCP options from SYN+ACK
    let (mss, remote_window_scale) = parse_syn_options(tcp_hdr);
    
    // Calculate window size with scaling
    let remote_window_size = calculate_window_size(
        tcp_hdr.window_size,
        remote_window_scale,
    );
    
    // 1. Connection management: transition to ESTABLISHED
    cb.connection_management.on_synack_in_synsent()?;
    
    // 2. Ordered delivery: set sequence numbers
    cb.delivery.on_syn_received(tcp_hdr.seq_num, local_isn);
    
    // 3. Flow control: set windows and MSS
    cb.flow_control.on_syn_received(
        remote_window_size,
        remote_window_scale.unwrap_or(0),
        mss,
    );
    
    // 4. Congestion control: initialize
    cb.congestion_control.on_syn_received(mss);
    
    Ok(())
}

//======================================================================================================================
// Helper Functions
//======================================================================================================================

/// Parses TCP options from a SYN or SYN+ACK segment.
/// Returns (MSS, window_scale).
fn parse_syn_options(tcp_hdr: &TcpHeader) -> (usize, Option<u8>) {
    use crate::inetstack::{
        consts::FALLBACK_MSS,
        protocols::layer4::tcp::header::TcpOptions2,
    };
    
    let mut mss = FALLBACK_MSS;
    let mut window_scale = None;
    
    for option in tcp_hdr.iter_options() {
        match option {
            TcpOptions2::WindowScale(w) => {
                info!("Received window scale: {}", w);
                window_scale = Some(*w);
            },
            TcpOptions2::MaximumSegmentSize(m) => {
                info!("Received advertised MSS: {}", m);
                mss = *m as usize;
            },
            _ => continue,
        }
    }
    
    (mss, window_scale)
}

/// Calculates the actual window size from the advertised window and scale.
fn calculate_window_size(window: u16, scale: Option<u8>) -> u32 {
    use crate::inetstack::consts::MAX_WINDOW_SCALE;
    
    match scale {
        Some(s) if s as usize <= MAX_WINDOW_SCALE => {
            (window as u32) << s
        },
        Some(_) => {
            warn!("Window scale too large, using MAX_WINDOW_SCALE");
            (window as u32) << MAX_WINDOW_SCALE
        },
        None => window as u32,
    }
}
