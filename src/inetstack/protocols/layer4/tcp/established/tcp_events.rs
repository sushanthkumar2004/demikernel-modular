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
