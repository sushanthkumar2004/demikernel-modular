// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// tcp_events.rs - Event Dispatchers for TCP Handshake
//
// This module implements the modular connection setup pattern. Instead of having a "god function"
// that knows all internal details, the handshake creates a ControlBlock early and uses component
// methods to evolve state:
//
//   1. Create ControlBlock in initial state (LISTEN or SYN_SENT)
//   2. As segments arrive, dispatchers call component methods (e.g., rod.on_syn_in_listen())
//   3. Each component updates only its own state - no cross-component writes
//   4. The ControlBlock evolves through handshake states until ESTABLISHED
//
// This eliminates the "control path has special write permissions" exception entirely.
//======================================================================================================================

use std::net::SocketAddrV4;
use std::time::Duration;

use crate::{
    inetstack::{
        config::TcpConfig,
        protocols::layer4::tcp::{
            congestion_control::CongestionControlConstructor,
            established::{
                congestion_control_state::CongestionControlState,
                connection_management_state::ConnectionManagementState,
                ctrlblk::ControlBlock,
                flow_control_state::FlowControlState,
                ordered_delivery_state::OrderedDeliveryState,
            },
            header::TcpHeader,
            SeqNumber,
        },
    },
    runtime::network::socket::option::TcpSocketOptions,
};

//======================================================================================================================
// Dispatch: SYN received in LISTEN state (passive open step 1)
//======================================================================================================================

/// Process a SYN segment received while in LISTEN state.
/// Each component updates only its own state.
///
/// State transition: LISTEN → SYN_RECEIVED
pub fn dispatch_syn_in_listen(
    cb: &mut ControlBlock,
    header: &TcpHeader,
    remote: SocketAddrV4,
    local_isn: SeqNumber,
    mss: usize,
    window_scale_bits: u8,
) {
    let remote_isn = header.seq_num;

    // Each component handles its own state:
    cb.delivery.on_syn_in_listen(remote_isn);
    cb.flow_control.on_syn_in_listen(header, remote_isn, local_isn, mss, window_scale_bits);
    cb.connection_management.on_syn_in_listen(remote);
}

//======================================================================================================================
// Dispatch: SYN+ACK received in SYN_SENT state (active open completion)
//======================================================================================================================

/// Process a SYN+ACK segment received while in SYN_SENT state.
/// Each component updates only its own state.
///
/// State transition: SYN_SENT → ESTABLISHED
pub fn dispatch_synack_in_synsent(
    cb: &mut ControlBlock,
    header: &TcpHeader,
    local_isn: SeqNumber,
    window_scale_bits: u8,
    mss: usize,
) -> Result<(), &'static str> {
    let remote_isn = header.seq_num;
    let ack_num = header.ack_num;

    // Each component handles its own state:
    cb.delivery.on_synack_in_synsent(remote_isn, local_isn, ack_num)?;
    cb.flow_control.on_synack_in_synsent(header, window_scale_bits, mss);
    cb.connection_management.on_synack_in_synsent();

    Ok(())
}

//======================================================================================================================
// Dispatch: ACK received in SYN_RECEIVED state (passive open completion)
//======================================================================================================================

/// Process an ACK segment received while in SYN_RECEIVED state.
/// Each component updates only its own state.
///
/// State transition: SYN_RECEIVED → ESTABLISHED
pub fn dispatch_ack_in_synrcvd(cb: &mut ControlBlock) {
    // For the final ACK, only connection management needs to update state
    cb.connection_management.on_ack_in_synrcvd();
}

//======================================================================================================================
// ControlBlock Builders - Create ControlBlock at start of handshake
//======================================================================================================================

/// Configuration for passive open (server-side).
pub struct PassiveOpenConfig {
    pub local: SocketAddrV4,
    pub tcp_config: TcpConfig,
    pub socket_options: TcpSocketOptions,
    pub local_isn: SeqNumber,
    pub ack_delay_timeout: Duration,
    pub local_window_size_bytes: u32,
    pub local_window_scale_bits: u8,
}

/// Create a ControlBlock for passive open in LISTEN state.
/// The ControlBlock will be evolved through the handshake using dispatchers.
///
/// Flow:
///   1. create_control_block_for_listen() -> ControlBlock in LISTEN
///   2. dispatch_syn_in_listen() -> LISTEN → SYN_RECEIVED
///   3. dispatch_ack_in_synrcvd() -> SYN_RECEIVED → ESTABLISHED
pub fn create_control_block_for_listen(
    config: PassiveOpenConfig,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Initialize delivery state with our local ISN (sender side only at this point)
    // Receiver side will be initialized when we receive the SYN via on_syn_in_listen()
    let delivery = OrderedDeliveryState::new(
        config.local_isn,           // sender starts at our ISN
        SeqNumber::from(0),         // receiver seq - will be set by on_syn_in_listen
        SeqNumber::from(0),         // receiver seq - will be set by on_syn_in_listen
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );

    // Flow control starts with placeholder values - will be set by on_syn_in_listen()
    let flow_control = FlowControlState::new(
        config.local_isn,
        SeqNumber::from(0),
        0,                          // send window - will be set when we see peer's window
        0,                          // window scale - will be set from SYN options
        0,                          // mss - will be set from SYN options
    );

    // Connection management starts in LISTEN state
    let connection_management = ConnectionManagementState::new_listen(
        config.local,
        config.tcp_config,
        config.socket_options,
    );

    // Congestion control
    let cc_algorithm = cc_constructor(0, config.local_isn, None); // mss will be updated
    let congestion_control = CongestionControlState::new(cc_algorithm);

    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

/// Configuration for active open (client-side).
pub struct ActiveOpenConfig {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub tcp_config: TcpConfig,
    pub socket_options: TcpSocketOptions,
    pub local_isn: SeqNumber,
    pub ack_delay_timeout: Duration,
    pub local_window_size_bytes: u32,
    pub local_window_scale_bits: u8,
}

/// Create a ControlBlock for active open in SYN_SENT state.
/// The ControlBlock will be evolved through the handshake using dispatchers.
///
/// Flow:
///   1. create_control_block_for_syn_sent() -> ControlBlock in SYN_SENT
///   2. dispatch_synack_in_synsent() -> SYN_SENT → ESTABLISHED
pub fn create_control_block_for_syn_sent(
    config: ActiveOpenConfig,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Initialize delivery state with our local ISN (sender side only at this point)
    // Receiver side will be initialized when we receive SYN+ACK via on_synack_in_synsent()
    let delivery = OrderedDeliveryState::new(
        config.local_isn,           // sender starts at our ISN
        SeqNumber::from(0),         // receiver seq - will be set by on_synack_in_synsent
        SeqNumber::from(0),         // receiver seq - will be set by on_synack_in_synsent
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );

    // Flow control starts with placeholder values - will be set by on_synack_in_synsent()
    let flow_control = FlowControlState::new(
        config.local_isn,
        SeqNumber::from(0),
        0,                          // send window - will be set when we see peer's window
        0,                          // window scale - will be set from SYN+ACK options  
        0,                          // mss - will be set from SYN+ACK options
    );

    // Connection management starts in SYN_SENT state
    let connection_management = ConnectionManagementState::new_syn_sent(
        config.local,
        config.remote,
        config.tcp_config,
        config.socket_options,
    );

    // Congestion control
    let cc_algorithm = cc_constructor(0, config.local_isn, None); // mss will be updated
    let congestion_control = CongestionControlState::new(cc_algorithm);

    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

//======================================================================================================================
// Legacy Builders - For backward compatibility (create ControlBlock in ESTABLISHED)
//======================================================================================================================

/// Legacy configuration for passive open - creates ControlBlock directly in ESTABLISHED.
/// DEPRECATED: Use create_control_block_for_listen() + dispatchers instead.
pub struct PassiveOpenConfigLegacy {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub local_isn: SeqNumber,
    pub remote_isn: SeqNumber,
    pub tcp_config: TcpConfig,
    pub socket_options: TcpSocketOptions,
    pub mss: usize,
    pub local_window_scale_bits: u8,
    pub remote_window_scale_bits: u8,
    pub local_window_size_bytes: u32,
    pub remote_window_size_bytes: u32,
    pub ack_delay_timeout: Duration,
}

/// Legacy builder - creates ControlBlock directly in ESTABLISHED state.
/// DEPRECATED: Use create_control_block_for_listen() + dispatchers instead.
pub fn build_control_block_for_passive_open(
    config: PassiveOpenConfigLegacy,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Sender sequence starts after our SYN (local_isn + 1)
    let sender_seq_no = config.local_isn + SeqNumber::from(1);
    // Receiver sequence starts after their SYN (remote_isn + 1)
    let receiver_seq_no = config.remote_isn + SeqNumber::from(1);

    let delivery = OrderedDeliveryState::new(
        sender_seq_no,
        receiver_seq_no,
        receiver_seq_no,
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );

    let flow_control = FlowControlState::new(
        sender_seq_no,
        receiver_seq_no,
        config.remote_window_size_bytes,
        config.remote_window_scale_bits,
        config.mss,
    );

    let connection_management = ConnectionManagementState::new(
        config.local,
        config.remote,
        config.tcp_config,
        config.socket_options,
    );

    let cc_algorithm = cc_constructor(config.mss, sender_seq_no, None);
    let congestion_control = CongestionControlState::new(cc_algorithm);

    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

/// Legacy configuration for active open - creates ControlBlock directly in ESTABLISHED.
/// DEPRECATED: Use create_control_block_for_syn_sent() + dispatchers instead.
pub struct ActiveOpenConfigLegacy {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub local_isn: SeqNumber,
    pub remote_isn: SeqNumber,
    pub tcp_config: TcpConfig,
    pub socket_options: TcpSocketOptions,
    pub mss: usize,
    pub local_window_scale_bits: u8,
    pub remote_window_scale_bits: u8,
    pub local_window_size_bytes: u32,
    pub remote_window_size_bytes: u32,
    pub ack_delay_timeout: Duration,
}

/// Legacy builder - creates ControlBlock directly in ESTABLISHED state.
/// DEPRECATED: Use create_control_block_for_syn_sent() + dispatchers instead.
pub fn build_control_block_for_active_open(
    config: ActiveOpenConfigLegacy,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Sender sequence starts after our SYN (local_isn + 1)
    let sender_seq_no = config.local_isn + SeqNumber::from(1);
    // Receiver sequence starts after their SYN (remote_isn + 1)
    let receiver_seq_no = config.remote_isn + SeqNumber::from(1);

    let delivery = OrderedDeliveryState::new(
        sender_seq_no,
        receiver_seq_no,
        receiver_seq_no,
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );

    let flow_control = FlowControlState::new(
        sender_seq_no,
        receiver_seq_no,
        config.remote_window_size_bytes,
        config.remote_window_scale_bits,
        config.mss,
    );

    let connection_management = ConnectionManagementState::new(
        config.local,
        config.remote,
        config.tcp_config,
        config.socket_options,
    );

    let cc_algorithm = cc_constructor(config.mss, sender_seq_no, None);
    let congestion_control = CongestionControlState::new(cc_algorithm);

    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

