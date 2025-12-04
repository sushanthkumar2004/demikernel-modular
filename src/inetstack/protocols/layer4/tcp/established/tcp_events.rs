// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// tcp_events.rs - Event Dispatchers for TCP Handshake
//
// These dispatchers orchestrate component methods during the TCP handshake.
// Each dispatcher calls component-specific methods in sequence.
// No dispatcher modifies any component state directly - it only calls methods.
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
    conn_mgmt: &mut ConnectionManagementState,
    delivery: &mut OrderedDeliveryState,
    flow_control: &mut FlowControlState,
    header: &TcpHeader,
    remote: SocketAddrV4,
    local_isn: SeqNumber,
    mss: usize,
    window_scale_bits: u8,
) {
    let remote_isn = header.seq_num;

    // Each component handles its own state:
    delivery.on_syn_in_listen(remote_isn);
    flow_control.on_syn_in_listen(header, remote_isn, local_isn, mss, window_scale_bits);
    conn_mgmt.on_syn_in_listen(remote);
}

//======================================================================================================================
// Dispatch: SYN+ACK received in SYN_SENT state (active open completion)
//======================================================================================================================

/// Process a SYN+ACK segment received while in SYN_SENT state.
/// Each component updates only its own state.
///
/// State transition: SYN_SENT → ESTABLISHED
pub fn dispatch_synack_in_synsent(
    conn_mgmt: &mut ConnectionManagementState,
    delivery: &mut OrderedDeliveryState,
    flow_control: &mut FlowControlState,
    header: &TcpHeader,
    local_isn: SeqNumber,
    window_scale_bits: u8,
    mss: usize,
) -> Result<(), &'static str> {
    let remote_isn = header.seq_num;
    let ack_num = header.ack_num;

    // Each component handles its own state:
    delivery.on_synack_in_synsent(remote_isn, local_isn, ack_num)?;
    flow_control.on_synack_in_synsent(header, window_scale_bits, mss);
    conn_mgmt.on_synack_in_synsent();

    Ok(())
}

//======================================================================================================================
// Dispatch: ACK received in SYN_RECEIVED state (passive open completion)
//======================================================================================================================

/// Process an ACK segment received while in SYN_RECEIVED state.
/// Each component updates only its own state.
///
/// State transition: SYN_RECEIVED → ESTABLISHED
pub fn dispatch_ack_in_synrcvd(
    conn_mgmt: &mut ConnectionManagementState,
    _delivery: &mut OrderedDeliveryState,
    _flow_control: &mut FlowControlState,
) {
    // For the final ACK, only connection management needs to update state
    conn_mgmt.on_ack_in_synrcvd();
}

//======================================================================================================================
// Helper: Build ControlBlock for Passive Open (complete handshake)
//======================================================================================================================

/// Configuration for building a ControlBlock during passive open.
pub struct PassiveOpenConfig {
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

/// Build a ControlBlock for passive open using component methods.
/// This creates and initializes each component, then combines them into a ControlBlock.
///
/// The ControlBlock starts in ESTABLISHED state (handshake complete).
pub fn build_control_block_for_passive_open(
    config: PassiveOpenConfig,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Initialize each component with appropriate initial values
    
    // Sender sequence starts after our SYN (local_isn + 1)
    let sender_seq_no = config.local_isn + SeqNumber::from(1);
    // Receiver sequence starts after their SYN (remote_isn + 1)
    let receiver_seq_no = config.remote_isn + SeqNumber::from(1);
    
    // Create delivery state with proper sequence numbers
    let delivery = OrderedDeliveryState::new(
        sender_seq_no,
        receiver_seq_no,  // reader_next_seq_no
        receiver_seq_no,  // receive_next_seq_no
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );
    
    // Create flow control state with peer's window info
    let flow_control = FlowControlState::new(
        sender_seq_no,
        receiver_seq_no,
        config.remote_window_size_bytes,
        config.remote_window_scale_bits,
        config.mss,
    );
    
    // Create connection management state (already in ESTABLISHED)
    let connection_management = ConnectionManagementState::new(
        config.local,
        config.remote,
        config.tcp_config,
        config.socket_options,
    );
    
    // Create congestion control state
    let cc_algorithm = cc_constructor(config.mss, sender_seq_no, None);
    let congestion_control = CongestionControlState::new(cc_algorithm);
    
    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

//======================================================================================================================
// Helper: Build ControlBlock for Active Open (complete handshake)
//======================================================================================================================

/// Configuration for building a ControlBlock during active open.
pub struct ActiveOpenConfig {
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

/// Build a ControlBlock for active open using component methods.
/// This creates and initializes each component, then combines them into a ControlBlock.
///
/// The ControlBlock starts in ESTABLISHED state (handshake complete).
pub fn build_control_block_for_active_open(
    config: ActiveOpenConfig,
    cc_constructor: CongestionControlConstructor,
) -> ControlBlock {
    // Initialize each component with appropriate initial values
    
    // Sender sequence starts after our SYN (local_isn + 1)
    let sender_seq_no = config.local_isn + SeqNumber::from(1);
    // Receiver sequence starts after their SYN (remote_isn + 1)
    let receiver_seq_no = config.remote_isn + SeqNumber::from(1);
    
    // Create delivery state with proper sequence numbers
    let delivery = OrderedDeliveryState::new(
        sender_seq_no,
        receiver_seq_no,  // reader_next_seq_no
        receiver_seq_no,  // receive_next_seq_no
        config.ack_delay_timeout,
        config.local_window_size_bytes,
        config.local_window_scale_bits,
    );
    
    // Create flow control state with peer's window info
    let flow_control = FlowControlState::new(
        sender_seq_no,
        receiver_seq_no,
        config.remote_window_size_bytes,
        config.remote_window_scale_bits,
        config.mss,
    );
    
    // Create connection management state (already in ESTABLISHED)
    let connection_management = ConnectionManagementState::new(
        config.local,
        config.remote,
        config.tcp_config,
        config.socket_options,
    );
    
    // Create congestion control state
    let cc_algorithm = cc_constructor(config.mss, sender_seq_no, None);
    let congestion_control = CongestionControlState::new(cc_algorithm);
    
    ControlBlock::new(connection_management, delivery, flow_control, congestion_control)
}

