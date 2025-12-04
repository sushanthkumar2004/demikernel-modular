# TCP Connection Setup Modularization

## 1. Overview

This document describes the refactoring of TCP connection setup in Demikernel (both Passive Open/Server and Active Open/Client) to follow a **modular, component-based architecture**.

### Problem Statement
The original connection setup was handled by large constructor functions (`SharedEstablishedSocket::new`) and monolithic logic in `passive_open.rs` and `active_open.rs`. This approach had several issues:

- **Tight Coupling:** The handshake logic needed to know internal details of all components (e.g., calculating window scales for Flow Control).
- **Privileged Control Path:** The handshake code directly modified state fields, bypassing component boundaries.
- **Inconsistency:** The handshake used a different pattern than the established state (which uses event dispatchers).

### Solution
The refactoring implements a **Dispatcher Pattern** where the `ControlBlock` is created at the beginning of the handshake and evolves through state transitions. Each component handles only its own state updates via dedicated methods. The four core components are:

1. **Connection Management** (State Machine, Metadata)
2. **Ordered Delivery** (Sequence Numbers, Buffers)
3. **Flow Control** (Window Management)
4. **Congestion Control** (Network Capacity)

## 2. Architecture

The architecture creates the `ControlBlock` at the start of the handshake (in LISTEN or SYN_SENT state) rather than at the end. As segments arrive, dispatcher functions call component-specific methods, and each component updates only its own state.

### ControlBlock Creation
Builder functions create the `ControlBlock` in the appropriate initial state:

```rust
// tcp_events.rs
pub fn create_control_block_for_listen(config: PassiveOpenConfig, ...) -> ControlBlock {
    // Each component initializes itself
    let delivery = OrderedDeliveryState::new(...); 
    let flow_control = FlowControlState::new(...);
    let conn_mgmt = ConnectionManagementState::new_listen(...);  // Starts in LISTEN state
    
    ControlBlock::new(conn_mgmt, delivery, flow_control, ...)
}
```

### Event Dispatching
Dispatcher functions orchestrate the handshake by calling component-specific methods:

```rust
// tcp_events.rs
pub fn dispatch_syn_in_listen(cb: &mut ControlBlock, header: &TcpHeader, ...) {
    // Each component handles the event independently
    cb.delivery.on_syn_in_listen(remote_isn);           // Updates sequence numbers
    cb.flow_control.on_syn_in_listen(header, ...);      // Updates window info
    cb.connection_management.on_syn_in_listen(remote);  // Transitions LISTEN -> SYN_RCVD
}
```

### Component Methods
Each component provides methods that handle specific handshake events:

```rust
// Passive Open (Server)
delivery.on_syn_in_listen(remote_isn)        // Sets receive sequence numbers
flow_control.on_syn_in_listen(header, ...)   // Sets peer's window info  
conn_mgmt.on_syn_in_listen(remote)           // LISTEN → SYN_RECEIVED
conn_mgmt.on_ack_in_synrcvd()                // SYN_RECEIVED → ESTABLISHED

// Active Open (Client)
delivery.on_synack_in_synsent(...)           // Sets receive sequence numbers
flow_control.on_synack_in_synsent(...)       // Sets peer's window info
conn_mgmt.on_synack_in_synsent()             // SYN_SENT → ESTABLISHED
```

## 3. Implementation Details

### Passive Open Flow (Server)

When a server receives a SYN packet:

1. **Create ControlBlock:** `create_control_block_for_listen()` creates a `ControlBlock` in LISTEN state
2. **Process SYN:** `dispatch_syn_in_listen()` calls each component's `on_syn_in_listen()` method
3. **Send SYN+ACK:** The server sends SYN+ACK and waits for ACK
4. **Process ACK:** `dispatch_ack_in_synrcvd()` transitions to ESTABLISHED
5. **Create Socket:** `SharedEstablishedSocket::new_from_control_block()` creates the socket from the evolved `ControlBlock`

```rust
// passive_open.rs (simplified)
async fn send_syn_ack_and_wait_for_ack(...) {
    // Step 1: Create ControlBlock in LISTEN state
    let mut control_block = create_control_block_for_listen(config, cc_constructor);

    // Step 2: Process SYN (LISTEN → SYN_RECEIVED)
    dispatch_syn_in_listen(&mut control_block, &syn_header, remote, ...);

    // Step 3-4: Send SYN+ACK, wait for ACK
    loop {
        send_syn_ack(...).await?;
        match wait_for_ack_packet(...).await {
            Ok((ack_header, buf)) => {
                // Process ACK (SYN_RECEIVED → ESTABLISHED)
                dispatch_ack_in_synrcvd(&mut control_block);
                
                // Step 5: Create socket
                return SharedEstablishedSocket::new_from_control_block(control_block, ...);
            }
            // Handle timeout/retry...
        }
    }
}
```

### Active Open Flow (Client)

When a client initiates a connection:

1. **Create ControlBlock:** `create_control_block_for_syn_sent()` creates a `ControlBlock` in SYN_SENT state
2. **Send SYN:** The client sends a SYN packet
3. **Process SYN+ACK:** `dispatch_synack_in_synsent()` calls each component's method
4. **Send ACK:** The client sends the final ACK
5. **Create Socket:** `SharedEstablishedSocket::new_from_control_block()` creates the socket

```rust
// active_open.rs (simplified)
pub async fn connect(mut self) -> Result<SharedEstablishedSocket, Fail> {
    // Step 1: Create ControlBlock in SYN_SENT state
    let mut control_block = create_control_block_for_syn_sent(config, cc_constructor);

    for _ in 0..handshake_retries {
        // Step 2: Send SYN
        send_syn(...).await?;

        // Step 3: Wait for and process SYN+ACK
        match recv_queue.pop(timeout).await {
            Ok((_, header, _)) => {
                // Process SYN+ACK (SYN_SENT → ESTABLISHED)
                dispatch_synack_in_synsent(&mut control_block, &header, ...)?;

                // Step 4: Send ACK
                send_ack(...)?;

                // Step 5: Create socket
                return SharedEstablishedSocket::new_from_control_block(control_block, ...);
            }
            // Handle timeout/retry...
        }
    }
}
```

## 4. State Machine

```
                    CLOSED
                       |
           ┌──────────┴──────────┐
           │                     │
       listen()              connect()
           │                     │
           v                     v
        LISTEN               SYN_SENT
           │                     │
       recv SYN            recv SYN+ACK
           │                     │
  dispatch_syn_in_listen   dispatch_synack_in_synsent
           │                     │
           v                     v
     SYN_RECEIVED           ESTABLISHED
           │                     
       recv ACK                   
           │                     
  dispatch_ack_in_synrcvd          
           │                     
           v                     
      ESTABLISHED                
```

## 5. Benefits

1. **Separation of Concerns:** Each component manages only its own state. No single function needs knowledge of all component internals.

2. **Testability:** Component methods like `FlowControlState::on_syn_in_listen` can be unit tested in isolation without requiring a full socket or network stack.

3. **Consistency:** The handshake now follows the same dispatcher pattern used in the established state, making the codebase more uniform.

4. **Maintainability:** Changes to one component (e.g., adding new window scaling logic to Flow Control) do not require modifications to the handshake code in `passive_open.rs` or `active_open.rs`.

## 6. Files Modified

- `src/inetstack/protocols/layer4/tcp/established/tcp_events.rs` - Dispatcher functions and builders
- `src/inetstack/protocols/layer4/tcp/established/connection_management_state.rs` - Added `new_listen()`, `new_syn_sent()` constructors
- `src/inetstack/protocols/layer4/tcp/passive_open.rs` - Refactored to use dispatcher pattern
- `src/inetstack/protocols/layer4/tcp/active_open.rs` - Refactored to use dispatcher pattern
