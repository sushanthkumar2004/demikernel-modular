# TCP Connection Setup Modularization: Summary

## 1. Overview

I have successfully refactored the TCP connection setup in Demikernel (both Passive Open/Server and Active Open/Client) to adhere to a **modular, component-based architecture**.

### The Problem (Before)
Previously, connection setup was handled by "God Functions" (`SharedEstablishedSocket::new`) and monolithic logic in `passive_open.rs` and `active_open.rs`.
- **Tight Coupling:** The handshake logic had to know internal details of all components (e.g., calculating window scales for Flow Control).
- **Privileged Control Path:** The handshake code directly modified state fields, bypassing component boundaries.
- **Inconsistency:** The handshake used a completely different pattern than the established state (which uses event dispatchers).

### The Solution (After)
I implemented a **Dispatcher & Builder Pattern** that delegates responsibility to the four core components:
1.  **Connection Management** (State Machine, Metadata)
2.  **Ordered Delivery** (Sequence Numbers, Buffers)
3.  **Flow Control** (Window Management)
4.  **Congestion Control** (Network Capacity)

## 2. Architecture: The Dispatcher & Builder Pattern

The new architecture uses a two-step process to establish connections, ensuring no single function needs "god-like" knowledge.

### Step 1: Component-Specific Initialization (The Builder)
Instead of a massive constructor, I use a helper `build_control_block_for_...` that asks each component to initialize itself.

```rust
// tcp_events.rs
pub fn build_control_block_for_passive_open(config: PassiveOpenConfig, ...) -> ControlBlock {
    // 1. Ordered Delivery initializes itself (calculates ISS, IRS)
    let delivery = OrderedDeliveryState::new(...); 
    
    // 2. Flow Control initializes itself (interprets window scales)
    let flow_control = FlowControlState::new(...);
    
    // 3. Connection Management initializes itself
    let conn_mgmt = ConnectionManagementState::new(...);

    // 4. Combine into ControlBlock
    ControlBlock::new(conn_mgmt, delivery, flow_control, ...)
}
```

### Step 2: Event Dispatching (The Handshake)
I introduced **Event Dispatchers** (`dispatch_syn_in_listen`, etc.) that orchestrate the handshake by calling specific methods on each component.

```rust
// tcp_events.rs
pub fn dispatch_syn_in_listen(conn_mgmt, delivery, flow_control, ...) {
    // Each component handles the event independently
    delivery.on_syn_in_listen(remote_isn);           // Updates sequence numbers
    flow_control.on_syn_in_listen(header, ...);      // Updates window size
    conn_mgmt.on_syn_in_listen(remote);              // Transitions LISTEN -> SYN_RCVD
}
```

## 3. Design Philosophy & lwIP Parity

This implementation aligns with the modular design philosophy found in stacks like lwIP, where components are isolated and manage their own state.

### The Target Model (lwIP-style)
In a modular stack, connection setup looks like this:

```rust
pub fn tcp_connect(state: &mut TcpConnectionState, ...) {
    // Each component handles its own initialization
    state.rod.on_connect()?;
    state.flow_ctrl.on_connect()?;
    state.conn_mgmt.on_connect(...)?;
}
```

### The Demikernel Implementation
I adapted this pattern to fit Demikernel's type system (where `ControlBlock` is created during the handshake):

```rust
pub fn build_control_block_for_active_open(config: ActiveOpenConfig, ...) -> ControlBlock {
    // Equivalent to state.rod.on_connect()
    let delivery = OrderedDeliveryState::new(...);
    
    // Equivalent to state.flow_ctrl.on_connect()
    let flow_control = FlowControlState::new(...);
    
    // Equivalent to state.conn_mgmt.on_connect()
    let conn_mgmt = ConnectionManagementState::new(...);
    
    ControlBlock::new(conn_mgmt, delivery, flow_control, ...)
}
```

**Key Insight:**
While lwIP mutates an *existing* state object, Demikernel creates a *new* one. However, the **behavior is identical**: each component is responsible for initializing its own state based on the connection parameters, rather than a central function doing it for them.

## 4. Concrete Walkthrough: Passive Open (Receiving SYN)

Here is a step-by-step comparison of what happens when a server receives a SYN packet.

### Before (Monolithic)
The `passive_open.rs` module did everything itself.

1.  **Receive SYN:** `SharedPassiveSocket::receive` gets the packet.
2.  **Parse Options:** `passive_open.rs` iterates over TCP options (MSS, Window Scale).
3.  **Calculate Windows:** `passive_open.rs` performs bitwise shifts to calculate window sizes.
4.  **Call God Function:** `passive_open.rs` calls `SharedEstablishedSocket::new` with **17 arguments**.
5.  **Manual Construction:** `SharedEstablishedSocket::new` manually constructs `FlowControlState`, `OrderedDeliveryState`, etc. using the raw numbers passed in.

```rust
// OLD CODE (Conceptual)
let local_window = base_window << scale; // Logic leaks into passive_open.rs
SharedEstablishedSocket::new(..., local_window, ...) // God function
```

### After (Modular)
The logic is distributed to the components.

1.  **Receive SYN:** `SharedPassiveSocket::receive` gets the packet.
2.  **Create Config:** `passive_open.rs` gathers the raw data into a `PassiveOpenConfig` struct.
3.  **Call Builder:** `passive_open.rs` calls `build_control_block_for_passive_open(config)`.
4.  **Component Self-Init:**
    *   The builder calls `OrderedDeliveryState::new`. This component calculates its own Initial Sequence Numbers (ISS/IRS).
    *   The builder calls `FlowControlState::new`. This component sets up its own window sizes.
    *   The builder calls `ConnectionManagementState::new`. This component sets its state to ESTABLISHED.
5.  **Create Socket:** `passive_open.rs` calls `SharedEstablishedSocket::new_from_control_block` with the fully formed `ControlBlock`.

```rust
// NEW CODE (Conceptual)
let config = PassiveOpenConfig { ... }; // Just data
let cb = build_control_block_for_passive_open(config); // Builder orchestrates
// Inside builder:
// FlowControlState::new() handles the window logic!
```

## 5. Benefits

1.  **Maintainability:** Changing Flow Control logic (e.g., adding Window Scaling support) only requires changing `FlowControlState`. The handshake logic in `passive_open.rs` remains untouched.
2.  **Testability:** I can now unit test `FlowControlState::on_syn_in_listen` in isolation, without needing a full socket or network stack.
3.  **Safety:** Invariants are enforced by the components themselves, not by external "god functions".
4.  **Consistency:** The entire TCP lifecycle (Handshake + Established) now uses the same architectural pattern.
