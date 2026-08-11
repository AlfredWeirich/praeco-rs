# praeco-reflection

**praeco-reflection** is the dynamic gRPC translation engine powering the `praeco-rs` API Gateway.

This crate enables the unique **JSON Transcoding** feature of the gateway. It allows the proxy to act as a bridge between modern REST/JSON clients (like web browsers or standard HTTP tools) and binary gRPC backend services.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

> **Note:** This crate is part of the [praeco-rs](https://github.com/AlfredWeirich/praeco-rs) project — an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. Check out the main repository to see how all the pieces fit together!

## How it works

1. **Schema Discovery**: Connects to upstream gRPC servers and uses gRPC Server Reflection to download the protobuf schemas on-the-fly.
2. **Dynamic Translation**: Parses incoming JSON HTTP requests and translates them into binary Protobuf payloads (`prost`).
3. **Transparent Proxying**: Forwards the binary payload to the gRPC server, awaits the response, and translates the Protobuf response back into JSON before sending it to the client.

By using this crate, `praeco-rs` can proxy gRPC services without requiring any pre-compiled `.proto` files at runtime.

## Example (CLI Router)

You can launch the standalone reflection router to test dynamic transcoding against a backend gRPC service (e.g. running on port 50051):

```bash
# Start the dynamic gRPC reflection router
$ cargo run -p praeco-reflection --bin grpc_router
Listening on http://127.0.0.1:3000

# Now you can send a standard JSON POST request:
$ curl -X POST http://127.0.0.1:3000/helloworld.Greeter/SayHello \
    -H "Content-Type: application/json" \
    -d '{"name": "World"}'

# The router translates this to binary Protobuf, sends it to port 50051,
# and translates the binary response back to JSON:
{"message": "Hello World"}
```

## Example (Rust Integration)

To test the router programmatically via Rust:

```rust
use std::process::Command;

fn main() {
    // Start the router in the background
    let mut router = Command::new("cargo")
        .args(["run", "-p", "praeco-reflection", "--bin", "grpc_router"])
        .spawn()
        .expect("Failed to start router");

    println!("Router started with PID: {}", router.id());
    
    // In a real test, you'd make HTTP requests to http://127.0.0.1:3000 here
    
    // Kill the router when done
    router.kill().expect("Failed to kill router");
}
```
