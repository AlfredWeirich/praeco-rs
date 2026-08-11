# REST to gRPC Gateway

## Fundamentals of gRPC and Tonic
As part of the article series "Tokio, Tower, Hyper, and Rustls: Building High-Performance and Secure Servers in Rust," we recently extended our routing layer into a fully-fledged load balancer with hot reloading. 
In this article, I will explain the fundamentals of how to extend the routing layer with "REST to gRPC Gateway" functionality.
Before we tackle the extension of the now quite complex routing layer, we need to understand the fundamentals of Tonic, gRPC, and routing from REST to gRPC and back. We have developed several small programs for this purpose.

This guide is designed to introduce developers and software architects who are new to the ecosystem around gRPC, Protocol Buffers (Protobuf), Tonic (the de facto standard gRPC framework for Rust), and Server Reflection to the topic. We will analyze in detail how a high-performance, modern gRPC infrastructure is built and how we construct an API gateway (router) that acts as an intelligent translator. This gateway receives classic REST/JSON traffic from frontend clients and translates it into binary gRPC at runtime (dynamically) without needing to recompile the gateway when APIs change.

## The Role of Tonic in the Rust Ecosystem
Before diving deep into the protocol layer, we need to clarify *how* gRPC is implemented in Rust. The answer is **Tonic**.

Tonic is the dominant gRPC framework for Rust, supported by the community and large parts of the industry. It is built on proven, high-performance async foundations:
* **Hyper**: An extremely fast, secure HTTP library (Tonic primarily uses Hyper's HTTP/2 features).
* **Tokio**: The asynchronous runtime for Rust.
* **Prost**: A Protocol Buffer compiler and runtime that integrates seamlessly with Rust's type system.

Tonic abstracts away the entire complexity of network multiplexing, HTTP/2 framing, streaming, and asynchronous I/O management. When you write a server in Tonic, you essentially just implement a simple `async trait`. This allows you to focus 100% on your business logic, while the framework juggles thousands of parallel streams over a few persistent TCP connections in the background.

## The Foundation: Protocol Buffers (Protobuf)
Before writing any code, we must understand the fundamental paradigm shift compared to REST. In the REST world (e.g., OpenAPI), code and contracts often exist side by side, or the contract is generated from the code. JSON is flexible but incredibly verbose and inefficient. If we send `{"name": "Alice"}`, the server parses quotes, colons, brackets, and transmits the word "name" as a string over the wire—for every single request.

**Protocol Buffers (Protobuf)** is the data serialization mechanism powering gRPC. It is a platform- and language-neutral system created by Google.

### The `.proto` File: The IDL (Interface Definition Language)
In gRPC, the schema represents a strict contract (Contract-first). We write a `.proto` file that defines our data types (Messages) and our endpoints (Services).

Excerpt from the `.proto` file:
```protobuf
syntax = "proto3"; // The current version of the Protobuf standard

// The namespace. Prevents collisions 
// if multiple teams define an "IdentityService".
package system;  

// A service defines the actual RPC (Remote Procedure Call) methods.
// This is the equivalent of a REST controller with its routes.
service IdentityService {
  // A method named "Login". It takes exactly one Request object
  // and returns exactly one Response object. (This is called "Unary").
  rpc Login (LoginRequest) returns (AuthTokenResponse);
}

// A Message is the equivalent of a JSON object or a C-struct.
message LoginRequest {
  // The core of Protobuf: Field types and Tags.
  // "username" is a string and is assigned the tag "1".
  string username = 1;
  string password = 2;
}

message AuthTokenResponse {
  string token = 1;
  int64 expires_in_seconds = 2;
}
```

### Why is this faster than JSON?
The crucial trick of Protobuf lies in the tags (`= 1`, `= 2`). When gRPC sends this object over the network, it does *not* send the string `"username"`. It merely sends the binary marker for Tag 1 (which consumes only a few bits) followed by the actual value (`"Alice"`).

The result:
1. **Extremely small payload:** Often 5 to 10 times smaller than JSON.
2. **CPU-efficient:** No expensive lexers/parsers for strings and brackets. The server reads bytes directly into the appropriate generated structs.
3. **Forward and backward compatibility:** If you add a field `string lastname = 3;`, older clients simply ignore "Tag 3". If an old client doesn't send "Tag 2", the new server fills in a default value.

## The Protobuf Compiler (`protoc`) and Code Generation
To use this `.proto` file in an object-oriented (or data-oriented like Rust) programming language, we need a compiler. Google provides `protoc` for this purpose.
`protoc` parses the `.proto` file and generates language-specific code. If you invoke `protoc` with the Java plugin, you get Java classes. With the Go plugin, you get Go structs.

### How Tonic Automates this Process in Rust (`build.rs`)
In Rust, we don't want to manually run `protoc` on the command line every time we build our project. We seamlessly integrate this step into the Cargo build lifecycle using a `build.rs` file. The `tonic-build` crate acts as a wrapper around `protoc`. Every time you run `cargo build`, this script reads the `.proto` files and generates the Rust code in the background within the temporary `OUT_DIR` directory.

### What Exactly Does Tonic Generate?
* **Data structures (`struct`):** The Protobuf message `LoginRequest` becomes an actual Rust struct `LoginRequest { pub username: String, pub password: String }`. This uses the `prost` library for blazing-fast binary (de)serialization in Rust.
* **Server Stubs (Traits):** Tonic generates an `IdentityService` trait. Our server code must implement this trait. Tonic also creates an `IdentityServiceServer` wrapper that accepts incoming HTTP/2 streams, handles framing (see below), deserializes bytes, calls our trait method, serializes the result back to bytes, and sends it back via HTTP/2. This handles massive amounts of complex boilerplate code for us.
* **Client Stubs:** Tonic generates an `IdentityServiceClient` struct. It encapsulates the HTTP/2 connections (multiplexing) and offers type-safe asynchronous methods (like `client.login(...)`).

## The Build Code and the Magic of the Descriptor Set
If we want to build a dynamic API gateway later (which must operate *without* the statically generated code!), this gateway needs the `.proto` definitions at runtime. Where does the gateway get this information? Via the **gRPC Reflection API** from the backend microservice (the `grpc-server`).

For the backend microservice to be able to answer the gateway's queries, we must instruct the compiler in the backend code to emit a binary metadata file in addition to the Rust code: the `FileDescriptorSet`. This `.bin` file contains the exact schema of all messages and services in a precise, machine-readable Protobuf format. The server later loads this file into its memory to make it available to the gateway.

```rust
//! build.rs
//!
//! This script is executed by Cargo *before* the main code is compiled.
//! For gRPC applications, this is the standard place to instruct the `tonic-build`
//! crate to parse your `.proto` schema files and automatically generate the
//! corresponding Rust structs, client stubs, and server traits.
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `OUT_DIR` is an environment variable provided by Cargo. It points to a
    // temporary directory inside `target/` where build scripts are allowed
    // to write generated files.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Configure the Tonic Protobuf compiler
    tonic_build::configure()
        // IMPORTANT FOR REFLECTION:
        // By default, tonic only generates Rust code (.rs files).
        // However, gRPC Server Reflection requires the raw layout 
        // of the schema exactly as it was defined, 
        // stored as a binary "Descriptor Set".
        .file_descriptor_set_path(out_dir.join("system_services_descriptor.bin"))
        // Finally, compile the actual proto file located in our project, 
        // as well as the reflection proto
        .compile_protos(
            &[
                "proto/system_services.proto",
                "proto/reflection/v1/reflection.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
```

## First Attempt: A gRPC Server with a Static Client
First, we want to step away from Server Reflection and get a server running with a standard, strongly-typed client. For both to communicate, we import the code generated by `build.rs` using the `tonic::include_proto!` macro.

### The Server
Our server implements the automatically generated `IdentityService` trait. The developer only cares about the business logic (reading the input parameters and returning a response). `Tonic` handles all the network wiring, buffer management, and HTTP/2 framing.

```rust
// src/server.rs
// Excerpt
pub mod system {
    tonic::include_proto!("system");
}
use system::identity_service_server::{IdentityService, IdentityServiceServer};
use system::{LoginRequest, AuthTokenResponse};
use tonic::{transport::Server, Request, Response, Status};

#[derive(Default)]
pub struct MyIdentityService {}

#[tonic::async_trait]
impl IdentityService for MyIdentityService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<AuthTokenResponse>, Status> {
        let req = request.into_inner();
        // Type-safe access to the 'username' and 'password' fields
        if req.username == "admin" && req.password == "admin123" {
            Ok(Response::new(AuthTokenResponse {
                token: "eyJhbGciOiJIUzI1Ni...".into(),
                expires_in_seconds: 3600,
            }))
        } else {
            Err(Status::unauthenticated("Invalid credentials"))
        }
    }
}
```

### The Static Client
A Rust client (e.g., Microservice B calling Microservice A) uses the generated `IdentityServiceClient`. HTTP/2 allows bidirectional streaming and multiplexing; the `IdentityServiceClient` abstracts these highly complex processes completely.

```rust
// src/static_client.rs (Excerpt)
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create exactly ONE underlying HTTP/2 connection (Channel)
    let channel = tonic::transport::Endpoint::from_static("http://[::1]:50051")
        .connect()
        .await?;    
    // 2. Clone the lightweight channel
    let mut client = IdentityServiceClient::new(channel.clone());
    
    // 3. Create the type-safe request
    let request = tonic::Request::new(LoginRequest { 
        username: "admin".into(), 
        password: "admin123".into() 
    });
    
    // Under the hood: Serializes to Protobuf, sends via HTTP/2, 
    // waits asynchronously, deserializes from the network
    let response = client.login(request).await?; 
    println!("Response: {:?}", response.into_inner()); 
    // prints: AuthTokenResponse { token: "...", expires_in_seconds: 3600 }
    Ok(())
}
```
*(The complete code is included at the end of the article).*

## gRPC Server Reflection
This static, pre-compiled approach scales extremely well internally. However, in modern infrastructures, there are tools that need to debug gRPC (like the CLI tool `grpcurl` or a GUI like Postman) or "dumb" API gateways (routers) that merely direct traffic without knowing the business logic of the microservices.

How can a generic gateway understand how to translate JSON into Protobuf if it doesn't know the Rust structs at compile-time?

The solution is **Server Reflection**. Reflection is a predefined, standard gRPC service. A server can explicitly enable this special service, essentially telling the world: *"Just ask me about my layout via gRPC, and I will send you my entire data model, as if you were reading my `.proto` files."*

For the server to do this, we inject the machine-readable `FileDescriptorSet` (the `.bin` file we just compiled using `configure()`) into the server initialization:

```rust
// src/server.rs init logic
use tonic_reflection::server::Builder as ReflectionBuilder;

// We embed the generated binary file directly into our executable
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("system_services_descriptor");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    
    // Build the standardized Reflection Service
    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;

    Server::builder()
        .add_service(IdentityServiceServer::new(MyIdentityService::default())) // The actual use case
        .add_service(reflection_service)                                       // Allows others to download our schema at runtime!
        .serve(addr)
        .await?;
    
    Ok(())
}
```

## The gRPC Transcoding Router
Let's get to the core: The API Gateway. A frontend (like React) sends simple JSON text via HTTP POST. The frontend knows nothing about HTTP/2 streams or gRPC. The router takes the JSON, converts it into binary gRPC, and forwards it to the gRPC backend. This is known as **Dynamic gRPC Transcoding**. To achieve this, we need the `prost-reflect` crate, which allows treating Protobuf messages dynamically, without static structs, using mere schema objects.

### Step A: Building the Schema Pool
The gateway boots up without ever having seen a `.proto` file, a compiled `.bin`, or Rust structs. Instead, it utilizes a standardized gRPC Reflection Client. It connects via HTTP/2 to the configured microservice and calls the `ServerReflection` service (version `v1`). 

First, the router asks: *"What services do you offer?"* (`ListServices`). 
Subsequently, the router iteratively asks for each discovered service: *"Give me the raw Protobuf bytes that describe how this service works"* (`FileContainingSymbol`).

From these responses (many small `FileDescriptorProto` objects), the API gateway builds an in-memory catalog existing purely at runtime: the `DescriptorPool`.

```rust
// router.rs (Excerpt: The Dynamic Schema Fetch)
let mut reflection_client = 
   ServerReflectionClient::connect("http://[::1]:50051").await?;

// Since the Reflection API in gRPC is defined as a "Bidirectional Stream" 
// (rpc ServerReflectionInfo(stream Req) returns (stream Res)), 
// Tonic demands an asynchronous Stream object.
// We use an MPSC (Multi-Producer, Single-Consumer) Channel 
// as an adapter to "squeeze" our single requests 
// into Tonic's asynchronous streaming interface.
let (tx, rx) = tokio::sync::mpsc::channel(1);
tx.send(ServerReflectionRequest { ... }).await?;

// We pass the receiver (rx) converted into a Stream to Tonic
let response = reflection_client
    .server_reflection_info(tonic::Request::new(ReceiverStream::new(rx)))
    .await?;

// ... Process response_stream ...

for fd_bytes in fd_res.file_descriptor_proto {
    // Converts the raw binary bytes into a logical struct object
    let fd_proto = prost::Message::decode(fd_bytes.as_ref())?;
    
    // We throw this schema into our pool on the fly
    pool.add_file_descriptor_proto(fd_proto)?; 
}
```

### Step B: From HTTP Call to Method Request
Every gRPC call uses REST-like HTTP/2 paths under the hood. The standard format is: `POST /<package>.<service>/<method>`.

So, when the frontend client (JavaScript) calls `POST http://127.0.0.1:8080/system.IdentityService/Login`, the router extracts the path and looks up the exact method schema in its pool.

```rust
// Excerpt from src/router.rs
// Extracting from the URL "/system.IdentityService/Login"

// We expect REST clients to POST to `/Package.Service/MethodName`
// Example: /system.IdentityService/Login
let uri_path = req.uri().path().to_string();
let path = uri_path.trim_start_matches('/');
let parts: Vec<&str> = path.split('/').collect();

if req.method() != Method::POST || parts.len() != 2 {
    return Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from(
            "Please use POST /Fully.Qualified.Service/Method!\n",
        )))?);
}

let service_name = parts[0];
let method_name = parts[1];

// ...

// The router fetches the schema instructions (MethodDescriptor) from its Memory Pool at runtime.
// These instructions tell it: "For this endpoint, a 'LoginRequest' object must be built. 
// It mandatorily requires a 'username' field of type String at Tag 1."
let method_desc = pool.get_service_by_name(service_name)
    .unwrap()
    .methods()
    .find(|m| m.name() == method_name)
    .unwrap();
```

### Step C: Dynamic Deserialization (JSON to Protobuf)
Now the router reads the string body of the HTTP request (e.g., `{"username": "admin", "password": "admin123"}`). It creates a "generic" memory template (`DynamicMessage`) from the `MethodDescriptor`. Utilizing `serde_json`, the router feeds the JSON string exactly through this template.

If the types don't match (e.g., `username` contains an integer instead of text), or if the JSON contains fields the backend rejects, the router instantly throws an error here (`400 Bad Request`), preventing unnecessary load on the microservice. If everything matches flawlessly, the router encodes the dynamic message directly into a highly compressed binary Protobuf byte array.

```rust
let mut deserializer = serde_json::Deserializer::from_slice(&json_from_client);
let dynamic_req_msg = method_desc.input().deserialize(&mut deserializer).unwrap();

let mut protobuf_payload = BytesMut::new();
dynamic_req_msg.encode(&mut protobuf_payload).unwrap();
```

### Step D: gRPC Framing
Given that gRPC transmits the actual message over an HTTP/2 TCP connection, length demarkation is required (so-called *Length-Prefixed Framing*). Otherwise, the receiver wouldn't know when the first byte stream ends. Framing is extremely strictly regulated in gRPC.

Every gRPC message requires exactly **5 bytes** prepended:
* `Byte 1`: A compression flag (`0` = uncompressed, `1` = compressed, e.g., via gzip). *(We assume uncompressed for this tutorial).*
* `Byte 2-5`: A 4-byte (32-bit) integer in Big-Endian format representing the exact length of the appended payload in bytes.

The router precisely prepends this before the serialized bytes.

```rust
let mut grpc_frame = BytesMut::with_capacity(5 + protobuf_payload.len());
grpc_frame.put_u8(0); 
grpc_frame.put_u32(protobuf_payload.len() as u32);
grpc_frame.put_slice(&protobuf_payload);
```

### Step E: Routing the HTTP/2 Request
Finally, the router constructs a valid HTTP/2 request using Hyper. It's crucial to set the `application/grpc` constant as the Content-Type and include the keyword `"te": "trailers"`, which mandates that HTTP headers are allowed to arrive *after* the actual body (gRPC utilizes this to communicate error codes or trailing metadata at the end of the stream).

We fire this to our microservice. It is perfectly happy: It seems to have been called by an authentic gRPC client. It is entirely unaware that there is a JavaScript frontend and a dynamic router operating in reality.

```rust
let grpc_req = Request::builder()
    .method(Method::POST)
    .uri("http://[::1]:50051/system.IdentityService/Login")
    .header("content-type", "application/grpc")
    .header("te", "trailers")
    .body(Full::new(grpc_frame.freeze()))
    .unwrap();

// The asynchronous HTTP/2 call
let response = client.request(grpc_req).await.unwrap();
```

### Step F: The Return Journey (Decoding)
The microservice replies with the same 5-byte framing format. The router buffers the binary stream, strips the 5 header bytes to obtain the raw Protobuf, and calls its `DescriptorPool` again, this time with `method_desc.output()`.

It decodes the binary ones and zeros into a struct, translates this generic struct into a clean JSON string via `serde_json`, and returns it to the end customer's browser.

```rust
// Parse the 4 bytes indicating length to extract only the payload
let payload_len = u32::from_be_bytes(res_body_bytes[1..5].try_into().unwrap()) as usize;
let raw_protobuf_res = &res_body_bytes[5..5 + payload_len];

// ------------------------------------
// STEP 6: TRANSLATE PROTOBUF -> JSON
// ------------------------------------
// Decode the raw binary back into a DynamicMessage dictionary based on the output schema
let mut dynamic_res_msg = DynamicMessage::new(method_desc.output());
if let Err(e) = dynamic_res_msg.merge(raw_protobuf_res) {
    return Ok(Response::builder()
        .status(502)
        .body(Full::new(Bytes::from(format!(
            "Failed to parse Protobuf: {}\n",
            e
        ))))?);
}

// Finally, transform it into standard JSON to send back to the REST client
// DynamicMessage implements the Trait Serialize
let response_json = serde_json::to_string(&dynamic_res_msg)?;
println!("Router sending back JSON: {}", response_json);
```

## Security: TLS, mTLS, and JWT in gRPC Routing
While we have focused heavily on pure functionality and routing up to this point, a production architecture never operates in plaintext (HTTP). Our gRPC gateway and microservices must communicate over a highly secured network.

There are three central security concepts that generally interlock in such an infrastructure:

### A) Basic TLS (Transport Layer Security)
Just as with regular websites, TLS is practically mandatory with HTTP/2 (and thus gRPC).
* **How it works:** A critical distinction: For simplicity, we use unencrypted HTTP on port 8080 in our local tutorial code. However, in a real production gateway accepting connections from the public internet, this must absolutely occur over HTTPS (typically handled via TLS termination at an upstream load balancer or edge router).
* **Internal traffic:** The connection *between* our gateway and the microservice (the internal HTTP/2 link) should also be handled via encrypted TCP streams (`rustls` within Tonic). The gateway validates that it is genuinely communicating with our internal microservice (Server Validation).

### B) TLS & mTLS (Transport Encryption via Rustls/Hyper)
Since gRPC is standardly based on HTTP/2 and Tonic employs the high-performance HTTP framework `Hyper` under the hood, we can effortlessly establish highly secure TLS or mTLS (Mutual TLS) connections using the `rustls` library.
* **Basic TLS:** Self-encryption. The path between the router and microservice (or from the outside to the router) is fully encrypted, just as with proper HTTPS.
* **mTLS (Mutual TLS):** In an internal Zero-Trust microservice environment, basic TLS is often insufficient. mTLS ensures that *both* sides must authenticate themselves. When the router communicates with the `system.IdentityService`, it transmits its own cryptographic certificate. The microservice verifies: *"Was this router certificate signed by my internal Certificate Authority (CA)?"*.

### C) JWT (JSON Web Tokens) and the "Interceptor Bouncer"
While TLS and mTLS guarantee machine-to-machine security (verifying the gateway is authorized to talk to the backend), it does not answer the question concerning *end-user authorization* (Is user "Admin" allowed to fetch data?).
* **The Problem:** A frontend in the browser classically sends the token as an HTTP header (`Authorization: Bearer eyJ...`). Our backend microservice, however, is not an HTTP server, but a gRPC server.
* **Transcoding:** The genius of our gRPC API gateway is its ability to automatically detect such classic HTTP metadata headers and seamlessly copy them 1-to-1 as **gRPC Metadata** (the gRPC equivalent of HTTP headers) into the new binary HTTP/2 tunnel leading to the backend.
* **Verification in the Backend:** The microservice must now verify whether the copied token in the metadata dictionary is valid. To avert duplicating this verification logic across every single endpoint, we utilize a **Tonic Interceptor**. 
An Interceptor acts like a "bouncer" standing before our gRPC server. Before a request is ever permitted to reach our Rust business logic (like `StoreData`), the bouncer inspects the gRPC Metadata. If it finds the JWT, it validates its cryptographic signature. If the signature is tampered with or expired, the bouncer instantly rejects the call with the `Code::Unauthenticated` status. If everything is flawless, the door to the functionality opens.

**Example of a JWT Interceptor in Tonic:**
```rust
use tonic::{Request, Status};

// This is our "bouncer"
fn check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    // 1. Search for the extracted HTTP header within the gRPC Metadata
    match req.metadata().get("authorization") {
        Some(token) => {
            // 2. Parse the "Bearer eyJ..." string
            let token_str = token.to_str().unwrap_or("");
            if token_str.starts_with("Bearer ") && token_str.len() > 7 {
                let jwt = &token_str[7..];
                // 3. Genuine certificate verification (simplified)
                if jwt == "my_secret_signature_123" {
                    return Ok(req); // The door opens!
                }
            }
            Err(Status::unauthenticated("Invalid or expired token!"))
        },
        None => Err(Status::unauthenticated("No token found in header!")),
    }
}

// This is how we bind the bouncer to the service during server boot:
// let svc = IdentityServiceServer::with_interceptor(MyIdentityService::default(), check_auth);
```

## API Usage (cURL Examples)
Because the router implements dynamic transcoding, you can directly interface with the deployed microservices using standardized HTTP/1.1 JSON. The router manages all decryption and translation to Protobuf in the background.

**1. Identity Service (Login)**
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  http://127.0.0.1:8080/system.IdentityService/Login
```

**2. System Metrics (Get Health)**
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"include_cpu": true, "include_memory": true}' \
  http://127.0.0.1:8080/system.SystemMetrics/GetHealth
```

**3. Stateful Store Service (In-Memory K/V Store)**

*Storing Data:*
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"key": "mykey", "value": "some data"}' \
  http://127.0.0.1:8080/system.StoreService/StoreData
```

*Retrieving Data:*
```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"key": "mykey"}' \
  http://127.0.0.1:8080/system.StoreService/RetrieveData
```

## Conclusion and Outlook
The ecosystem comprising **Rust, Tonic, and gRPC** currently provides developers with tools empowering them to construct distributed systems that are unrivaled concerning type safety, CPU efficiency, and network throughput.

Through building a dynamic API gateway utilizing **Server Reflection** and **Transcoding**, we've demonstrated how to combine the best of both paradigms:
1. **For the Backend (Rust/gRPC):** Uncompromising performance, extremely compact binary payloads (Protobuf), strictly typed API contracts, and effortless multiplexing over a single HTTP/2 connection. Code generation prevents tedious serialization errors.
2. **For the Frontend (React/Web/cURL):** The familiar ecosystem remains intact. Frontend developers continue to communicate via standard HTTP/1.1, dispatch JSON payloads, transfer their tokens in classic headers, and are alleviated from wrestling with asynchronous stream management or binary encoding.

Our custom router (`router.rs`) demonstrates this transcoding mechanism elegantly. In enterprise production environments, specialized edge proxies like Envoy or Nginx frequently assume these responsibilities. Nonetheless, understanding what transpires "under the hood"—from iterating through asynchronous reflection streams, to the MPSC channel, and ultimately directly verifying JWT metadata in the Tonic interceptor—is indispensable for modern system architects.

**The Complete Experimental Codebase**
* `Cargo.toml`
* `build.rs`
* `proto/system_services.proto`
* `proto/reflection/v1/reflection.proto`: Required for reflection. Downloaded from the official gRPC repository (`https://github.com/grpc/grpcproto/blob/master/grpc/reflection/v1/reflection.proto`).
* `src/router.rs`
* `src/server.rs`
* `src/static_client.rs`

**Usage:**
1. Start the server
2. Start the router
3. Dispatch cURL requests (see above).
