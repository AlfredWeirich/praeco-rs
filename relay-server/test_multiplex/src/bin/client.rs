//! A concurrent Yamux client example.
//! This client establishes a single TCP connection to the server and spawns multiple asynchronous
//! tasks. Each task concurrently requests a new logical substream and communicates over it.

use tokio::net::TcpStream;
use yamux::{Config, Connection, Mode};
use tokio_util::compat::TokioAsyncReadCompatExt;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// Connects to a Yamux server as a client and opens multiple substreams simultaneously.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Establish the underlying raw TCP connection
    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("TCP connection to the server established.");

    // Use the default Yamux configuration
    let config = Config::default();

    // Initialize the Yamux connection in Client mode
    let mut connection = Connection::new(socket.compat(), config, Mode::Client);

    // We create a channel so that our worker tasks can request new substreams
    // from the connection driver task asynchronously.
    let (tx, mut rx) = mpsc::channel::<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>>(10);

    // --- The Yamux Connection Driver ---
    // This background task "drives" the TCP connection.
    // Since Yamux 0.14 requires the connection to be polled constantly to make progress,
    // we handle both opening outbound streams and processing incoming network events here.
    tokio::spawn(async move {
        // Holds a pending request to open a new outbound stream
        let mut pending_outbound: Option<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>> = None;

        std::future::poll_fn(|cx| {
            // 1. Are there any new requests from worker tasks to open an outbound stream?
            if pending_outbound.is_none() {
                if let std::task::Poll::Ready(Some(resp_tx)) = rx.poll_recv(cx) {
                    pending_outbound = Some(resp_tx);
                }
            }

            // 2. If we have a pending request, drive the outbound stream creation process
            if pending_outbound.is_some() {
                if let std::task::Poll::Ready(result) = connection.poll_new_outbound(cx) {
                    let resp_tx = pending_outbound.take().unwrap();
                    // Send the newly created stream (or error) back to the requesting task
                    let _ = resp_tx.send(result); 
                }
            }

            // 3. Keep the connection alive: process incoming events (e.g., WindowUpdates, Pings)
            // Even though we are a client and don't expect incoming streams, we MUST poll this 
            // to ensure the underlying state machine makes progress.
            while let std::task::Poll::Ready(Some(_inbound)) = connection.poll_next_inbound(cx) {
                // We ignore incoming streams from the server in this client example
            }

            // The driver never terminates on its own unless the connection dies
            std::task::Poll::Pending::<()>
        }).await;
    });

    // --- Multiplexing in Action ---
    // We spawn 5 completely independent Tokio tasks that will communicate SIMULTANEOUSLY
    // over the exact same underlying TCP connection.
    let mut tasks = vec![];

    for i in 1..=5 {
        let tx = tx.clone();
        
        let handle = tokio::spawn(async move {
            // 1. Request a new substream from the background driver
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(resp_tx).await.unwrap();
            
            // Wait until the driver provides us with the opened stream
            let mut stream = resp_rx.await.unwrap().unwrap();
            
            // 2. Communicate over the independent logical stream
            let msg = format!("Message from Task {}", i);
            stream.write_all(msg.as_bytes()).await.unwrap();

            // 3. Await the echo response from the server
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            
            println!("Task {} received response: {:?}", i, String::from_utf8_lossy(&buf[..n]));
        });
        
        tasks.push(handle);
    }

    // Wait for all 5 concurrent tasks to finish their communication
    for t in tasks {
        t.await?;
    }

    Ok(())
}
