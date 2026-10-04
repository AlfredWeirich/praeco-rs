//! A simple Yamux server example.
//! This server listens for incoming TCP connections, upgrades them to Yamux multiplexed sessions,
//! and echoes back any data received on any substream.

use tokio::net::{TcpListener, TcpStream};
use yamux::{Config, Connection, Mode};
use tokio_util::compat::TokioAsyncReadCompatExt;
use futures::io::{AsyncReadExt, AsyncWriteExt};

/// Binds a TCP listener and handles incoming connections by upgrading them
/// to multiplexed Yamux sessions.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Yamux TCP server listening on 127.0.0.1:8080");

    loop {
        // Accept a raw TCP connection
        let (socket, remote_addr) = listener.accept().await?;
        println!("Accepted raw TCP connection from: {remote_addr}");

        // Spawn a background task to handle the lifecycle of this specific TCP connection
        tokio::spawn(async move {
            println!("Processing raw TCP connection from: {remote_addr}");
            if let Err(e) = upgrade_and_serve(socket).await {
                eprintln!("Yamux connection error: {e}");
            }
        });
    }
}

/// Upgrades a standard `TcpStream` into a Yamux connection,
/// drives the multiplexer, and accepts incoming logical substreams.
async fn upgrade_and_serve(socket: TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Use the default Yamux configuration
    let config = Config::default();

    // Initialize the Yamux connection in Server mode.
    // We must use `.compat()` from `tokio-util` because Yamux expects `futures::io` traits,
    // whereas Tokio provides `tokio::io` traits.
    let mut connection = Connection::new(socket.compat(), config, Mode::Server);

    // Accept incoming multiplexed substreams by continuously polling the connection.
    // In Yamux 0.14, the `Connection` implements `futures::Stream`, yielding incoming streams.
    // We use `std::future::poll_fn` to manually drive the connection forward.
    while let Some(stream_result) = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)).await {
        match stream_result {
            Ok(stream) => {
                // For each newly opened substream, spawn a dedicated task to handle it
                tokio::spawn(async move {
                    if let Err(e) = handle_substream(stream).await {
                        eprintln!("Error in substream: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept substream: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Processes a single multiplexed Yamux substream.
/// This acts as a simple echo server, returning any received data back to the client.
async fn handle_substream(mut stream: yamux::Stream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 1024];
    
    // Read data from the substream
    let n = stream.read(&mut buf).await?;
    
    if n > 0 {
        println!("Received {} bytes on a multiplexed substream", n);
        
        // Echo the data back to the client
        stream.write_all(&buf[..n]).await?;
    }

    Ok(())
}
