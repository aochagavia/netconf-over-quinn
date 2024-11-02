use crate::io::{netconf_quic, netconf_ssh};
use crate::ssh_listener::NetconfSshListener;
use crate::{NETCONF_ALPN_STRING, SERVER_CERT_PATH};
use anyhow::{bail, Context};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::TransportConfig;
use russh::server::Msg;
use russh::Channel;
use rustls::pki_types::CertificateDer;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub async fn run_client(socket_addr: SocketAddr) -> anyhow::Result<()> {
    // Listen to incoming SSH connections
    let client_proxy_listener = NetconfSshListener::new("127.0.0.1:8081".parse().unwrap()).await?;
    println!("listening on 127.0.0.1:8081");

    loop {
        let ssh_connection = client_proxy_listener
            .next_client()
            .await
            .context("failed to get next client");

        match ssh_connection {
            Ok(ssh_connection) => {
                tokio::spawn(handle_single_client(ssh_connection, socket_addr));
            }
            Err(e) => {
                println!("Error accepting SSH connection: {e:?}")
            }
        }
    }
}

async fn handle_single_client(
    mut ssh_connection: Channel<Msg>,
    quic_server_socket_addr: SocketAddr,
) -> anyhow::Result<()> {
    // Initialize QUIC client
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;

    let mut roots = rustls::RootCertStore::empty();
    let server_cert = fs::read(SERVER_CERT_PATH).context("failed to read server cert path")?;
    roots.add(CertificateDer::from(server_cert))?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![NETCONF_ALPN_STRING.as_bytes().to_vec()];

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    let mut transport_config = TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(2)));
    client_config.transport_config(Arc::new(transport_config));
    client.set_default_client_config(client_config);

    let connecting = client.connect(quic_server_socket_addr, "localhost")?;
    let connection = connecting.await?;

    let connection_clone = connection.clone();
    let mut ssh_writer = ssh_connection.make_writer();
    tokio::task::spawn(async move {
        // Handle incoming data from the SSH channel
        println!("=== HANDLING INCOMING SSH DATA");

        let mut hello_sent = false;
        loop {
            let Some(request) =
                netconf_ssh::read_message(&mut ssh_connection.make_reader()).await?
            else {
                break;
            };

            // The `hello` message requires custom handling (we send it in an initial bidi
            // stream and wait for the hello response
            if request.payload.starts_with(b"<hello") {
                println!("=== SENDING HELLO");

                if hello_sent {
                    bail!("Hello message sent for the second time!");
                }

                hello_sent = true;

                println!("{}", String::from_utf8_lossy(&request.payload));
                let (mut stream_tx, mut stream_rx) = connection_clone.open_bi().await?;
                netconf_quic::write_message(&mut stream_tx, request).await?;
                stream_tx.finish()?;

                let msg = netconf_quic::read_message(&mut stream_rx).await?;
                if !msg.payload.starts_with(b"<hello") {
                    bail!("Hello message from the server didn't start with `<hello`")
                }
                println!("=== RECEIVED HELLO");
                netconf_ssh::write_message(&mut ssh_connection.make_writer(), msg).await?;
            } else if request.payload.starts_with(b"<rpc") {
                // Each RPC call is processed inside its own bidi stream
                println!("=== OPEN BI");
                let (mut request_tx, mut response_rx) = connection_clone.open_bi().await?;

                println!("=== REQUEST");
                println!("{}", String::from_utf8_lossy(&request.payload));

                netconf_quic::write_message(&mut request_tx, request).await?;
                request_tx.finish()?;

                let response = netconf_quic::read_message(&mut response_rx).await?;

                println!("=== RESPONSE");
                println!("{}", String::from_utf8_lossy(&response.payload));

                // Write response to the SSH writer
                netconf_ssh::write_message(&mut ssh_connection.make_writer(), response).await?;
            } else {
                println!("=== UNKNOWN MESSAGE KIND");
                println!("{}", String::from_utf8_lossy(&request.payload));
            }

            println!("=== MESSAGE HANDLED");
        }

        Ok::<(), anyhow::Error>(())
    });

    // Notification handling
    println!("=== HANDLING NOTIFICATIONS");
    if let Ok(mut notification_rx) = connection.accept_uni().await {
        println!("=== ACCEPTED NOTIFICATIONS STREAM");

        while let Some(message) = netconf_ssh::read_message(&mut notification_rx).await? {
            println!("=== NOTIFICATION");
            println!("{}", String::from_utf8_lossy(&message.payload));

            netconf_ssh::write_message(&mut ssh_writer, message).await?;
            println!("=== WRITTEN");
        }
    }

    if let Some(reason) = connection.close_reason() {
        println!("=== CONNECTION CLOSED BY PEER");
        println!("{reason:?}");
    }

    println!("=== CLOSING CLIENT");

    // Nothing else to read from the client
    connection.close(0u32.into(), b"done");
    client.wait_idle().await;

    Ok(())
}
