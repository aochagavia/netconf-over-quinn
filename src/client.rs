use crate::io::{netconf, proxy};
use crate::ssh_listener::NetconfSshListener;
use crate::{NETCONF_ALPN_STRING, SERVER_CERT_PATH};
use anyhow::{bail, Context};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn run_client(socket_addr: SocketAddr) -> anyhow::Result<()> {
    // Initialize proxy
    let client_proxy_listener = NetconfSshListener::new("127.0.0.1:8081".parse().unwrap()).await?;
    println!("listening on 127.0.0.1:8081");

    let mut ssh_connection = client_proxy_listener
        .next_client()
        .await
        .context("failed to get next client")?;

    // Initialize QUIC client
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;

    let mut roots = rustls::RootCertStore::empty();
    let server_cert = fs::read(SERVER_CERT_PATH).context("failed to read server cert path")?;
    roots.add(CertificateDer::from(server_cert))?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![NETCONF_ALPN_STRING.as_bytes().to_vec()];

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client.set_default_client_config(client_config);

    let connecting = client.connect(socket_addr, "localhost")?;
    let connection = connecting.await?;

    let connection_clone = connection.clone();
    let mut ssh_writer = ssh_connection.make_writer();
    tokio::task::spawn(async move {
        // Handle incoming data from the SSH channel
        println!("=== HANDLING INCOMING SSH DATA");

        let mut hello_sent = false;
        loop {
            let Some(request) = netconf::read_message(&mut ssh_connection.make_reader()).await?
            else {
                break;
            };

            if request.payload.starts_with(b"<hello") {
                // The `hello` message requires custom handling (we send it in an initial uni
                // stream, instead of in a bidi stream like RPC commands)
                if hello_sent {
                    bail!("Hello message sent for the second time!");
                }

                hello_sent = true;

                println!("=== SENDING HELLO (framing = {:?})", request.framing_method);
                println!("{}", String::from_utf8_lossy(&request.payload));
                let mut stream = connection_clone.open_uni().await?;
                proxy::write_message(&mut stream, request).await?;
                stream.finish()?;
            } else if request.payload.starts_with(b"<rpc") {
                // Each RPC call is processed inside its own bidi stream
                let (mut request_tx, mut response_rx) = connection_clone.open_bi().await?;

                println!("=== REQUEST (framing = {:?})", request.framing_method);
                println!("{}", String::from_utf8_lossy(&request.payload));

                proxy::write_message(&mut request_tx, request).await?;
                request_tx.finish()?;

                let response = proxy::read_message(&mut response_rx).await?;

                println!("=== RESPONSE (framing = {:?})", response.framing_method);
                println!("{}", String::from_utf8_lossy(&response.payload));

                // Write response to the SSH writer
                netconf::write_message(&mut ssh_connection.make_writer(), response).await?;
            } else {
                println!("=== UNKNOWN MESSAGE KIND");
                println!("{}", String::from_utf8_lossy(&request.payload));
            }

            println!("=== MESSAGE HANDLED");
        }

        Ok::<(), anyhow::Error>(())
    });

    // Notification handling (btw. the server's `<hello>` is treated as a notification)
    // Each notification comes in its own unidirectional stream
    println!("=== HANDLING NOTIFICATIONS");
    while let Ok(mut notification_rx) = connection.accept_uni().await {
        println!("=== ACCEPTED UNI STREAM");
        let message = proxy::read_message(&mut notification_rx).await?;

        println!("=== NOTIFICATION (framing = {:?})", message.framing_method);
        println!("{}", String::from_utf8_lossy(&message.payload));

        netconf::write_message(&mut ssh_writer, message).await?;

        println!("=== WRITTEN");
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
