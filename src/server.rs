use crate::io::{netconf, proxy};
use crate::{ssh_client, NETCONF_ALPN_STRING, SERVER_CERT_PATH, SERVER_KEY_PATH};
use anyhow::{anyhow, bail, Context};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::Incoming;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn run_server(socket_addr: SocketAddr) -> anyhow::Result<()> {
    let server_cert = fs::read(SERVER_CERT_PATH).context("failed to read server cert")?;
    let server_cert = CertificateDer::from(server_cert);

    let server_key = fs::read(SERVER_KEY_PATH).context("failed to read server key")?;
    let server_key = PrivateKeyDer::try_from(server_key)
        .map_err(|_| anyhow!("server has invalid private key"))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_key)?;
    server_crypto.alpn_protocols = vec![NETCONF_ALPN_STRING.as_bytes().to_vec()];

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let endpoint = quinn::Endpoint::server(server_config, socket_addr)?;
    println!("listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match session(incoming).await {
                Ok(_) => {}
                Err(e) => println!("error: {e:?}"),
            }
        });
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn session(incoming: Incoming) -> anyhow::Result<()> {
    let conn = incoming
        .await
        .context("failed to initialize incoming connection")?;

    let mut channel = ssh_client::with_default_ssh_keys("127.0.0.1:830").await?;

    // Receive client hello message
    let mut hello_stream = conn.accept_uni().await?;
    let hello = proxy::read_message(&mut hello_stream).await?;
    if !hello.payload.starts_with(b"<hello") {
        bail!("Expected hello message, found something else");
    }
    let mut ssh_writer = channel.make_writer();
    netconf::write_message(&mut ssh_writer, hello).await?;

    println!("=== HELLO RECEIVED");

    // We handle the SSH client's received messages in a separate task, because we need to
    // always be listening (in case we are receiving a notification instead of a normal response)
    let (ssh_response_tx, mut ssh_response_rx) = tokio::sync::mpsc::unbounded_channel();
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        while let Some(message) = netconf::read_message(&mut channel.make_reader()).await? {
            if message.payload.starts_with(b"<rpc-reply") {
                ssh_response_tx
                    .send(message)
                    .context("failed to send SSH response")?;
            } else {
                let mut stream = conn_clone.open_uni().await?;

                println!("=== NOTIFICATION");
                println!("{}", String::from_utf8_lossy(&message.payload));

                proxy::write_message(&mut stream, message).await?;

                // Close the stream
                stream.finish()?;

                // TODO: I had to add this to ensure the stream actually got sent... Can we remove it?
                stream.stopped().await?;

                println!("=== SENT");
            }
        }

        println!("=== NOTIFICATION TASK DONE");
        Ok::<(), anyhow::Error>(())
    });

    loop {
        // Each request-response is handled inside a new bidi stream
        let (mut response_tx, mut request_rx) = conn.accept_bi().await.context("failed to accept bidi stream")?;

        println!("=== ACCEPTED BIDI STREAM");

        let request = proxy::read_message(&mut request_rx).await?;
        if !request.payload.starts_with(b"<rpc") {
            bail!(
                "unknown message type: {}",
                String::from_utf8_lossy(&request.payload)
            );
        }

        println!(
            "=== RECEIVED MESSAGE (terminator = {:?})",
            request.framing_method
        );

        netconf::write_message(&mut ssh_writer, request).await.context("failed to write to NETCONF server")?;

        println!("=== WROTE MESSAGE TO REAL SERVER");
        let response = ssh_response_rx
            .recv()
            .await
            .ok_or(anyhow!("no SSH response!"))?;

        println!("=== SERVER RESPONSE READ");
        proxy::write_message(&mut response_tx, response).await?;

        // Close the stream
        response_tx.finish()?;

        println!("=== PROXIED RESPONSE TO CLIENT");
    }

    // conn.closed().await;
    // println!("=== CLOSED SESSION");
    //
    // Ok(())
}
