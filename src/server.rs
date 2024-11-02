use crate::io::{netconf_quic, netconf_ssh};
use crate::{ssh_client, NETCONF_ALPN_STRING, SERVER_CERT_PATH, SERVER_KEY_PATH};
use anyhow::{anyhow, bail, Context};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Incoming, SendStream};
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
    let (hello_stream_tx, mut hello_stream_rx) = conn.accept_bi().await?;
    let hello = netconf_quic::read_message(&mut hello_stream_rx).await?;
    if !hello.payload.starts_with(b"<hello") {
        bail!("Expected hello message, found something else");
    }
    let mut ssh_writer = channel.make_writer();
    netconf_ssh::write_message(&mut ssh_writer, hello).await?;
    println!("=== HELLO RECEIVED");

    let mut hello_stream_tx = Some(hello_stream_tx);
    let mut notifications_tx: Option<SendStream> = None;

    // We handle the SSH client's received messages in a separate task, because we need to
    // always be listening (in case we are receiving a notification instead of a normal response)
    let (ssh_response_tx, mut ssh_response_rx) = tokio::sync::mpsc::unbounded_channel();
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        while let Some(message) = netconf_ssh::read_message(&mut channel.make_reader()).await? {
            if message.payload.starts_with(b"<rpc-reply") {
                println!("=== RPC REPLY");
                ssh_response_tx
                    .send(message)
                    .context("failed to send SSH response")?;
            } else if message.payload.starts_with(b"<notification") {
                let mut tx = match notifications_tx {
                    Some(tx) => tx,
                    None => {
                        println!("=== CREATING NOTIFICATION STREAM");
                        conn_clone.open_uni().await?
                    }
                };

                println!("=== NOTIFICATION");
                println!("{}", String::from_utf8_lossy(&message.payload));

                netconf_ssh::write_message(&mut tx, message).await?;
                notifications_tx = Some(tx);

                println!("=== SENT");
            } else if message.payload.starts_with(b"<hello") {
                let Some(mut hello_stream_tx) = hello_stream_tx.take() else {
                    bail!("hello message sent for a second time");
                };

                netconf_quic::write_message(&mut hello_stream_tx, message).await?;
                hello_stream_tx.finish()?;
                println!("=== SENT HELLO")
            } else {
                bail!(
                    "server tried to send message of unknown kind: {}",
                    String::from_utf8_lossy(&message.payload)
                );
            }
        }

        println!("=== NOTIFICATION TASK DONE");
        Ok::<(), anyhow::Error>(())
    });

    loop {
        println!("=== ACCEPT BI");

        // Each request-response is handled inside a new bidi stream
        let (mut response_tx, mut request_rx) = conn
            .accept_bi()
            .await
            .context("failed to accept bidi stream")?;

        println!("=== ACCEPTED BIDI STREAM");

        let request = netconf_quic::read_message(&mut request_rx).await?;
        if !request.payload.starts_with(b"<rpc") {
            bail!(
                "unknown message type: {}",
                String::from_utf8_lossy(&request.payload)
            );
        }

        println!("=== RECEIVED MESSAGE",);

        netconf_ssh::write_message(&mut ssh_writer, request)
            .await
            .context("failed to write to NETCONF server")?;

        println!("=== WROTE MESSAGE TO REAL SERVER");
        let response = ssh_response_rx
            .recv()
            .await
            .ok_or(anyhow!("no SSH response!"))?;

        println!("=== SERVER RESPONSE READ");
        netconf_quic::write_message(&mut response_tx, response).await?;

        // Close the stream
        response_tx.finish()?;

        println!("=== PROXIED RESPONSE TO CLIENT");
    }

    // conn.closed().await;
    // println!("=== CLOSED SESSION");
    //
    // Ok(())
}
