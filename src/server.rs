use crate::{netconf, ALPN_STRING, SERVER_CERT_PATH, SERVER_KEY_PATH};
use anyhow::{anyhow, Context};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use quinn::Incoming;

pub async fn run_server(socket_addr: SocketAddr) -> anyhow::Result<()> {
    let server_cert = fs::read(SERVER_CERT_PATH).context("failed to read server cert")?;
    let server_cert = CertificateDer::from(server_cert);

    let server_key = fs::read(SERVER_KEY_PATH).context("failed to read server key")?;
    let server_key = PrivateKeyDer::try_from(server_key)
        .map_err(|_| anyhow!("server has invalid private key"))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert], server_key)?;
    server_crypto.alpn_protocols = vec![ALPN_STRING.as_bytes().to_vec()];

    // server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));

    let endpoint = quinn::Endpoint::server(server_config, socket_addr)?;
    println!("listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(session(incoming));
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn session(incoming: Incoming) -> anyhow::Result<()> {
    let conn = incoming
        .await
        .context("failed to initialize incoming connection")?;

    // Hello
    let (mut hello_tx, mut hello_rx) = conn.accept_bi().await?;
    hello_tx.write_all(netconf::hello().as_bytes()).await?;
    hello_tx.finish()?;

    let client_hello = hello_rx.read_to_end(usize::MAX).await?;

    // TODO: netconf mandates utf-8; we should return a proper error if we receive invalid utf-8
    println!("{}", String::from_utf8(client_hello)?);

    // TODO: handle incoming messages
    // - <close-session> (see https://support.huawei.com/enterprise/en/doc/EDOC1100271790/9d14e7e4/closing-the-netconf-session)
    // - <kill-session>
    // - <create-subscription>
    // Other possible messages

    conn.closed().await;

    Ok(())
}


