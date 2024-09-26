use crate::{netconf, ALPN_STRING, SERVER_CERT_PATH};
use anyhow::Context;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn run_client(socket_addr: SocketAddr) -> anyhow::Result<()> {
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;

    let mut roots = rustls::RootCertStore::empty();
    let server_cert = fs::read(SERVER_CERT_PATH).context("failed to read server cert path")?;
    roots.add(CertificateDer::from(server_cert))?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN_STRING.as_bytes().to_vec()];

    // client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client.set_default_client_config(client_config);

    let connecting = client.connect(socket_addr, "localhost")?;
    let connection = connecting.await?;

    // Note: each command uses its own stream

    // Hello
    let (mut hello_tx, mut hello_rx) = connection.open_bi().await?;
    hello_tx.write_all(netconf::hello().as_bytes()).await?;
    hello_tx.finish()?;

    let server_hello = hello_rx.read_to_end(usize::MAX).await?;
    println!("{}", String::from_utf8_lossy(&server_hello));

    // TODO: enter some loop to make requests (let the user manually write xml?)

    connection.close(0u32.into(), b"done");
    client.wait_idle().await;

    Ok(())
}
