use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::fs;

mod client;
mod io;
mod server;
mod ssh_client;
mod ssh_listener;

static NETCONF_ALPN_STRING: &str = "NoQ";
static SERVER_CERT_PATH: &str = "certificates/server_cert.der";
static SERVER_KEY_PATH: &str = "certificates/server_key.der";
static CLIENT_SSH_PRIVATE_KEY_PATH: &str = "ssh_keys/client_rsa";

fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or("server".to_string());

    // TODO: make configurable
    let socket_addr = "127.0.0.1:8080".parse().context("invalid socket address")?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match mode.as_str() {
            "server" => server::run_server(socket_addr).await,
            "client" => client::run_client(socket_addr).await,
            "refresh-certificates" => refresh_certificates(),
            _ => unreachable!("invalid mode"),
        }
    })?;

    println!("[{mode}] Done");
    Ok(())
}

fn refresh_certificates() -> anyhow::Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert: CertificateDer = cert.cert.into();
    fs::write(SERVER_CERT_PATH, &cert).context("failed to write certificate")?;
    fs::write(SERVER_KEY_PATH, key.secret_pkcs8_der()).context("failed to write private key")?;
    Ok(())
}
