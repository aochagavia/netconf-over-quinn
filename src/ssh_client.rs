use crate::{CLIENT_SSH_PRIVATE_KEY_PATH};
use anyhow::{bail, Context};
use std::sync::Arc;
use async_trait::async_trait;
use russh::Channel;
use russh::client::Msg;
use tokio::net::ToSocketAddrs;

pub async fn with_default_ssh_keys(
    addr: impl ToSocketAddrs,
) -> anyhow::Result<Channel<Msg>> {
    let key_pair = russh_keys::load_secret_key(CLIENT_SSH_PRIVATE_KEY_PATH, None)?;
    let config = russh::client::Config {
        ..Default::default()
    };

    let mut session = russh::client::connect(Arc::new(config), addr, SshSession).await?;
    let authenticated = session.authenticate_publickey("root", Arc::new(key_pair)).await?;
    if !authenticated {
        bail!("authentication failed");
    }

    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "netconf").await.context("failed to start NETCONF subsystem")?;

    Ok(channel)
}

struct SshSession;

#[async_trait]
impl russh::client::Handler for SshSession {
    type Error = anyhow::Error;

    // Connect to the server regardless of its keys
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
