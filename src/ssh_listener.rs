use anyhow::{anyhow, bail};
use async_trait::async_trait;
use russh::keys::key::{KeyPair, PublicKey, RsaPrivate, SignatureHash};
use russh::server::{Auth, Config, Msg, Session};
use russh::{Channel, ChannelId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Accepts NETCONF connections from a SSH client and handles messages
pub struct NetconfSshListener {
    listener: TcpListener,
}

impl NetconfSshListener {
    pub async fn new(addr: SocketAddr) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    pub async fn next_client(&self) -> anyhow::Result<Channel<Msg>> {
        let (stream, _socket) = self.listener.accept().await?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        russh::server::run_stream(
            Arc::new(Config {
                keys: vec![KeyPair::RSA {
                    key: RsaPrivate::generate(2048).unwrap(),
                    hash: SignatureHash::SHA2_256,
                }],
                ..Config::default()
            }),
            stream,
            SshSession {
                channel: None,
                channel_stream_tx: Some(tx),
            },
        )
        .await?;

        // TODO: this await means that no new connections are established if the client keeps the
        // connection open without initializing the netconf subsystem
        Ok(rx.await?)
    }
}

struct SshSession {
    channel: Option<Channel<Msg>>,
    channel_stream_tx: Option<tokio::sync::oneshot::Sender<Channel<Msg>>>,
}

#[async_trait]
impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    // Any public key is accepted
    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel);
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // This is overly restrictive, but better to keep tight control of everything while experimenting
        if self.channel.is_some() {
            bail!("you are only allowed to create a single channel")
        }

        self.channel = Some(channel);
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "netconf" {
            session.channel_failure(channel_id);
            bail!("requested `{name}` subsystem, but only netconf is allowed");
        }

        let Some(channel) = self.channel.take() else {
            bail!("requested subsystem for a second time");
        };

        session.channel_success(channel_id);
        self.channel_stream_tx
            .take()
            .unwrap()
            .send(channel)
            .map_err(|_| anyhow!("failed to send channel stream to parent"))?;
        Ok(())
    }
}
