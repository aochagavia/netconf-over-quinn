//! Functions to read/write proxied NETCONF messages

use crate::io::netconf_ssh::ProxiedMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_message(reader: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<ProxiedMessage> {
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload).await?;
    Ok(ProxiedMessage { payload })
}

pub async fn write_message(
    writer: &mut (impl AsyncWrite + Unpin),
    message: ProxiedMessage,
) -> anyhow::Result<()> {
    writer.write_all(&message.payload).await?;
    Ok(())
}
