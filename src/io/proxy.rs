//! Functions to read/write proxied NETCONF messages

use crate::io::netconf::{FramingMethod, ProxiedMessage};
use anyhow::bail;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_message(reader: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<ProxiedMessage> {
    let framing_method = match reader.read_u8().await? {
        0 => FramingMethod::Terminated,
        1 => FramingMethod::Chunked,
        invalid => bail!("invalid framing method: `{invalid}`"),
    };
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload).await?;
    Ok(ProxiedMessage {
        payload,
        framing_method,
    })
}

pub async fn write_message(
    writer: &mut (impl AsyncWrite + Unpin),
    message: ProxiedMessage,
) -> anyhow::Result<()> {
    writer.write_u8(message.framing_method as _).await?;
    writer.write_all(&message.payload).await?;
    Ok(())
}
