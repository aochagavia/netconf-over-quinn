//! Types and functions to read/write to a NETCONF SSH server

use anyhow::{bail, Context};
use std::iter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_message(
    channel: &mut (impl AsyncWrite + Unpin),
    message: ProxiedMessage,
) -> anyhow::Result<()> {
    let mut payload;

    if message.payload.starts_with(b"<hello") {
        // Terminated
        payload = message.payload;
        payload.extend_from_slice(b"]]>]]>");
    } else {
        // Chunked
        payload = format!("\n#{}\n", message.payload.len()).into_bytes();
        payload.extend_from_slice(&message.payload);
        payload.extend_from_slice(b"\n##\n");
    };

    channel.write_all(&payload).await?;

    Ok(())
}

pub struct ProxiedMessage {
    pub payload: Vec<u8>,
}

pub async fn read_message(
    channel: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<Option<ProxiedMessage>> {
    match start_read_message(channel).await? {
        StartReadResult::Terminated => Ok(Some(read_terminated(channel).await?)),
        StartReadResult::Chunked(next_chunk_length) => {
            Ok(Some(read_chunked(channel, next_chunk_length).await?))
        }
        StartReadResult::Eof => Ok(None),
    }
}

enum StartReadResult {
    Terminated,
    Chunked(usize),
    Eof,
}

async fn start_read_message(
    channel: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<StartReadResult> {
    let mut chunk_header = String::new();

    loop {
        // TODO: reading 1 byte at a time is terribly inefficient
        let mut buffer = [1u8; 1];
        let bytes_read = channel.read(&mut buffer[..]).await?;

        if bytes_read == 0 {
            return Ok(StartReadResult::Eof);
        }

        if buffer[0] != b'<' {
            chunk_header.push(buffer[0] as char);
            continue;
        }

        // Just found the leading `<`, now need to parse the header if any was present
        let chunk_header_trimmed = chunk_header.trim();
        return if chunk_header_trimmed.is_empty() {
            Ok(StartReadResult::Terminated)
        } else {
            Ok(StartReadResult::Chunked(
                chunk_header_trimmed[1..].parse().with_context(|| {
                    format!("failed to parse chunk length: `{chunk_header_trimmed}`")
                })?,
            ))
        };
    }
}

async fn read_terminated(channel: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<ProxiedMessage> {
    let mut result = vec![b'<'];
    loop {
        result.push(channel.read_u8().await?);
        if result.ends_with(b"]]>]]>") {
            result.truncate(result.len() - b"]]>]]>".len());
            return Ok(ProxiedMessage { payload: result });
        }
    }
}

async fn read_chunked(
    channel: &mut (impl AsyncRead + Unpin),
    mut chunk_length: usize,
) -> anyhow::Result<ProxiedMessage> {
    // If we know the chunk's length, we can read it in one go
    let mut result = vec![b'<'];

    // Note: we subtract 1 from the chunk length because the `<` has already been parsed
    if chunk_length == 0 {
        bail!("invalid zero chunk length");
    }
    chunk_length -= 1;

    loop {
        let chunk_start = result.len();
        result.extend(iter::repeat_n(0, chunk_length));
        channel
            .read_exact(&mut result[chunk_start..])
            .await
            .context("eof before we finished reading chunk")?;

        // Now read the `\n#` after the chunk
        eat(channel, b'\n').await?;
        eat(channel, b'#').await?;

        // Now either a `#\n` or another chunk
        let mut byte = channel.read_u8().await?;
        if byte == b'#' {
            eat(channel, b'\n').await?;
            return Ok(ProxiedMessage { payload: result });
        }

        // We got another chunk!
        let mut chunk_size_str = String::new();

        loop {
            if byte == b'\n' {
                let chunk_size_str_trimmed = chunk_size_str.trim();
                chunk_length = chunk_size_str_trimmed.parse().with_context(|| {
                    format!("failed to parse chunk length: `{chunk_size_str_trimmed}`")
                })?;
                break;
            }

            chunk_size_str.push(byte as char);
            byte = channel.read_u8().await?;
        }
    }
}

async fn eat(reader: &mut (impl AsyncRead + Unpin), expected: u8) -> anyhow::Result<()> {
    let byte = reader.read_u8().await?;
    if byte != expected {
        bail!(
            "expected `{expected}` (char = `{}`) at the end of chunk, found `{byte}` (char = `{}`)",
            expected as char,
            byte as char
        );
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    pub async fn test_read_terminated() -> anyhow::Result<()> {
        let body = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>"#;

        let terminator_len = "]]>]]>".len();
        let expected_output = &body[..body.len() - terminator_len];

        let output = read_message(&mut body.as_bytes()).await?;

        let output = output.unwrap();
        let output = String::from_utf8(output.payload)?;
        assert_eq!(output.as_str(), expected_output);

        Ok(())
    }

    #[tokio::test]
    pub async fn test_read_chunked_single() -> anyhow::Result<()> {
        let body = r#"#365
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><error-type>rpc</error-type><error-tag>malformed-message</error-tag><error-severity>error</error-severity><error-message xml:lang="en">A message could not be handled because it failed to be parsed correctly.</error-message></rpc-error></rpc-reply>
##
"#;

        let header_len = "#365\n".len();
        let footer_len = "\n##\n".len();
        let expected_output = &body[header_len..body.len() - footer_len];

        let output = read_message(&mut body.as_bytes()).await?;

        let output = output.unwrap();
        let output = String::from_utf8(output.payload)?;
        assert_eq!(output.as_str(), expected_output);

        Ok(())
    }

    #[tokio::test]
    pub async fn test_read_chunked_multi() -> anyhow::Result<()> {
        let body = r#"#59
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
#59
<rpc-error xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
#6
<error
#241
-type>rpc</error-type><error-tag>malformed-message</error-tag><error-severity>error</error-severity><error-message xml:lang="en">A message could not be handled because it failed to be parsed correctly.</error-message></rpc-error></rpc-reply>
##
"#;

        let body_lines: Vec<_> = body.lines().filter(|l| !l.starts_with('#')).collect();
        let expected_output = body_lines.join("");

        let output = read_message(&mut body.as_bytes()).await?;

        let output = output.unwrap();
        let output = String::from_utf8(output.payload)?;
        assert_eq!(output.as_str(), expected_output);

        Ok(())
    }
}
