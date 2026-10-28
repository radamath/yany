use crate::error::YanyError;
use crate::protocol::ControlMsg;
use crate::{MAX_CONTROL_BYTES, MAX_FRAME_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn encode_msg(msg: &ControlMsg) -> Result<Vec<u8>, YanyError> {
    msg.validate()?;
    let body = bincode::serialize(msg)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(YanyError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_body(body: &[u8]) -> Result<ControlMsg, YanyError> {
    if body.len() > MAX_FRAME_BYTES {
        return Err(YanyError::TooLarge(body.len()));
    }
    let msg: ControlMsg = bincode::deserialize(body)?;
    msg.validate()?;
    Ok(msg)
}

pub fn peek_len(header: &[u8; 4]) -> Result<usize, YanyError> {
    let n = u32::from_le_bytes(*header) as usize;
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err(YanyError::TooLarge(n));
    }
    Ok(n)
}

pub fn len_ok(n: usize, max: usize) -> Result<(), YanyError> {
    if n == 0 || n > max {
        return Err(YanyError::TooLarge(n));
    }
    Ok(())
}

pub async fn read_msg_max<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<ControlMsg, YanyError> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await?;
    let n = peek_len(&hdr)?;
    len_ok(n, max)?;
    let mut body = vec![0u8; n];
    reader.read_exact(&mut body).await?;
    decode_body(&body)
}

pub async fn read_control<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<ControlMsg, YanyError> {
    read_msg_max(reader, MAX_CONTROL_BYTES).await
}

pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &ControlMsg,
) -> Result<(), YanyError> {
    let bytes = encode_msg(msg)?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<ControlMsg, YanyError> {
    read_msg_max(reader, MAX_FRAME_BYTES).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::HostId;

    #[test]
    fn roundtrip_register() {
        let msg = ControlMsg::RegisterHost {
            id: HostId::from_raw(123456789).unwrap(),
        };
        let bytes = encode_msg(&msg).unwrap();
        let n = peek_len(bytes[..4].try_into().unwrap()).unwrap();
        let decoded = decode_body(&bytes[4..4 + n]).unwrap();
        match decoded {
            ControlMsg::RegisterHost { id } => assert_eq!(id.raw(), 123456789),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn peek_rejects_zero() {
        assert!(peek_len(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn control_cap_rejects_oversize() {
        assert!(len_ok(MAX_CONTROL_BYTES, MAX_CONTROL_BYTES).is_ok());
        assert!(len_ok(MAX_CONTROL_BYTES + 1, MAX_CONTROL_BYTES).is_err());
    }

    #[test]
    fn encrypted_frame_roundtrip() {
        use crate::crypto::SessionKeys;
        use crate::tile::TileFrame;

        let nonce = [9u8; 32];
        let host = SessionKeys::derive("session-pass", &nonce, true).unwrap();
        let view = SessionKeys::derive("session-pass", &nonce, false).unwrap();
        let inner = TileFrame {
            width: 2,
            height: 2,
            tiles: vec![],
        };
        let ciphertext = host.seal_bincode(1, b"yany-frame", &inner).unwrap();
        let msg = ControlMsg::Frame {
            seq: 1,
            ciphertext,
        };
        let bytes = encode_msg(&msg).unwrap();
        let n = peek_len(bytes[..4].try_into().unwrap()).unwrap();
        match decode_body(&bytes[4..4 + n]).unwrap() {
            ControlMsg::Frame { seq, ciphertext } => {
                let got: TileFrame = view.open_bincode(seq, b"yany-frame", &ciphertext).unwrap();
                assert_eq!(got.width, 2);
            }
            _ => panic!("wrong variant"),
        }
    }
}
