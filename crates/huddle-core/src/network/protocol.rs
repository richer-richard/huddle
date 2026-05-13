use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;

use crate::session::PrekeyBundle;

pub const HUDDLE_PROTOCOL: StreamProtocol = StreamProtocol::new("/huddle/1.0.0");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuddleRequest {
    Handshake {
        sender_fingerprint: String,
        prekey_bundle: PrekeyBundle,
    },
    EncryptedMessage {
        ciphertext: Vec<u8>,
        msg_type: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuddleResponse {
    Handshake {
        sender_fingerprint: String,
        prekey_bundle: PrekeyBundle,
    },
    Ack {
        message_id: Option<i64>,
    },
}

#[derive(Debug, Clone)]
pub struct HuddleCodec;

const MAX_MSG_SIZE: u32 = 1_048_576;

#[async_trait]
impl request_response::Codec for HuddleCodec {
    type Protocol = StreamProtocol;
    type Request = HuddleRequest;
    type Response = HuddleResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp_json(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_lp_json(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp_json(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_lp_json(io, &res).await
    }
}

async fn read_lp_json<T, D>(io: &mut T) -> io::Result<D>
where
    T: AsyncRead + Unpin + Send,
    D: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn write_lp_json<T, S>(io: &mut T, value: &S) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    S: serde::Serialize,
{
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = bytes.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialization_round_trip() {
        let req = HuddleRequest::Handshake {
            sender_fingerprint: "a3b1-c2d4-e5f6-7890-1234-abcd".into(),
            prekey_bundle: PrekeyBundle {
                identity_key: "base64key".into(),
                one_time_key: "base64otk".into(),
            },
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: HuddleRequest = serde_json::from_slice(&json).unwrap();
        match decoded {
            HuddleRequest::Handshake {
                sender_fingerprint,
                prekey_bundle,
            } => {
                assert_eq!(sender_fingerprint, "a3b1-c2d4-e5f6-7890-1234-abcd");
                assert_eq!(prekey_bundle.identity_key, "base64key");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_serialization_round_trip() {
        let resp = HuddleResponse::Ack {
            message_id: Some(42),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: HuddleResponse = serde_json::from_slice(&json).unwrap();
        match decoded {
            HuddleResponse::Ack { message_id } => assert_eq!(message_id, Some(42)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn encrypted_message_round_trip() {
        let req = HuddleRequest::EncryptedMessage {
            ciphertext: vec![1, 2, 3, 4, 5],
            msg_type: 1,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: HuddleRequest = serde_json::from_slice(&json).unwrap();
        match decoded {
            HuddleRequest::EncryptedMessage {
                ciphertext,
                msg_type,
            } => {
                assert_eq!(ciphertext, vec![1, 2, 3, 4, 5]);
                assert_eq!(msg_type, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn length_prefixed_codec_round_trip() {
        let req = HuddleRequest::Handshake {
            sender_fingerprint: "test-fp".into(),
            prekey_bundle: PrekeyBundle {
                identity_key: "ik".into(),
                one_time_key: "otk".into(),
            },
        };

        let mut buf = Vec::new();
        write_lp_json(&mut buf, &req).await.unwrap();

        let mut cursor = futures::io::Cursor::new(buf);
        let decoded: HuddleRequest = read_lp_json(&mut cursor).await.unwrap();
        match decoded {
            HuddleRequest::Handshake {
                sender_fingerprint, ..
            } => {
                assert_eq!(sender_fingerprint, "test-fp");
            }
            _ => panic!("wrong variant"),
        }
    }
}
