// src/ramp.rs

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use prost::Message;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use crate::crypto::{decrypt_chacha, encrypt_chacha, sign_blake3, verify_blake3};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/halberd.rs"));
}

const PROTOCOL_VERSION: &str = "RAMP/0.0.0-RC-1.0";

#[derive(Debug, PartialEq)]
enum SessionStep {
    Hello,
    MailTo,
    Data,
    ReceivingData,
    Done,
}

pub struct RAMPSession {
    step:    SessionStep,
    from:    Option<String>,
    to:      Option<String>,
    subject: Option<String>,
    body:    Option<String>,
}

impl RAMPSession {
    pub fn new() -> Self {
        RAMPSession {
            step:    SessionStep::Hello,
            from:    None,
            to:      None,
            subject: None,
            body:    None,
        }
    }

    pub async fn handle_message(&mut self, data: &[u8], stream: &mut TcpStream) -> Result<()> {
        let mut cursor = Cursor::new(data);

        match self.step {
            SessionStep::Hello => {
                let msg = proto::Hello::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode Hello: {}", e))?;
                if msg.protocol != PROTOCOL_VERSION {
                    self.send_error(stream, format!("Unsupported protocol: {}", msg.protocol)).await?;
                    return Err(anyhow!("Protocol mismatch"));
                }
                self.from = Some(msg.server_id);
                self.step = SessionStep::MailTo;
                self.send_ok(stream, "HELLO accepted").await?;
            }

            SessionStep::MailTo => {
                let msg = proto::MailTo::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode MailTo: {}", e))?;
                self.to = Some(msg.address);
                self.step = SessionStep::Data;
                self.send_ok(stream, "MAIL_TO accepted").await?;
            }

            SessionStep::Data => {
                let _ = proto::Data::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode Data: {}", e))?;
                self.step = SessionStep::ReceivingData;
                self.send_ok(stream, "DATA accepted, send EMAIL_CONTENT").await?;
            }

            SessionStep::ReceivingData => {
                let content = proto::EmailContent::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode EmailContent: {}", e))?;

                // SUBJECT
                let subj_bytes = STANDARD
                    .decode(&content.subject)
                    .map_err(|e| anyhow!("Base64 decode subject failed: {}", e))?;
                let (subj_nonce_bytes, subj_ct) = subj_bytes.split_at(12);
                let subj_nonce: [u8; 12] = subj_nonce_bytes
                    .try_into()
                    .map_err(|_| anyhow!("Invalid subject nonce length"))?;
                let subj_plain = decrypt_chacha(subj_ct, &subj_nonce)
                    .map_err(|e| anyhow!("Subject decryption failed: {}", e))?;
                let subject = String::from_utf8(subj_plain)
                    .map_err(|e| anyhow!("Subject is not valid UTF-8: {}", e))?;

                // BODY
                let body_bytes = STANDARD
                    .decode(&content.body)
                    .map_err(|e| anyhow!("Base64 decode body failed: {}", e))?;
                let (body_nonce_bytes, body_ct) = body_bytes.split_at(12);
                let body_nonce: [u8; 12] = body_nonce_bytes
                    .try_into()
                    .map_err(|_| anyhow!("Invalid body nonce length"))?;
                let body_plain = decrypt_chacha(body_ct, &body_nonce)
                    .map_err(|e| anyhow!("Body decryption failed: {}", e))?;
                let body = String::from_utf8(body_plain)
                    .map_err(|e| anyhow!("Body is not valid UTF-8: {}", e))?;

                // SIGNATURE
                if !verify_blake3(body_ct, &content.signature) {
                    self.send_error(stream, "Invalid signature".into()).await?;
                    return Err(anyhow!("Signature mismatch"));
                }

                self.subject = Some(subject);
                self.body    = Some(body);
                self.step    = SessionStep::Done;
                self.send_ok(stream, "Email content received").await?;
            }

            SessionStep::Done => {
                let _ = proto::EndData::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode EndData: {}", e))?;
                println!(
                    "[SERVER] Full email received: from={:?}, to={:?}, subject={:?}, body={:?}",
                    self.from, self.to, self.subject, self.body
                );
                self.send_ok(stream, "END_DATA, done").await?;
            }
        }

        Ok(())
    }

    async fn send_ok(&self, stream: &mut TcpStream, msg: &str) -> Result<()> {
        let reply = proto::Ok {
            protocol: PROTOCOL_VERSION.into(),
            message:  msg.into(),
        };
        let mut buf = Vec::new();
        reply.encode_length_delimited(&mut buf)?;
        stream.write_all(&buf).await?;
        Ok(())
    }

    async fn send_error(&self, stream: &mut TcpStream, msg: String) -> Result<()> {
        let reply = proto::Error { message: msg };
        let mut buf = Vec::new();
        reply.encode_length_delimited(&mut buf)?;
        stream.write_all(&buf).await?;
        Ok(())
    }
}

pub async fn run_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("RAMP listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("Connection from {}", peer);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Session error: {}", e);
            }
        });
    }
}

async fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut session = RAMPSession::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }
        session.handle_message(&buf[..n], &mut stream).await?;
    }
    Ok(())
}

pub async fn run_test_client(addr: &str) -> Result<()> {
    use prost::Message;
    use crate::ramp::proto;

    let mut stream = TcpStream::connect(addr).await?;
    println!("[CLIENT] Connected to {}", addr);

    // HELLO
    let hello = proto::Hello {
        server_id: "testclient#localhost".into(),
        protocol:  PROTOCOL_VERSION.into(),
    };
    let mut buf = Vec::new();
    hello.encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent HELLO");
    let mut resp = [0u8; 1024];
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    // MAIL_TO
    buf.clear();
    proto::MailTo { address: "alice#localhost".into() }
        .encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent MAIL_TO");
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    // DATA
    buf.clear();
    proto::Data {}.encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent DATA");
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    // EMAIL_CONTENT: encrypt + sign
    let subj_plain = b"Hello World!";
    let body_plain = b"Welcome to new future of mail!";

    let (subj_ct, subj_nonce) = encrypt_chacha(subj_plain)?;
    let mut subj_comb = subj_nonce.to_vec();
    subj_comb.extend(subj_ct);
    let subj_b64 = STANDARD.encode(&subj_comb);

    let (body_ct, body_nonce) = encrypt_chacha(body_plain)?;
    let mut body_comb = body_nonce.to_vec();
    body_comb.extend(body_ct.clone());
    let body_b64 = STANDARD.encode(&body_comb);

    let signature = sign_blake3(&body_ct);
    println!("[SERVER] Signature is {:?}", &signature);

    buf.clear();
    let content = proto::EmailContent {
        subject:      subj_b64,
        body:         body_b64,
        content_type: "text/plain".into(),
        html_body:    "".into(),
        signature,
    };
    content.encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent EMAIL_CONTENT");
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    // END_DATA
    buf.clear();
    proto::EndData {}.encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent END_DATA");
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    Ok(())
}
