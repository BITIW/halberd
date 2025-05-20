use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Cursor;
use anyhow::{anyhow, Result};
/// Скомпилированные из proto/halberd.proto структуры
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/halberd.rs"));
}
/// Версия протокола, с которой мы работаем
const PROTOCOL_VERSION: &str = "RAMP/0.0.0-RC-1.0";

/// Шаги обработки одной сессии
#[derive(Debug, PartialEq)]
enum SessionStep {
    Hello,
    MailTo,
    Data,
    ReceivingData,
    Done,
}

/// Структура, хранящая состояние приёма одного письма
pub struct RAMPSession {
    step: SessionStep,
    from: Option<String>,
    to:   Option<String>,
    subject: Option<String>,
    body:    Option<String>,
}

impl RAMPSession {
    pub fn new() -> Self {
        RAMPSession {
            step: SessionStep::Hello,
            from: None,
            to:   None,
            subject: None,
            body:    None,
        }
    }

    /// Обработать один incoming-байт-буфер как protobuf-сообщение
    pub async fn handle_message(&mut self, data: &[u8], stream: &mut TcpStream) -> Result<()> {
        let mut cursor = Cursor::new(data);

        match self.step {
            SessionStep::Hello => {
                // Распаковка Hello
                let msg = proto::Hello::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode Hello: {}", e))?;

                // Проверка версии
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
                // Ожидаем просто маркер Data
                let _ = proto::Data::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode Data: {}", e))?;

                self.step = SessionStep::ReceivingData;
                self.send_ok(stream, "DATA accepted, send EMAIL_CONTENT").await?;
            }

            SessionStep::ReceivingData => {
                // Сначала читаем EmailContent
                let content = proto::EmailContent::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode EmailContent: {}", e))?;

                self.subject = Some(content.subject);
                self.body    = Some(content.body);

                // После контента ждём EndData
                // Здесь можно не менять step, но для простоты:
                self.step = SessionStep::Done;
                self.send_ok(stream, "Email content received").await?;
            }

            SessionStep::Done => {
                // Опционально: можно ожидать EndData или просто завершать
                let _ = proto::EndData::decode_length_delimited(&mut cursor)
                    .map_err(|e| anyhow!("Failed to decode EndData: {}", e))?;

                println!(
                    "[SERVER] Full email received: from={:?}, to={:?}, subject={:?}, body={:?}",
                    self.from, self.to, self.subject, self.body
                );
                self.send_ok(stream, "END_DATA, done").await?;
                // можно stream.shutdown().await.ok();
            }
        }

        Ok(())
    }

    /// Отправить клиенту Ok { protocol, message }
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

    /// Отправить клиенту Error { message }
    async fn send_error(&self, stream: &mut TcpStream, msg: String) -> Result<()> {
        let reply = proto::Error { message: msg };
        let mut buf = Vec::new();
        reply.encode_length_delimited(&mut buf)?;
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Запуск TCP-сервера, он будет принимать подключения и обрабатывать их
pub async fn run_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("RAMP listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("Connection from {}", peer);

        // Каждое подключение — в свой таск
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Session error: {}", e);
            }
        });
    }
}

/// Обработка одного клиента: читаем пакеты, прокидываем в session
async fn handle_client(mut stream: TcpStream) -> Result<()> {
    let mut session = RAMPSession::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // Клиент разорвал соединение
            break;
        }
        // Обработать пришедший протобуфер
        session.handle_message(&buf[..n], &mut stream).await?;
    }
    Ok(())
}

/// Тестовый клиент, шлёт по порядку HELLO→MAIL_TO→DATA→EMAIL_CONTENT→END_DATA
pub async fn run_test_client(addr: &str) -> Result<()> {
    use tokio::net::TcpStream;
    use prost::Message;
    use crate::ramp::proto;

    let mut stream = TcpStream::connect(addr).await?;
    println!("[CLIENT] Connected to {}", addr);

    // HELLO
    let hello = proto::Hello {
        server_id: "testclient#localhost".into(),
        protocol: PROTOCOL_VERSION.into(),
    };
    let mut buf = Vec::new();
    hello.encode_length_delimited(&mut buf)?;
    stream.write_all(&buf).await?;
    println!("[CLIENT] Sent HELLO");

    // Читать ответ
    let mut resp = [0u8; 1024];
    let n = stream.read(&mut resp).await?;
    if let Ok(ok) = proto::Ok::decode_length_delimited(&resp[..n]) {
        println!("[CLIENT] Got OK: {}", ok.message);
    }

    // MAIL_TO
    buf.clear();
    let mto = proto::MailTo { address: "alice#localhost".into() };
    mto.encode_length_delimited(&mut buf)?;
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

    // EMAIL_CONTENT
    buf.clear();
    let content = proto::EmailContent {
        subject: "Hello".into(),
        body:    "Welcome to new future of mail!".into(),
        content_type: "text/plain".into(),
        html_body:    "".into(),
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