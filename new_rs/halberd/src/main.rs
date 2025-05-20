mod ramp; // подключаем вышеописанный модуль
mod dns; // подключаем dns... 
mod auth;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::spawn(async {
        ramp::run_server("127.0.0.1:5000").await.unwrap();});
    let token = auth::generate_token(42, 1);
    println!("TOKEN: {token}");

    match auth::verify_token(&token){
        Some(uid) => println!("Valid token for user_id={}", uid),
        None => println!("Invalid or expired token"),
    }     
    // ... остальной main, например запуск сервера/клиента
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    ramp::run_test_client("127.0.0.1:5000").await?;
    Ok(())
}