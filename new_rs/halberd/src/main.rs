mod ramp; // подключаем вышеописанный модуль
mod dns; // подключаем dns... 
mod auth;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::spawn(async {
        ramp::run_server("127.0.0.1:5000").await.unwrap();});
    //  // Тестируем DNS-резолвер!
    //  let domain = "ramp.ourmcc.world"; // сюда домен с валидным SRV!
    //  match dns::resolve_ramp_srv(domain).await {
    //      Ok(ep) => println!("resolve_ramp_srv: target={} ip={} port={}", ep.target, ep.ip, ep.port),
    //      Err(e) => eprintln!("DNS test failed: {e}"),
    //  }
    //  let some_ip = "95.165.107.109".parse().unwrap(); // IP под свой домен
    //  match dns::verify_ramp_domain(domain, some_ip).await {
    //      Ok(()) => println!("verify_ramp_domain: ok"),
    //      Err(e) => eprintln!("verify test failed: {e}"),
    //  }
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