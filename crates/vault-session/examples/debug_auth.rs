//! cargo run -p vault-session --example debug_auth

use vault_session::{LoginResult, Session};

#[tokio::main]
async fn main() {
    let server = "http://127.0.0.1:8080";
    let email = format!("debug{}@example.com", std::process::id());
    let password = "TestPassword123!";

    let mut s = Session::new(server).unwrap();
    match s.register(&email, password, Some("Debug")).await {
        Ok(()) => println!("register OK for {email}"),
        Err(e) => println!("register ERR: {e}"),
    }
    match s.login(&email, password, None).await {
        Ok(LoginResult::Success) => {
            println!("login OK, items={}", s.items().len());
        }
        Ok(LoginResult::TwoFactorRequired { providers }) => {
            println!("login needs 2FA: {providers:?}");
        }
        Err(e) => println!("login ERR: {e:?}"),
    }
}
