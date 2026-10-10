use veil_server::{credential_db, issue, router, App, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var("HOST_DB").unwrap_or("hosts.sqlite".into());
    let db = credential_db(&path)?;
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("issue") {
        let name = args.get(2).ok_or("Usage: veil-server issue <name>")?;
        // Explicit local administration output only; the service never logs tokens.
        println!("{}", issue(&db, name)?);
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("revoke") {
        let name = args.get(2).ok_or("Usage: veil-server revoke <name>")?;
        db.execute("DELETE FROM hosts WHERE name=?1", [name])?;
        return Ok(());
    }
    let app = App::new(db, Config::from_env()?);
    let sweep = app.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            sweep.sweep();
        }
    });
    let address = std::env::var("LISTEN").unwrap_or("127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
