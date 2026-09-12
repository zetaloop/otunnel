use otunnel::{CancellationToken, Result, Tunnel, config::Config};

#[tokio::main]
async fn main() -> Result<()> {
    let configuration = std::env::args_os()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("usage: embedded <tunnel.yaml>"))?;
    let tunnel = Tunnel::new(Config::read(configuration)?)?;
    let stop = CancellationToken::new();
    let running = tunnel.run(stop.clone());
    tokio::pin!(running);
    tokio::select! {
        result = &mut running => result,
        signal = tokio::signal::ctrl_c() => {
            stop.cancel();
            let result = running.await;
            signal?;
            result
        }
    }
}
