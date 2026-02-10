#[tokio::main]
async fn main() -> std::process::ExitCode {
    match raymon::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
