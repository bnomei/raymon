#[tokio::main]
async fn main() -> Result<(), raymon::DynError> {
    raymon::run().await
}
