fn main() {
    let env = env_logger::Env::default().default_filter_or("trace");
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_millis()
        .try_init();
    if let Err(err) = bitcoin_asmap_quorum::run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
