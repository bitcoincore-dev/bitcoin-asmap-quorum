fn main() {
    if let Err(err) = bitcoin_asmap_quorum::run() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
