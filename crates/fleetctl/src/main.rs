const HELP: &str = "Usage: fleetctl [--help|--version]";

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("fleetctl {}", env!("CARGO_PKG_VERSION")),
        _ => println!("{HELP}"),
    }
}
