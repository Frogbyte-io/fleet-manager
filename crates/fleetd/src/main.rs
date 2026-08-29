const HELP: &str = "Usage: fleetd [--help|--version]";

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("fleetd {}", env!("CARGO_PKG_VERSION")),
        _ => println!("{HELP}"),
    }
}
