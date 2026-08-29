const HELP: &str = "Usage: fleet-controller [--help|--version]";

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("fleet-controller {}", env!("CARGO_PKG_VERSION")),
        _ => println!("{HELP}"),
    }
}
