//! Test helper, not shipped: ask the broker for approval of a command and exit with the result code.
//! `ASB_URL=... ASB_KEY=... sudo_ask CMD ARGS...` (used by tests/test_sudo_mode.py against a real broker).

use asb_client::{Client, Config};
use asb_proto::SudoRequest;

fn main() {
    let (url, key) = (
        std::env::var("ASB_URL").unwrap(),
        std::env::var("ASB_KEY").unwrap(),
    );
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let req = SudoRequest::new(
        argv,
        Some("/home/ryan".into()),
        Some("ryan".into()),
        "ryan@box".into(),
    );
    let client = Client::new(Config { url, key });
    match client.approve_sudo(&req, |m| eprintln!("{m}")) {
        Ok(()) => println!("approved"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(e.exit_code());
        }
    }
}
