use anyhow::Context;
use clap::Parser;
use sambot_parser::process_str;
use std::io::Read;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    tlp: Option<String>,
    #[clap(long = "type", short = 't')]
    report_type: Option<String>,
}

fn main() {
    // take input from stdin
    let cli = Cli::parse();
    let tlp = cli.tlp.unwrap_or("green".to_string());
    let report_type = cli.report_type.unwrap_or("phish".to_string());

    let mut data = String::new();

    std::io::stdin()
        .read_to_string(&mut data)
        .with_context(|| "Failed to read from stdin")
        .unwrap();

    process_str(&data, &tlp, &report_type);
}
