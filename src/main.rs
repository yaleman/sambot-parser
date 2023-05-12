use anyhow::Context;
use clap::Parser;
use lazy_static::lazy_static;
use sambot_parser::process_str;
use std::io::Read;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Pipe some text through this and it'll output fields like it should for sambot"
)]
struct Cli {
    #[clap(long = "tlp", short = 't')]
    tlp: Option<String>,
    #[clap(long = "report", short = 'r')]
    report_type: Option<String>,
}

lazy_static! {
    static ref VALID_REPORT_TYPES: Vec<&'static str> =
        vec!["phish", "malware", "bec/scam", "dump", "apt",];
    static ref VALID_TLP: Vec<&'static str> = vec!["white", "green", "amber", "red",];
}

fn main() {
    // take input from stdin
    let cli = Cli::parse();
    let tlp = cli.tlp.unwrap_or("green".to_string()).to_lowercase();
    let report_type = cli
        .report_type
        .unwrap_or("phish".to_string())
        .to_lowercase();

    if !VALID_TLP.contains(&tlp.as_str()) {
        println!(
            "TLP value needs to be one of: {}, not '{}'",
            VALID_TLP.join(","),
            tlp
        );
        std::process::exit(1);
    }

    if !VALID_REPORT_TYPES.contains(&report_type.as_str()) {
        println!(
            "Report type needs to be one of: {}, not '{}'",
            VALID_REPORT_TYPES.join(","),
            report_type
        );
        std::process::exit(1);
    }

    let mut data = String::new();

    std::io::stdin()
        .read_to_string(&mut data)
        .with_context(|| "Failed to read from stdin")
        .unwrap();

    process_str(&data, &tlp, &report_type);
}
