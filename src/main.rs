use anyhow::Context;
use clap::Parser;

use sambot_parser::{process_str, VALID_REPORT_TYPES, VALID_TLP};
use std::io::{stdin, IsTerminal, Read};
use std::path::PathBuf;

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
    #[clap(long = "file", short = 'f')]
    filename: Option<PathBuf>,
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

    let data = match cli.filename {
        Some(val) => {
            let mut tmp = String::new();
            std::fs::File::open(val.clone())
                .with_context(|| format!("Failed to open file: {}", val.display()))
                .unwrap()
                .read_to_string(&mut tmp)
                .with_context(|| format!("Failed to read from file: {}", val.display()))
                .unwrap();
            tmp
        }
        None => {
            let mut stdin = stdin();

            if stdin.is_terminal() {
                eprintln!(
                    "Reading from stdin, paste your text and press Ctrl-D and enter when done"
                );
            }
            // eprintln!("Reading from stdin, paste your text and press Ctrl-D and enter when done");
            let mut tmp = String::new();
            stdin
                .read_to_string(&mut tmp)
                .with_context(|| "Failed to read from stdin")
                .unwrap();
            tmp
        }
    };

    if let Ok(output) = process_str(&data, &tlp, &report_type) {
        println!("{output}");
    };
}
