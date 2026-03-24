use clap::Parser;
use std::fs;
use std::path::PathBuf;

use rtrace::attack::load_runtime_rule_catalog;

#[derive(Parser, Debug)]
#[command(
    name = "export-rule-attack-map",
    about = "Export MITRE ATT&CK mapping for active YARA runtime rules"
)]
struct Cli {
    #[arg(long, default_value = "rules")]
    rules_dir: PathBuf,

    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() {
    let args = Cli::parse();
    let catalog = match load_runtime_rule_catalog(&args.rules_dir) {
        Ok(value) => value,
        Err(err) => {
            eprintln!(
                "Failed to build rule ATT&CK catalog from {:?}: {}",
                args.rules_dir, err
            );
            std::process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&catalog) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("Failed to serialize ATT&CK catalog: {}", err);
            std::process::exit(1);
        }
    };

    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(err) = fs::write(&output, json) {
            eprintln!("Failed to write {:?}: {}", output, err);
            std::process::exit(1);
        }
        println!("{}", output.display());
        return;
    }

    println!("{}", json);
}
