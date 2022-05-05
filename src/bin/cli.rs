use clap::{command, Command};

fn main() {
    let matches = command!()
        .subcommand_required(true)
        .subcommand(
            Command::new("generate-shared-key")
                .about("generates a secret key suitable for use in shared key authentication"),
        )
        .get_matches();

    if let Some(_matches) = matches.subcommand_matches("generate-shared-key") {
        match ditto_authtool::shared_key::generate_key() {
            Ok(key) => println!("{}", key),
            Err(e) => println!("Error generating key: {}", e),
        }
    }
}
