mod crypto;

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use anyhow::{bail, Context, Result};
use crypto::{encrypt, decrypt};
use clap::{Parser, ArgGroup};
use zeroize::Zeroize;
use rpassword::prompt_password;
use indicatif::{ProgressBar, ProgressStyle};

/// Program to encrypt and decrypt files using AES-GCM
#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = None,
    group(
        ArgGroup::new("mode")
            .args(["encrypt", "decrypt"])
            .required(true)
            .multiple(false)
    )
)]
struct Args {
    /// Flag to encrypt the file
    #[arg(short, long)]
    encrypt: bool,

    /// Flag to decrypt the file
    #[arg(short, long)]
    decrypt: bool,

    /// Input file (reads from stdin if not provided)
    file: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut password = prompt_password("Enter password: ")
        .context("failed to read password")?;

    let mut data = if !io::stdin().is_terminal() {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).context("failed to read from stdin")?;
        buf
    } else if let Some(ref file_name) = args.file {
        fs::read(file_name).with_context(|| format!("failed to read file '{}'", file_name))?
    } else {
        bail!("no input provided, provide a file or pipe input");
    };

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?
    );

    let mut result = if args.encrypt {
        spinner.set_message("Encrypting...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));
        let res = encrypt(&password, &data)?;
        spinner.finish_and_clear();
        eprintln!("Encryption complete!");
        res
    } else {
        spinner.set_message("Decrypting...");
        spinner.enable_steady_tick(std::time::Duration::from_millis(100));
        let res = decrypt(&password, &data)?;
        spinner.finish_and_clear();
        eprintln!("Decryption complete!");
        res
    };

    password.zeroize();
    data.zeroize();

    match (&args.file, io::stdout().is_terminal()) {
        (Some(file_name), true) => {
            fs::write(file_name, &result)
                .with_context(|| format!("failed to write to file '{}'", file_name))?;
        }
        _ => {
            io::stdout().write_all(&result).context("failed to write to stdout")?;
        }
    }

    result.zeroize();

    Ok(())
}
