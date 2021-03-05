use std::path::PathBuf;

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "cli", about = "MPC over Signal")]
pub struct App {
    #[structopt(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, StructOpt)]
pub enum Cmd {
    /// Logins to Signal by linking to application on your phone
    Login(Login),
    Whoami(Whoami),
}

#[derive(Debug, StructOpt)]
pub struct Login {
    /// A successful login will produce keys file containing sensitive information that should be
    /// kept in secret! File will include: identity secret key, encryption/decryption keys, etc.
    #[structopt(default_value = "secret-keys.json")]
    pub keys: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct Whoami {
    /// Path to a file containing private access keys
    #[structopt(default_value = "secret-keys.json")]
    pub keys: PathBuf,
}
