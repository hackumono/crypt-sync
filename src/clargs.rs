use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "csync")]
pub struct Opts {
    // /// any and all debug information
    // #[structopt(short = "d", long = "debug")]
    // pub debug: bool,
    #[structopt(parse(from_os_str))]
    pub file: PathBuf,

    #[structopt(short = "t", long = "target", parse(from_os_str))]
    pub target_dir: PathBuf,
    // in place editing option
}
