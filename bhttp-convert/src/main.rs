#![deny(clippy::pedantic)]

use bhttp::{Message, Mode};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "bhttp",
    about = "Translator between message/http and message/bhttp."
)]
struct Args {
    /// Both read and produce message/bhttp.
    #[structopt(long, short = "b")]
    binary: bool,

    /// Decode message/bhttp and produce message/http instead.
    #[structopt(long, short = "d")]
    decode: bool,

    /// When creating message/bhttp, use the indefinite-length form.
    #[structopt(long, short = "n")]
    indefinite: bool,

    /// Input file.
    #[structopt(long, short = "i")]
    input: Option<PathBuf>,

    /// Output file.
    #[structopt(long, short = "o")]
    output: Option<PathBuf>,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indefinite {
            Mode::IndefiniteLength
        } else {
            Mode::KnownLength
        }
    }
}

fn main() -> Result<(), bhttp::Error> {
    let args = Args::from_args();

    let mut input: Box<dyn io::BufRead> = if let Some(infile) = &args.input {
        Box::new(io::BufReader::new(File::open(infile)?))
    } else {
        Box::new(io::BufReader::new(std::io::stdin()))
    };
    let m = if args.binary || args.decode {
        Message::read_bhttp(&mut input)?
    } else {
        Message::read_http(&mut input)?
    };

    let mut output: Box<dyn io::Write> = if let Some(outfile) = &args.output {
        Box::new(File::open(outfile)?)
    } else {
        Box::new(std::io::stdout())
    };
    if args.binary || !args.decode {
        m.write_bhttp(args.mode(), &mut output)?;
    } else {
        m.write_http(&mut output)?;
    }
    Ok(())
}
