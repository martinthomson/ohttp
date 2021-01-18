//
// License CC0: https://creativecommons.org/publicdomain/zero/1.0/
//

#![deny(clippy::pedantic)]

use bhttp::{Message, Mode};
use std::io;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "bhttp",
    about = "Translator between message/http and message/bhttp."
)]
struct Args {
    #[structopt(long, short = "d")]
    decode: bool,
    #[structopt(long, short = "i")]
    indefinite: bool,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indefinite {
            Mode::Indefinite
        } else {
            Mode::Known
        }
    }
}

fn main() -> Result<(), bhttp::Error> {
    let args = Args::from_args();

    if args.decode {
        let m = Message::read_bhttp(&mut io::BufReader::new(std::io::stdin()))?;
        m.write_http(&mut std::io::stdout())?;
    } else {
        let m = Message::read_http(&mut io::BufReader::new(std::io::stdin()))?;
        m.write_bhttp(args.mode(), &mut std::io::stdout())?;
    }
    Ok(())
}
