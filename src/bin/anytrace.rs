extern crate anytrace;
extern crate getopts;

use anytrace::anytrace::run;
use self::getopts::{Options, Matches};
use self::std::env;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn get_options() -> Result<Matches, ()> {
    let mut opts = Options::new();
    opts.optopt("", "ip", "ip adderss to emit the packets", "ip");
    opts.optflag("h", "help", "print this help menu");

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") || !matches.opt_present("ip") {
        let program = args[0].clone();
        print_usage(&program, opts);
        return Err(());
    }
    return Ok(matches);
}

fn main() {
    if let Ok(opts) = get_options() {
        run(&opts.opt_str("ip").unwrap());
    }
}
