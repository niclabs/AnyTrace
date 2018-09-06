extern crate anytrace;
extern crate env_logger;
extern crate getopts;

use self::getopts::{Matches, Options};
use self::std::env;
use anytrace::anytrace::run;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn get_options() -> Result<Matches, ()> {
    let mut opts = Options::new();
    opts.reqopt("i", "ip", "IP adderss to emit the packets", "192.168.0.1");
    opts.reqopt(
        "p",
        "pps",
        "Rate of packets per second to send, considering every packets is 64 bytes or less.",
        "1000",
    );
    opts.reqopt(
        "l",
        "hitlist",
        "File containing the histlist, separated by newline",
        "data/hitlist.txt",
    );
    opts.optflag("h", "help", "Print this help menu");

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("{}", f.to_string());
            let program = args[0].clone();
            print_usage(&program, opts);
            return Err(());
        },
    };

    return Ok(matches);
}

fn main() {
    env_logger::init();
    if let Ok(opts) = get_options() {
        run(
            &opts.opt_str("hitlist").unwrap(),
            &opts.opt_str("ip").unwrap(),
            opts.opt_get("pps")
                .unwrap_or_else(|_| panic!("--pps must be a u32"))
                .unwrap(),
        );
    }
}
