extern crate anytrace;
extern crate env_logger;
extern crate getopts;

use anytrace::anytrace::run;
use anytrace::anytrace::PingMethod;
use getopts::{Matches, Options};
use std::env;
use std::ops::BitXor;
use std::time::Duration;

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
    opts.optopt(
        "l",
        "hitlist",
        "File containing the histlist, separated by newline. Can't be used with --stdin",
        "data/hitlist.txt",
    );
    opts.optflag(
        "i",
        "stdin",
        "Use the stdin to receive the hitlist, separated by newline. Can't be used with --hitlist",
    );
    opts.reqopt(
        "m",
        "method",
        "Method used to send the ping requests. Options: ICMP, UDP",
        "ICMP",
    );
    opts.optflag(
        "",
        "master",
        "Set the node as a master, sending the requests on the hitlist",
    );
    opts.optopt(
        "d",
        "duration",
        "Set the duration in seconds of the measurements. Only works on non-master process.",
        "600",
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
        }
    };

    if matches.opt_present("help") {
        let program = args[0].clone();
        print_usage(&program, opts);
        return Err(());
    }

    return Ok(matches);
}

fn main() {
    env_logger::init();
    if let Ok(opts) = get_options() {
        if opts.opt_present("master")
            && (opts
                .opt_present("hitlist")
                .bitxor(opts.opt_present("stdin"))
                == false)
        {
            panic!("When using master, you must set either --hitlist or --stdin, and not both.");
        }

        run(
            opts.opt_str("hitlist"),
            &opts.opt_str("ip").unwrap(),
            opts.opt_get("pps")
                .unwrap_or_else(|_| panic!("--pps must be a u32"))
                .unwrap(),
            match opts.opt_str("method").unwrap().to_uppercase().as_ref() {
                "ICMP" => PingMethod::ICMP,
                "UDP" => PingMethod::UDP,
                _ => panic!("--method must be ICMP or UDP"),
            },
            opts.opt_present("master"),
            Duration::from_secs(
                opts.opt_str("duration")
                    .unwrap_or(format!("{}", u32::max_value()))
                    .parse::<u64>()
                    .unwrap(),
            ),
        );
    }
}
