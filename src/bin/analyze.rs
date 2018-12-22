extern crate anytrace;
extern crate env_logger;

use anytrace::analyze::run;
use anytrace::analyze::Steps;

use std::env;

fn main() {
    let methods = [
        ("join", Steps::JoinData),
        ("testing", Steps::Testing),
        ("distance", Steps::DistanceMatrix),
//        ("paths", Steps::Paths),
        ("latency", Steps::Latency),
        ("compare", Steps::Compare),
        ("verify", Steps::Verify),
    ];
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Avaiable methods: {:?}",
            methods.iter().map(|(x, _)| *x).collect::<Vec<&str>>()
        );
        return;
    }

    for (key, p) in methods.iter() {
        if args[1] == *key {
            run(p);
            return;
        }
    }
    panic!("{} not found in methods", args[1]);
}
