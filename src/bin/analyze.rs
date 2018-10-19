extern crate anytrace;
extern crate env_logger;

use anytrace::analyze::Steps;
use anytrace::analyze::run;

use std::env;

fn main() {
    let methods = [
        ("join", Steps::JoinData),
        ("testing", Steps::Testing),
    ];
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Avaiable methods: {:?}", methods.iter().map(|(x,_)| *x).collect::<Vec<&str>>());
        return;
    }

    for (key, p) in methods.iter() {
        if args[1] == *key {
            run(p);
            break;
        }
    }
}
