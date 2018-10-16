extern crate anytrace;
extern crate env_logger;

use anytrace::analyze::run;
use anytrace::analyze::Steps;

fn main() {
    env_logger::init();
    run(Steps::JoinData);
}
