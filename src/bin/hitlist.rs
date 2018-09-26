extern crate anytrace;
extern crate env_logger;
use anytrace::hitlist::run;

fn main() {
    env_logger::init();
    //put your local ip here
    run("172.30.65.57");
}
