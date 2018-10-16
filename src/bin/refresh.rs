extern crate anytrace;
extern crate env_logger;
use anytrace::hitlist::refresh::refresh_file;
fn main() {
    env_logger::init();
    //put your local ip here
    refresh_file();
}
