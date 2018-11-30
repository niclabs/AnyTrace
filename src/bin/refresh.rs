extern crate anytrace;
extern crate env_logger;
use self::std::env;
use anytrace::hitlist::refresh::refresh_file;
fn main() {
    env_logger::init();
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 3 {
    panic!("Argments: <asn_prefixes.json> <ips.txt> <optional>");
    }
   
    let json_path= &arguments[1];
    let ip_path= &arguments[2];
    let blacklist_path= arguments.get(3);
    refresh_file(json_path, ip_path, blacklist_path);
}
