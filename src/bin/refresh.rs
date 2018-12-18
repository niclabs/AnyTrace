extern crate anytrace;
extern crate env_logger;
use self::std::env;
use anytrace::hitlist::refresh::refresh_file;
fn main() {
    env_logger::init();
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
    panic!("Argments: <asn_prefixes.json> <ips.txt> <local_ip> <optional>");
    }
   
    let json_path= &arguments[1];
    let ip_path= &arguments[2];
    let local_up= &arguments[3]
    let blacklist_path= arguments.get(4);
    refresh_file(json_path, ip_path, ip_path, blacklist_path);
}
