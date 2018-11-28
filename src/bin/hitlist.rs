extern crate anytrace;
extern crate env_logger;
use self::std::env;
use anytrace::hitlist::run;

fn main() {
    env_logger::init();
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 3 {
    panic!("Argments: <asn_prefixes.json> <optional>");
    }
   
    let json_path= &arguments[1];
    let blacklist_path= arguments.get(2);
    run(json_path, blacklist_path)
    

}
