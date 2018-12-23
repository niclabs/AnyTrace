extern crate treebitmap;

use self::treebitmap::IpLookupTable;
use analyze::helper::{ip_normalize, load_asn};

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

pub fn compare_joins() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: ./result/x.udp.join <asn.csv>");
    }
    let trace1 = arguments[2].clone();
    let asnpath = arguments[3].clone();
    // Load all icmp, load all udp, look for collisions between tcp and udp.
    compare(
        &trace1,
        &trace1.split(".").collect::<Vec<&str>>()[1].to_string(),
    );

    let asn = load_asn(&asnpath);
    show_anycast_detected(&asn);
}

fn show_anycast_detected(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let traces = list_files();

    let mut founded = HashSet::new(); // Mark network as founded in trace
    let mut anycast = HashSet::new(); // Mark network as anytrace
    for (_, path) in traces {
        let data = load_area_simplified(&path);
        for ip in data {
            if founded.contains(&ip) {
                anycast.insert(ip);
            } else {
                founded.insert(ip);
            }
        }
    }
    info!("Found {} anycast networks", anycast.len());

    // transform from networks to ASN
    let mut asnlist = HashSet::new();
    for ip in anycast {
        if let Some((_, _, asn)) = asn.longest_match(ip) {
            for asn in asn {
                asnlist.insert(asn);
            }
        }
    }
    info!("Found {} anycast AS {:?}", asnlist.len(), asnlist);
}

fn compare(udp: &String, origin: &String) {
    let mut icmp = HashMap::new();
    for (id, path) in list_files() {
        icmp.insert(id, load_area_simplified(&path));
    }

    let udp = load_area_simplified(udp);

    // Compare
    info!("compare {} vs {}", udp.len(), icmp.len());
    let mut count = 0;
    for ip in udp.iter() {
        for (src, list) in icmp.iter() {
            if list.contains(ip) {
                if src != origin && icmp.get(origin).unwrap().contains(ip) {
                    count += 1;
                }
            }
        }
    }

    info!("Found {} networks in another server", count);
}

fn list_files() -> HashMap<String, String> {
    let mut result = HashMap::new();
    let paths = fs::read_dir("./result/").unwrap();
    for path in paths {
        let name = path.unwrap().path().display().to_string();
        if name.contains(".icmp.join") {
            result.insert(name.split(".").collect::<Vec<&str>>()[1].to_string(), name);
        }
    }
    return result;
}

/// Load the area of services of the given csv
fn load_area_simplified(path: &String) -> HashSet<Ipv4Addr> {
    let f = File::open(path).unwrap();
    let mut result = HashSet::new();
    let void = Ipv4Addr::new(0, 0, 0, 0);

    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        let data = line.split(",").collect::<Vec<&str>>();
        let dst: Ipv4Addr = data[1].parse().unwrap();
        if dst.is_private() || dst == void {
            continue;
        }
        result.insert(ip_normalize(dst));
    }

    return result;
}
