extern crate treebitmap;

use analyze::helper::{asn_geoloc, load_asn, load_data};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::env;
use self::treebitmap::IpLookupTable;

use std::u32;

fn ip_normalize(address: Ipv4Addr) -> Ipv4Addr {
    return Ipv4Addr::from(u32::from(address) & 0xFFFFFF00);
}

fn generate_iplink(tracepath: &String) -> HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> {
    let mut data = load_data(tracepath);
    let mut merge: HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> = HashMap::new();

    debug!("Merging data on generate_iplink");

    for (_, measurement) in data.iter() {
        let data = &measurement.data;
        let l = data.len();
        for i in 1..l {
            if let Some(destination) = &data[i] {
                let mut j = (i as i32) - 1;
                while j >= 0 {
                    if let Some(origin) = &data[j as usize] {
                        if origin.dst == destination.dst {
                            break;
                        }
                        merge.entry(ip_normalize(origin.dst)).or_insert(HashMap::new()).entry(j as u32).or_insert(Vec::new()).push((ip_normalize(destination.dst), i as u32));
                        break;
                    }
                    j -= 1;
                }
            }
        }
    }
    info!("Elements: {}", merge.len());
    //println!("{:?}", merge.iter().max_by_key(|(_, v)| v.len()));
    info!("{:?}", merge.get(&Ipv4Addr::new(200, 7, 6, 0)));
    info!("{:?}", merge.get(&Ipv4Addr::new(176,10,100,0)));
    return merge;
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct Node {
    ip: (Ipv4Addr, u32),
    dist: u32,
}

impl Ord for Node {
    fn cmp(&self, other: &Node) -> Ordering {
        other
            .dist
            .cmp(&self.dist)
            .then_with(|| self.ip.cmp(&other.ip))
    }
}
impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Node) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn analyze_paths(graph: &HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>>, asn: IpLookupTable<Ipv4Addr, Vec<u32>>, start: (Ipv4Addr, u32)) {
    debug!("analyze paths");
    // Join all paths as a graph, each one separated?
    let mut distance: HashMap<(Ipv4Addr, u32), u32> = HashMap::new();
    let mut paths = HashMap::<(Ipv4Addr, u32), Vec<(Ipv4Addr, u32)>>::with_capacity(graph.len());
    let mut heap = BinaryHeap::new();
    
    heap.push(Node {
        ip: start,
        dist: 0,
    });
    paths.insert(start, Vec::new());

    while let Some(Node { ip, dist }) = heap.pop() {
        if dist > *distance.get(&(ip.0, ip.1)).unwrap_or(&u32::MAX) {
            continue;
        }

        let next = 1 + dist;
        for nodes in graph.get(&ip.0) {
            for path in nodes.get(&ip.1).unwrap_or(&Vec::new()).iter() {
                if next < *distance.get(&path).unwrap_or(&u32::MAX) {
                    distance.insert(*path, next);
                    heap.push(Node {
                        ip: *path,
                        dist: next,
                    });

                    let mut p = paths.get(&ip).unwrap().clone();
                    p.push(*path);
                    paths.insert(*path, p);
                }
            }
        }
    }

    info!("max distance: {:?}", distance.iter().max_by_key(|(_, d)| *d));
    info!("Distance from 185.32.124.199: {:?}", distance.get(&("185.32.124.0".parse().unwrap(), 17)));
    info!("path for 185.32.124.199: {:?}", paths.get(&("185.32.124.0".parse().unwrap(), 17)));
    use std::{thread, time};

let ten_millis = time::Duration::from_millis(100000000);
let now = time::Instant::now();

thread::sleep(ten_millis);

}

pub fn graph_info() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: <traces.csv> <asn.csv>");
    }
    let tracepath = arguments[2].clone();
    let asnpath = arguments[3].clone();

    let graph = generate_iplink(&tracepath);
    let asn = load_asn(&asnpath);
    analyze_paths(&graph, asn, (Ipv4Addr::new(200, 7, 6, 0), 1));
}
