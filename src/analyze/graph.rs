use analyze::helper::{load_asn, load_data};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::net::Ipv4Addr;

#[derive(PartialEq, Eq, Hash, Debug)]
struct Node {
    ip: Ipv4Addr,
    dt: u32,
}

fn generate_router_graph() -> HashMap<Ipv4Addr, HashSet<Node>> {
    let mut result : HashMap<Ipv4Addr, HashSet<Node>> = HashMap::new();
    {
        let data = load_data();
        for (_, measurement) in data.iter() {
            let data = &measurement.data;
            let l = data.len();
            for i in 0..(l - 1) {
                if let Some(origin) = &data[i + 1] {
                    if let Some(destination) = &data[i] {
                        let node = Node {
                            ip: destination.dst,
                            dt: origin.ms.saturating_sub(destination.ms) as u32,
                        };
                        match result.entry(origin.dst) {
                            Entry::Occupied(mut o) => {
                                o.get_mut().insert(node);
                                },
                            Entry::Vacant(v) => {
                                let map = v.insert(HashSet::new());
                                map.insert(node);
                            }
                        };
                    }
                }
            }
        }
    }

    return result;
}

/// Generate an AS graph with the given date
pub fn generate_graph() {
    let graph = generate_router_graph();
    let asn = load_asn();

    let mut result : HashMap<u32, HashSet<u32>> = HashMap::new();
    for (src, destinations) in graph.iter() {
        println!("{} {:?}", src, destinations);
        if let Some((_, _, src)) = asn.longest_match(*src) {
            for dst in destinations.iter() {
                if let Some((_, _, dst)) = asn.longest_match(dst.ip) {
                    for src in src.iter() {
                        for dst in dst.iter() {
                            if src == dst {
                                continue;
                            }
                            match result.entry(*src) {
                                Entry::Occupied(mut o) => {
                                    o.get_mut().insert(*dst);
                                },
                                Entry::Vacant(v) => {
                                    let v = v.insert(HashSet::<u32>::new());
                                    v.insert(*dst);
                                }
                            };/*
                            match result.entry(*dst) {
                                Entry::Occupied(mut o) => {
                                    o.get_mut().insert(*src);
                                },
                                Entry::Vacant(v) => {
                                    let v = v.insert(HashSet::<u32>::new());
                                    v.insert(*src);
                                }
                            };*/
                        }
                    }
                    if src == dst {
                        continue;
                    }
                    println!("{:?} -> {:?}", src, dst);
                }
            }
        }
    }
    println!("{:?}", result);
}
