use analyze::helper::{load_asn, load_data};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::u32;

#[derive(Debug, Clone)]
struct AsPath {
    asn: u32,
    dist: u32,
}

impl PartialEq for AsPath {
    fn eq(&self, other: &AsPath) -> bool {
        self.asn == other.asn
    }
}
impl Eq for AsPath {}

impl Hash for AsPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.asn.hash(state);
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
struct TraceNode {
    ip: Ipv4Addr,
    dt: u32,
}

fn generate_router_graph() -> HashMap<Ipv4Addr, Vec<TraceNode>> {
    let mut result : HashMap<Ipv4Addr, Vec<TraceNode>> = HashMap::new();
    let data = load_data();
    debug!("Generating router graph");
    for (_, measurement) in data.iter() {
        let data = &measurement.data;
        let l = data.len();
        for i in 0..(l - 1) {
            if let Some(origin) = &data[i] {
                if let Some(destination) = &data[i + 1] {
                    if origin.ms.saturating_sub(destination.ms) as u32 == 0 {
                        if destination.ms.saturating_sub(origin.ms) as u32 != 0 {
                            //println!("Inconsistent, {} ({}) vs {} ({})", origin.ms, origin.hops, destination.ms, destination.hops);
                        }
                    }
                    let node = TraceNode {
                        ip: destination.dst,
                        dt: origin.ms.saturating_sub(destination.ms) as u32,
                    };
                    match result.entry(origin.dst) {
                        Entry::Occupied(mut o) => {
                            o.get_mut().push(node);
                            },
                        Entry::Vacant(v) => {
                            let map = v.insert(Vec::new());
                            map.push(node);
                        }
                    };
                }
            }
        }
    }

    return result;
}

fn generate_asmap() -> HashMap<u32, HashSet<AsPath>> {
    let mut result : HashMap<u32, HashSet<AsPath>> = HashMap::new();
    {
        let asn = load_asn();
        let graph = generate_router_graph();
        for (src, destinations) in graph.iter() {
            let sip = *src;
            if let Some((_, _, src)) = asn.longest_match(*src) {
                for dst in destinations.iter() {
                    let dist = dst.dt;
                    let dip = dst.ip;
                    if let Some((_, _, dst)) = asn.longest_match(dst.ip) {
                        for src in src.iter() {
                            for dst in dst.iter() {
                                if src == dst {
                                    continue;
                                }
                                //println!("{} ({}) -> {} ({})",sip, src,dip, dst);
                                // Insert the forward path  
                                let node = AsPath {
                                    asn: *dst,
                                    dist: dist,
                                };
                                match result.entry(*src) {
                                    Entry::Occupied(mut o) => {
                                        o.get_mut().insert(node);
                                    },
                                    Entry::Vacant(v) => {
                                        let v = v.insert(HashSet::new());
                                        v.insert(node);
                                    }
                                };

                                // Insert the reverse path
                                
                                let node = AsPath {
                                    asn: *src,
                                    dist: dist,
                                };
                                match result.entry(*dst) {
                                    Entry::Occupied(mut o) => {
                                        o.get_mut().insert(node);
                                    },
                                    Entry::Vacant(v) => {
                                        let v = v.insert(HashSet::new());
                                        v.insert(node);
                                    }
                                };
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}

fn dijkstra_as(graph: HashMap<u32, HashSet<AsPath>>, start: u32) -> HashMap::<u32, u32> {
    let mut distance = HashMap::<u32, u32>::with_capacity(graph.len());
    let mut visited = HashSet::new();

    distance.insert(start, 0);

    let mut current = start;
    let mut current_dist = *distance.get(&current).unwrap();
    loop {
        for nodes in graph.get(&current) {
            for path in nodes.iter() {
                if visited.contains(&path.asn) {
                    continue;
                }
                let dist = 1 + current_dist;
                if dist < *distance.get(&path.asn).unwrap_or(&u32::MAX) {
                    distance.insert(path.asn, dist);
                }
            }
        }
        visited.insert(current);

        let mut found = false;
        for (k, v) in distance.iter() {
            let dist = *distance.get(&current).unwrap();
            if !visited.contains(k) && *v != u32::MAX && (!found || current_dist > dist){
                current = *k;
                current_dist = dist;
                found = true;
            }
        }
        if !found {
            break;
        }
    }

    return distance;
}

pub fn check_paths() {
    let graph = generate_asmap();
    let base = dijkstra_as(graph, 27678);
    println!("a {:?}", base.iter().filter(|(_, y)| **y == 0).map(|(x,_)| *x).collect::<Vec<u32>>());
    println!("b {:?}", base.iter().filter(|(_, y)| **y == 1).map(|(x,_)| *x).collect::<Vec<u32>>());
    //println!("c {:?}", base.iter().filter(|(_, y)| **y == 2).map(|(x,_)| *x).collect::<Vec<u32>>());
    //println!("d {:?}", base.iter().filter(|(_, y)| **y == 3).map(|(x,_)| *x).collect::<Vec<u32>>());
    println!("max dist: {:?}", base.iter().max_by_key(|(_,x)| *x));
    let mut x = 0;
    // TODO: Check Hash, as each run give different numbers
    loop {
        let count = base.iter().filter(|(_, y)| **y == x).count();
        if count == 0 {
            break;
        }
        println!("Length {}: {}", x, count);
        x += 1;
    }
}
