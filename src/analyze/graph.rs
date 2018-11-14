extern crate rayon;
//TODO: Change HashMap for FnvHashMap
use analyze::helper::{load_asn, load_data};
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use self::rayon::prelude::*;


use std::u32;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};


#[derive(PartialEq, Eq, Hash, Debug, Clone)]
struct Node {
    ip: Ipv4Addr,
    dt: u32,
}

fn generate_router_graph() -> HashMap<Ipv4Addr, HashSet<Node>> {
    let mut result : HashMap<Ipv4Addr, HashSet<Node>> = HashMap::new();
    let data = load_data();
    debug!("Generating router graph");
    for (_, measurement) in data.iter() {
        let data = &measurement.data;
        let l = data.len();
        for i in 0..(l - 1) {
            if let Some(destination) = &data[i + 1] {
                if let Some(origin) = &data[i] {
                    if origin.ms.saturating_sub(destination.ms) as u32 == 0 {
                        if destination.ms.saturating_sub(origin.ms) as u32 != 0 {
                            println!("Inconsistent, {} ({}) vs {} ({})", origin.ms, origin.hops, destination.ms, destination.hops);
                        }
                    }
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

    return result;
}

#[derive(Debug, Clone)]
struct AsPath {
    dst: u32,
    dist: u32,
}

impl PartialEq for AsPath {
    fn eq(&self, other: &AsPath) -> bool {
        self.dst == other.dst
    }
}
impl Eq for AsPath {}

impl Hash for AsPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dst.hash(state);
    }
}

fn dijkstra_matrix(graph: &HashMap<u32, HashSet<AsPath>>, node: u32) -> HashMap<u32, u32> {
    let mut distance = HashMap::<u32, u32>::with_capacity(graph.len());
    let mut visited = HashSet::new();
    for (k, v) in graph.iter() {
        distance.insert(*k, u32::MAX);
        for path in v {
            distance.insert(path.dst, u32::MAX);
        }
    }
    distance.insert(node, 0);

    let mut current = node;
    let mut current_dist = *distance.get(&current).unwrap();
    loop {
        for nodes in graph.get(&current) {
            for path in nodes.iter() {
                if visited.contains(&path.dst) {
                    continue;
                }
                let dist = path.dist + current_dist;
                if dist < *distance.get(&path.dst).unwrap() {
                    distance.insert(path.dst, dist);
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

fn max_dijkstra(graph: &HashMap<u32, HashSet<AsPath>>, node: u32) -> u32 {
    let mut distance = dijkstra_matrix(graph, node);
    //debug!("dist vector: {:?}", distance);

    // Return the sum of distances
    info!("Distance: {}", distance.iter().map(|(_,b)| *b).filter(|x| *x != u32::MAX).sum::<u32>() );
    return distance.iter().map(|(_,b)| *b).filter(|x| *x != u32::MAX).sum::<u32>();
}

fn map_trace_to_as() -> HashMap<u32, HashSet<AsPath>> {
    let mut result : HashMap<u32, HashSet<AsPath>> = HashMap::new();
    let asn = load_asn();
    let graph = generate_router_graph();
    
    // Hacer disjkstra para almacenar distancias entre ips, y anotar los path despues
    return result;
}

fn generate_datamap() -> HashMap<u32, HashSet<AsPath>> {
    let mut result : HashMap<u32, HashSet<AsPath>> = HashMap::new();
    {
        let asn = load_asn();
        let graph = generate_router_graph();
        debug!("{}", graph.len());
        for (src, destinations) in graph.iter() {
            if let Some((_, _, src)) = asn.longest_match(*src) {
                for dst in destinations.iter() {
                    let dist = dst.dt;
                    if let Some((_, _, dst)) = asn.longest_match(dst.ip) {
                        for src in src.iter() {
                            for dst in dst.iter() {
                                if src == dst {
                                    continue;
                                }
                                // Insert the forward path  
                                let node = AsPath {
                                    dst: *dst,
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
                                    dst: *src,
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

pub fn generate_distance() {
    let mut result = generate_datamap();

    let mut nodes = result.iter().filter(|(k, v)| !v.is_empty()).map(|(k, _)| *k).collect::<Vec<u32>>();
    nodes.sort();
    debug!("AS Graph: {} nodes", nodes.len());
    {
        let mut nodemap = HashMap::new();
        let mut distances: Vec<Vec<u32>> = Vec::with_capacity(nodes.len());
        let mut index = 0;
        for node in nodes.iter() {
            let length = nodes.len() - index;
            distances.push(Vec::with_capacity(length));
            for _ in 0..length {
                distances[index].push(1_000_000);
            }
            nodemap.insert(node, index);
            index += 1;
        }
        // flow
        for (k, v) in result.iter() {
            let src = nodemap.get(k).unwrap();
            for path in v.iter() {
                let dst = nodemap.get(&path.dst).unwrap();
                distances[*src.min(dst)][src.max(dst) - src.min(dst)] = path.dist;
            }
        }
        info!("base calculated");
        use std;
        std::mem::drop(result);

        // Clear start
        for node in distances.iter_mut() {
            node[0] = 0;
        }

        // Run Floyd
        let n = distances.len();
        for k in 0..n {
            for i in 0..n {
                let start = distances[i.min(k)][i.max(k) - i.min(k)];
                for j in (i+1)..n {
                    let end = distances[k.min(j)][j.max(k) - j.min(k)];
                    if distances[i][j-i] > start + end {
                        distances[i][j-i] = start + end;
                    }
                }
            }
            info!("K = {}", k);
        }

        use std::io::{self, Write};
        // output the matrix
        info!("writting file");
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        for i in 0..n {
            for j in 0..n {
                handle.write(format!("{} ", distances[i.min(j)][i.max(j) - i.min(j)]).as_bytes());
            }
            handle.write("\n".as_bytes());
        }
    }

    return;

    // calculate the center of the graph
    let mut nodes = result.iter().filter(|(k, v)| !v.is_empty()).map(|(k, _)| *k).collect::<Vec<u32>>();
    nodes.sort();
    debug!("AS Graph: {} nodes", nodes.len());
    rayon::scope(|s| {
        for asn in nodes.iter() {
            let asn = Arc::new(asn.clone());
            s.spawn(|_| {
                let tmp = asn;
                let data = dijkstra_matrix(&result, *tmp);
                let result = nodes.iter().map(|n| data.get(n).unwrap()).map(|x| x.to_string()).collect::<Vec<String>>().join(",");

                println!("{},{}", tmp, result);
                //println!("{}", data.iter().map(|(_,b)| *b).filter(|x| *x != u32::MAX).sum::<u32>());
            });
        }
    });
}

#[derive(PartialEq, Eq, Hash, Debug)]
struct Vertex {
    ip: Ipv4Addr,
    edge: Vec<(Ipv4Addr, u32)>,
}

#[derive(Debug)]
struct Path {
    asn: u32,
    distance: u8,
}

pub fn testing() {
    let map = generate_datamap();
    calculate_distance(&map);
}

fn calculate_distance(map: &HashMap<u32, HashSet<AsPath>>) {
    let origin = 27678; // NIC Chile
    let target = 13768;
    println!("{:?}", map.get(&target).unwrap());
    let distance = dijkstra_matrix(map, origin);
    println!("Distance from {} to {}: {}", origin, target, distance.get(&target).unwrap_or(&u32::MAX));
}

/// Calculate and print the max length of the AS graph
fn calculate_max_length(map: &HashMap<u32, HashSet<u32>>) {
    let origin = 23140;
    let mut visited = HashSet::new();
    let mut step = VecDeque::new();
    step.push_back(Path {asn:origin, distance: 0 });

    let mut max_distance = 0;
    while let Some(current) = step.pop_front() {
        if visited.contains(&current.asn) { 
            continue;
        }
        visited.insert(current.asn);
        max_distance = max_distance.max(current.distance);
        if let Some(targets) = map.get(&current.asn) {
            for target in targets.iter() {
                if visited.contains(target) {
                    continue;
                }
                step.push_back(Path {
                    asn: *target,
                    distance: current.distance + 1,
                });
            }
        }
    }
    info!("Max distance: {}", max_distance);
}