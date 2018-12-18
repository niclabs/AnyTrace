use analyze::helper::{asn_geoloc, load_asn, load_data};
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::net::Ipv4Addr;
use std::u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AsPath {
    asn: u32,
    dist: u32,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
struct TraceNode {
    ip: Ipv4Addr,
    dt: u32,
}

fn generate_router_graph(tracepath: &String) -> HashMap<Ipv4Addr, Vec<TraceNode>> {
    let mut result: HashMap<Ipv4Addr, Vec<TraceNode>> = HashMap::default();
    let data = load_data(tracepath);
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
                        }
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

fn generate_asmap(tracepath: &String, asnpath: &String) -> HashMap<u32, Vec<AsPath>> {
    let mut result: HashMap<u32, Vec<AsPath>> = HashMap::default();
    {
        let asn = load_asn(asnpath);
        let graph = generate_router_graph(tracepath);
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
                                    asn: *dst,
                                    dist: dist,
                                };
                                match result.entry(*src) {
                                    Entry::Occupied(mut o) => {
                                        o.get_mut().push(node);
                                    }
                                    Entry::Vacant(v) => {
                                        let v = v.insert(Vec::default());
                                        v.push(node);
                                    }
                                };

                                // Insert the reverse path
                                let node = AsPath {
                                    asn: *src,
                                    dist: dist,
                                };
                                match result.entry(*dst) {
                                    Entry::Occupied(mut o) => {
                                        o.get_mut().push(node);
                                    }
                                    Entry::Vacant(v) => {
                                        let v = v.insert(Vec::default());
                                        v.push(node);
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

#[derive(Copy, Clone, Eq, PartialEq)]
struct State {
    id: u32,
    dist: u32,
}

impl Ord for State {
    fn cmp(&self, other: &State) -> Ordering {
        other
            .dist
            .cmp(&self.dist)
            .then_with(|| self.id.cmp(&other.id))
    }
}
impl PartialOrd for State {
    fn partial_cmp(&self, other: &State) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn dijkstra_as(graph: &HashMap<u32, Vec<AsPath>>, start: u32) -> HashMap<u32, u32> {
    let mut distance = HashMap::<u32, u32>::with_capacity(graph.len());
    let mut heap = BinaryHeap::new();

    distance.insert(start, 0);
    heap.push(State { dist: 0, id: start });

    while let Some(State { id, dist }) = heap.pop() {
        if dist > *distance.get(&id).unwrap_or(&u32::MAX) {
            continue;
        }

        let next = 1 + dist;
        for nodes in graph.get(&id) {
            for path in nodes.iter() {
                if next < *distance.get(&path.asn).unwrap_or(&u32::MAX) {
                    distance.insert(path.asn, next);
                    heap.push(State {
                        dist: next,
                        id: path.asn,
                    });
                }
            }
        }
    }

    return distance;
}

fn bucket_as(distance: &HashMap<u32, u32>, asnpath: &String) {
    let geo = asn_geoloc(asnpath);
    let mut result = HashMap::new();
    for (asn, dist) in distance.iter() {
        if let Some(geodata) = geo.get(asn) {
            let data = result.entry(dist).or_insert(HashMap::<String, u32>::new());
            for loc in geodata {
                let mut item = data.entry(loc.country.clone()).or_insert(0);
                *item += 1;
            }
        }
    }

    let mut x = 0;
    while let Some(data) = result.get(&x) {
        let mut loc = data.iter().collect::<Vec<(&String, &u32)>>();
        loc.sort_by_key(|(_, c)| u32::MAX - *c);
        info!("Locations len {}: {:?}", x, loc);
        x += 1;
    }
}

fn check_as_rangecount(tracepath: &String, asnpath: &String) {
    let mut count = HashMap::new();
    {
        let mut visited = HashSet::new();
        let asn = load_asn(asnpath);
        let graph = generate_router_graph(tracepath);
        for (src, destinations) in graph.iter() {
            let prefix = u32::from(*src) & 0xFFFFFF00;
            if let Some((_, _, src)) = asn.longest_match(*src) {
                if !visited.contains(&prefix) {
                    visited.insert(prefix);
                    for src in src.iter() {
                        let mut cnt = count.entry(*src).or_insert(0);
                        *cnt += 1;
                    }
                }
                for dst in destinations.iter() {
                    let prefix = u32::from(dst.ip) & 0xFFFFFF00;
                    if let Some((_, _, dst)) = asn.longest_match(dst.ip) {
                        for src in src.iter() {
                            for dst in dst.iter() {
                                if src == dst {
                                    continue;
                                }
                                if !visited.contains(&prefix) {
                                    visited.insert(prefix);
                                    let mut cnt = count.entry(*dst).or_insert(0);
                                    *cnt += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut res = count.iter().collect::<Vec<(&u32, &u32)>>();
    res.sort_by_key(|(_, c)| u32::MAX - *c);
    info!("Top used AS: {:?}", &res[0..10]);
}

fn calculate_latency(tracepath: &String, asnpath: &String) -> HashMap<u32, u64> {
    // TODO: Change the single origin to mul
    let mut latency = HashMap::new();
    {
        let asndata = load_asn(asnpath);
        let data = load_data(tracepath);
        for (_, measurement) in data.iter() {
            let data = &measurement.data;
            let l = data.len();
            for item in data {
                if let Some(item) = item {
                    if let Some((_, _, asn)) = asndata.longest_match(item.dst) {
                        for asn in asn {
                            latency
                                .entry(asn.clone())
                                .or_insert(Vec::new())
                                .push(item.ms);
                        }
                    }
                }
            }
        }
    }

    let mut res = latency
        .iter()
        .map(|(asn, lat)| {
            (
                asn,
                lat.iter().fold(0, |acc, x| acc + *x) / lat.iter().count() as u64,
            )
        }).collect::<Vec<(&u32, u64)>>();
    use std::u64;
    res.sort_by_key(|(_, c)| u64::MAX - *c);
    info!("Top latency AS: {:?}", &res[0..10]);
    return latency
        .iter()
        .map(|(asn, lat)| {
            (
                *asn,
                lat.iter().fold(0, |acc, x| acc + *x) / lat.iter().count() as u64,
            )
        }).collect::<HashMap<u32, u64>>();;
}

fn pathfind_as(src: u32, target: u32, graph: &HashMap<u32, Vec<AsPath>>) -> Vec<u32> {
    let mut distance = HashMap::<u32, u32>::with_capacity(graph.len());
    let mut paths = HashMap::<u32, Vec<u32>>::with_capacity(graph.len());

    let mut heap = BinaryHeap::new();

    distance.insert(src, 0);
    heap.push(State { dist: 0, id: src });
    paths.insert(src, vec![src]);

    while let Some(State { id, dist }) = heap.pop() {
        if dist > *distance.get(&id).unwrap_or(&u32::MAX) {
            continue;
        }

        let next = 1 + dist;
        for nodes in graph.get(&id) {
            for path in nodes.iter() {
                if next < *distance.get(&path.asn).unwrap_or(&u32::MAX) {
                    distance.insert(path.asn, next);
                    heap.push(State {
                        dist: next,
                        id: path.asn,
                    });
                    let mut p = paths.get(&id).unwrap().clone();
                    p.push(path.asn);
                    paths.insert(path.asn, p);
                }
            }
        }
    }
    //info!("{:?}", paths);
    info!("{:?}", distance.get(&target));
    info!("{:?}", paths.get(&target));
    return paths.get(&target).unwrap().clone();
}

pub fn check_paths() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: <traces.csv> <asn.csv>");
    }
    let tracepath = arguments[2].clone();
    let asnpath = arguments[3].clone();

    let graph = generate_asmap(&tracepath, &asnpath);
    let base = dijkstra_as(&graph, 27678);
    //bucket_as(&base, &asnpath);
    //check_as_rangecount(&tracepath, &asnpath);
    //calculate_latency(&tracepath, &asnpath);

    info!("max dist: {:?}", base.iter().max_by_key(|(_, x)| *x));
    info!("Distance from {}: {:?}", 27978, base.get(&27978));
    info!("Distance to {}: {:?}", 59891, base.get(&59891));
    info!("path to {}: {:?}", 59891, pathfind_as(27678, 59891, &graph));

    let mut x = 0;
    loop {
        let count = base.iter().filter(|(_, y)| **y == x).count();
        if count == 0 {
            break;
        }
        info!("Length {}: {}", x, count);
        x += 1;
    }
}
