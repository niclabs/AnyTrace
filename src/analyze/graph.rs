extern crate treebitmap;

use self::treebitmap::IpLookupTable;
use analyze::helper::{
    asn_geoloc, generate_citytable, generate_geotable, load_asn, load_data, GeoLoc,
};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::net::Ipv4Addr;

use std::u32;

/// Normalize the ip address, converting it in a /24 network address
/// by removing the list 8 bits
fn ip_normalize(address: Ipv4Addr) -> Ipv4Addr {
    return Ipv4Addr::from(u32::from(address) & 0xFFFFFF00);
}

/// Load the traces and merge them in a HashMap by /24 network.
/// The IP addresses in the trace are separated by the hop where they were found
fn generate_iplink(tracepath: &String) -> HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> {
    let mut data = load_data(tracepath);
    let mut merge: HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> = HashMap::new();
    let mut ms: HashMap<Ipv4Addr, Vec<u32>> = HashMap::new(); // avg, count, sd

    debug!("Merging data on generate_iplink");

    for (_, measurement) in data.iter() {
        let data = &measurement.data;
        let l = data.len();

        for m in data {
            if let Some(m) = m {
                let current = ms
                    .entry(ip_normalize(m.dst))
                    .or_insert(Vec::new())
                    .push(m.ms as u32);
            }
        }
        for i in 1..l {
            if let Some(destination) = &data[i] {
                let mut j = (i as i32) - 1;
                while j >= 0 {
                    if let Some(origin) = &data[j as usize] {
                        if origin.dst == destination.dst {
                            break;
                        }
                        merge
                            .entry(ip_normalize(origin.dst))
                            .or_insert(HashMap::new())
                            .entry(j as u32)
                            .or_insert(Vec::new())
                            .push((ip_normalize(destination.dst), i as u32));
                        break;
                    }
                    j -= 1;
                }
            }
        }
    }

    let mut msavg = HashMap::new();
    for (ip, data) in ms.iter() {
        let mut data = data
            .iter()
            .filter(|x| **x < 1000)
            .map(|x| *x)
            .collect::<Vec<u32>>();
        if data.len() > 2 {
            //let avg: f64 = (data.iter().sum::<u32>() as f64) / data.len() as f64;
            data.sort();
            let avg: f64 = {
                if data.len() % 2 == 1 {
                    data[data.len() / 2] as f64
                } else {
                    (data[data.len() / 2 - 1] + data[data.len() / 2]) as f64 / 2.
                }
            };
            let sum2 = data
                .iter()
                .fold(0f64, |sum, curr| sum + (*curr as f64 - avg).powf(2.) as f64);
            let sd = (sum2 / (data.len() as f64 - 1.)).sqrt();
            msavg.insert(ip, (avg, sd));
        }
    }

    // Separate data in bucket, from 0-10,10-20...500
    let mut buckets = Vec::new();
    let step = 10;
    for i in (0..500).step_by(step) {
        let current = i as f64;
        let mut count = 0;
        for (_, (avg, _)) in msavg.iter() {
            if current < *avg && *avg < current + step as f64 {
                count += 1
            }
        }
        buckets.push(count);
    }

    info!("Median buckets: {:?}", buckets);

    info!(
        "Biggest ms: {:?}",
        msavg.iter().fold(
            ("0.0.0.0".parse().unwrap(), (0f64, 0f64)),
            |(ip1, (avg1, sd1)), (ip2, (avg2, sd2))| match PartialOrd::partial_cmp(&avg1, &avg2) {
                None => ("0.0.0.0".parse::<Ipv4Addr>().unwrap(), (0f64, 0f64)),
                Some(Ordering::Greater) => (ip1, (avg1, sd1)),
                Some(_) => (**ip2, (*avg2, *sd2)),
            }
        )
    );

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

/// Calculate the distance and paths to every /24 network
fn analyze_paths(
    graph: &HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>>,
    asn: IpLookupTable<Ipv4Addr, Vec<u32>>,
    start: (Ipv4Addr, u32),
) -> HashMap<(Ipv4Addr, u32), u32> {
    debug!("analyze paths");
    // Join all paths as a graph, each one separated?
    let mut distance: HashMap<(Ipv4Addr, u32), u32> = HashMap::new();
    let mut paths = HashMap::<(Ipv4Addr, u32), Vec<(Ipv4Addr, u32)>>::with_capacity(graph.len());
    let mut heap = BinaryHeap::new();

    heap.push(Node { ip: start, dist: 0 });
    paths.insert(start, Vec::new());

    //info!("test src{:?}", graph.get(&"45.71.8.0".parse::<Ipv4Addr>().unwrap()));

    while let Some(Node { ip, dist }) = heap.pop() {
        debug!("ip: {:?}", ip);
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

    let ip: Ipv4Addr = "190.124.27.0".parse().unwrap();
    info!(
        "Sources of 190.124.27.10: {:?}",
        graph
            .iter()
            .map(|(_, v)| v
                .iter() // HashMap
                .map(|(_, next)| next
                    .iter()
                    .filter(|(address, _)| *address == ip)
                    .map(|x| *x)
                    .collect::<Vec<(Ipv4Addr, u32)>>()).fold(Vec::new(), |mut current, next| {
                    current.extend(next);
                    current
                })).filter(|x| x.len() > 0)
            .fold(Vec::new(), |mut current, next| {
                current.extend(next);
                current
            })
    );

    info!(
        "Position of 190.124.27.10: {:?}",
        graph.get(&"190.124.27.0".parse().unwrap())
    );
    info!(
        "max distance: {:?}",
        distance.iter().max_by_key(|(_, d)| *d)
    );
    info!(
        "Distance from 185.32.124.199: {:?}",
        distance.get(&("185.32.124.0".parse().unwrap(), 17))
    );
    info!(
        "path for 185.32.124.199: {:?}",
        paths.get(&("185.32.124.0".parse().unwrap(), 17))
    );
    //info!("Path to 94.139.67.0: {:?}", paths.get(&("94.139.67.0".parse().unwrap(), 23)));
    info!(
        "test {:?}",
        paths
            .iter()
            .filter(|(x, _)| x.0 == "190.124.27.0".parse::<Ipv4Addr>().unwrap())
            .collect::<HashMap<&(Ipv4Addr, u32), &Vec<(Ipv4Addr, u32)>>>()
    );

    paths_to_asn(&paths, &asn);

    return distance;
}

/// Transform the /24 paths to AS paths
fn paths_to_asn(
    paths: &HashMap<(Ipv4Addr, u32), Vec<(Ipv4Addr, u32)>>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
) {
    debug!("Transforming paths to asn paths");
    let mut result: HashMap<(Ipv4Addr, u32), Vec<u32>> = HashMap::new();
    let mut count: HashMap<u32, u32> = HashMap::new();

    for (target, ip_path) in paths.iter() {
        let path = result.entry(*target).or_insert(Vec::new());
        for ip in ip_path {
            if let Some((_, _, asn)) = asn.longest_match(ip.0) {
                for asn in asn {
                    if path.len() == 0 || *path.last().unwrap() != *asn {
                        path.push(*asn);
                        *count.entry(*asn).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    info!(
        "AS PATH for 185.32.124.199: {:?}",
        result.get(&("185.32.124.0".parse().unwrap(), 17))
    );
    info!(
        "AS PATH max: {:?}",
        result.iter().max_by_key(|(_, v)| v.len())
    );

    let mut count = count
        .iter()
        .map(|(x, y)| (*x, *y))
        .collect::<Vec<(u32, u32)>>();
    count.sort_by_key(|(_, y)| *y);
    count.reverse();
    info!("First 10 most indexed ASN: {:?}", &count[0..10]);
    check_aspath_hops(&result);
}

/// Check the hops of a AS path graph
fn check_aspath_hops(aspath: &HashMap<(Ipv4Addr, u32), Vec<u32>>) {
    let mut result = HashMap::new();

    for (_, path) in aspath {
        for i in 0..path.len() {
            let mut data = result.entry(path[i]).or_insert(HashSet::new());
            data.insert(i);
        }
    }

    let mut count = result
        .iter()
        .filter(|(_, y)| y.len() > 1)
        .map(|(x, y)| (*x, y.len() as u32))
        .collect::<Vec<(u32, u32)>>();
    count.sort_by_key(|(_, y)| *y);
    count.reverse();
    info!("Most as with multiple hop count: {:?}", &count[0..10]);
}

/// Geolocalize the destinations
/// Get the /24 network count by country
/// Get the hops to get to a country
/// Get the ms to a country
fn geolocalize(distances: &HashMap<(Ipv4Addr, u32), u32>, asnpath: &String) {
    //let geo = asn_geoloc(asnpath);
    let geo = generate_geotable();
    //let mut result = HashMap::new();

    // Remove duplicates by hop
    let mut data = distances
        .iter()
        .map(|(x, _)| *x)
        .collect::<Vec<(Ipv4Addr, u32)>>();
    data.sort_by_key(|(ip, hops)| u32::from(*ip) | hops);
    data.dedup_by_key(|(ip, _)| *ip);

    let mut result: HashMap<GeoLoc, u32> = HashMap::new();
    for (ip, _) in data {
        if let Some((_, _, loc)) = geo.longest_match(ip) {
            let current = result.entry(loc.clone()).or_insert(0);
            *current += 1;
        }
    }

    let mut data = result
        .iter()
        .map(|(x, y)| (x, *y))
        .collect::<Vec<(&GeoLoc, u32)>>();
    data.sort_by_key(|(_, y)| u32::MAX - y);
    info!("max geo: {:?}", &data[0..10.min(data.len())]);
    info!(
        "Chile: {:?}",
        result
            .iter()
            .filter(|(x, _)| x.country == "CL")
            .map(|(x, y)| (x, *y))
            .collect::<Vec<(&GeoLoc, u32)>>()
    );
    /*
    let mut x = 0;
    while let Some(data) = result.get(&x) {
        let mut loc = data.iter().collect::<Vec<(&String, &u32)>>();
        loc.sort_by_key(|(_, c)| u32::MAX - *c);
        info!("Locations len {}: {:?}", x, loc);
        x += 1;
    }*/
}

pub fn graph_info() {
    // arica: (45.71.8.0, 0)
    // merced: (200.1.123.0, 0)
    // saopaulo: (200.160.0.0, 0)
    // tucapel: (190.153.177.0, 0)
    generate_citytable();
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: <traces.csv> <asn.csv>");
    }
    let tracepath = arguments[2].clone();
    let asnpath = arguments[3].clone();

    let graph = generate_iplink(&tracepath);
    let asn = load_asn(&asnpath);
    let distance = analyze_paths(&graph, asn, (Ipv4Addr::new(190, 153, 177, 0), 0));
    geolocalize(&distance, &asnpath);
}

// Define distance as (origin, middle, out) for every asn
// In this way, we make sure that this systems take into account the total distance to get to the destination.
// Tests get defines as a dummy node to the origin to the next.
// (Dummy -> Origin -> Target) == ping Target
// (Origin -> Target -> B2)

// Uso un dump de traceroutes para hacer mi mapa de /24 como lo hice con los otros
// Transformar la matriz
// Con eso me armo mi matriz de distancia bidireccional
//
