extern crate geo;
extern crate treebitmap;

use self::geo::prelude::*;
use self::geo::Point;

use self::treebitmap::IpLookupTable;
use analyze::helper::{
    generate_citytable, generate_geotable, ip_normalize, load_area, load_asn, load_data,
    load_weights, CityLoc, GeoLoc, get_locations, get_locations_asn,
};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::net::Ipv4Addr;

use std::u32;

/// Load the traces and merge them in a HashMap by /24 network.
/// The IP addresses in the trace are separated by the hop where they were found
pub fn generate_iplink(
    tracepath: &String,
) -> HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> {
    let data = load_data(tracepath);
    let mut merge: HashMap<Ipv4Addr, HashMap<u32, Vec<(Ipv4Addr, u32)>>> = HashMap::new();
    let mut ms: HashMap<Ipv4Addr, Vec<u32>> = HashMap::new(); // avg, count, sd

    debug!("Merging data on generate_iplink");

    for (_xxx, measurement) in data.iter() {
        let data = &measurement.data;
        let l = data.len();

        for m in data {
            // latency measurement
            if let Some(m) = m {
                let _current = ms
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
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
    //start: (Ipv4Addr, u32),
    start: &Vec<Ipv4Addr>,
) -> HashMap<(Ipv4Addr, u32), u32> {
    debug!("analyze paths");

    // Join all paths as a graph, each one separated?
    let mut distance: HashMap<(Ipv4Addr, u32), u32> = HashMap::new();
    let mut paths = HashMap::<(Ipv4Addr, u32), Vec<(Ipv4Addr, u32)>>::with_capacity(graph.len());
    let mut heap = BinaryHeap::new();

    //heap.push(Node { ip: start, dist: 0 });
    //paths.insert(start, Vec::new());
    // search for the first valid hop
    for ip in start {
        for i in 0..5 {
            for nodes in graph.get(&ip) {
                if nodes.contains_key(&i) {
                    heap.push(Node {ip: (*ip, i), dist: 0});
                    paths.insert((*ip, i), Vec::new());
                    break;
                }
            }
        }
    }
    //for ip in start {
    //    heap.push(Node {ip: (*ip, 2), dist: 0});
    //    paths.insert((*ip, 0), Vec::new());
    //}
    //error!("{:?}", nodes.get());

    //info!("test src{:?}", graph.get(&"45.71.8.0".parse::<Ipv4Addr>().unwrap()));

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

pub fn generate_asgraph(paths: &HashMap<(Ipv4Addr, u32), Vec<(Ipv4Addr, u32)>>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> HashMap<u32, HashSet<u32>> {
    let mut graph: HashMap<u32, HashSet<u32>> = HashMap::new();
    for (_, ip_path) in paths.iter() {
        //let path = result.entry(*target).or_insert(Vec::new());
        for i in 0..(ip_path.len().saturating_sub(1)) {
            if ip_path[i].1 + 1 == ip_path[i+1].1 {
                if let Some((_, _, asn1)) = asn.longest_match(ip_path[i].0) {
                    if let Some((_, _, asn2)) = asn.longest_match(ip_path[i+1].0) {
                        for asn1 in asn1 {
                            for asn2 in asn2 {
                                graph.entry(*asn1).or_insert(HashSet::new()).insert(*asn2);
                            }
                        }
                    }
                }
            }
        }
    }

    return graph;
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

    for (x, y) in count.iter() {
        println!("asncount:{},{}", x, y)
    }

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
    info!("Most AS tha are in different hop count: {:?}", &count[0..10]);

    
    let mut mapping = HashMap::new();
    for (asn, levels) in result.iter() {
        mapping.entry(levels.iter().max().unwrap() + 1).or_insert(HashSet::new()).insert(asn);
    }
    for (x, y) in mapping.iter() {
        info!("jumpcount:{},{}", x, y.len());
    }
}

/// Geolocalize the destinations
/// Get the /24 network count by country
/// Get the hops to get to a country
/// Get the ms to a country
fn geolocalize(area: &HashMap<Ipv4Addr, Vec<u64>>) {
    let geo = generate_geotable();

    let mut result: HashMap<GeoLoc, u32> = HashMap::new();
    for (ip, _) in area.iter() {
        if let Some((_, _, loc)) = geo.longest_match(*ip) {
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

    for (loc, count) in result.iter() {
        println!("country:{},{}", loc.country, count);
    }
    /*
    let mut x = 0;
    while let Some(data) = result.get(&x) {
        let mut loc = data.iter().collect::<Vec<(&String, &u32)>>();
        loc.sort_by_key(|(_, c)| u32::MAX - *c);
        info!("Locations len {}: {:?}", x, loc);
        x += 1;
    }*/
}

fn geolocalize_asnaware(
    area: &HashMap<Ipv4Addr, Vec<u64>>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
) {
    let geo = generate_geotable();

    // for every location, add to a hashset of ASN to count
    let mut geoasn: HashMap<GeoLoc, HashSet<u32>> = HashMap::new();
    for (ip, _) in area.iter() {
        if let Some((_, _, loc)) = geo.longest_match(*ip) {
            if let Some((_, _, asn)) = asn.longest_match(*ip) {
                for asn in asn {
                    geoasn
                        .entry(loc.clone())
                        .or_insert(HashSet::new())
                        .insert(*asn);
                }
            }
        }
    }

    // Transform the hashset to count
    let mut result = geoasn
        .iter()
        .map(|(x, y)| (x, y.len() as u32))
        .collect::<Vec<(&GeoLoc, u32)>>();
    result.sort_by_key(|(_, y)| u32::MAX - *y);

    info!(
        "Max locations by ASN: {:?}",
        &result[0..10.min(result.len())]
    );
    info!(
        "Chile ASN: {:?}",
        result
            .iter()
            .filter(|(x, _)| x.country == "CL")
            .map(|(x, y)| (x, *y))
            .collect::<Vec<(&&GeoLoc, u32)>>()
    );

    // Number of AS by country
    for (loc, count) in result.iter() {
        println!("countryas:{},{}", loc.country, count);
    }
}

fn geolocalize_weighted(area: &HashMap<Ipv4Addr, Vec<u64>>) {
    let weight = load_weights(area);
    let geo = generate_geotable();

    let mut result: HashMap<GeoLoc, f64> = HashMap::new();
    for (ip, _) in area.iter() {
        if let Some((_, _, loc)) = geo.longest_match(*ip) {
            let current = result.entry(loc.clone()).or_insert(0f64);
            *current += weight.get(ip).unwrap_or(&0f64);
        }
    }

    let mut data = result
        .iter()
        .map(|(x, y)| (x, *y))
        .collect::<Vec<(&GeoLoc, f64)>>();
    data.sort_by_key(|(_, y)| (*y * 100000f64) as u64);
    data.reverse();
    info!("Weighted max geo: {:?}", &data[0..10.min(data.len())]);
    info!(
        "Chile Weight: {:?}",
        result
            .iter()
            .filter(|(x, _)| x.country == "CL")
            .map(|(x, y)| (x, *y))
            .collect::<Vec<(&GeoLoc, f64)>>()
    );

    // normalize and print
    for (loc, count) in result.iter() {
        println!(
            "countryweight:{},{}",
            loc.country,
            count / result.iter().map(|(_, x)| *x).sum::<f64>()
        );
    }
}

pub fn graph_info() {
    // arica: (45.71.8.0, 0)
    // merced: (200.1.123.0, 0)
    // saopaulo: (200.160.0.0, 0)
    // tucapel: (190.153.177.0, 0)
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 5 {
        panic!("Argments: <traces.csv> <asn.csv> <location>");
    }
    let tracepath = arguments[2].clone();
    let asnpath = arguments[3].clone();
    let origin = arguments[4].clone();

    let graph = generate_iplink(&tracepath);
    let asn = load_asn(&asnpath);
    //println!("{:?}", asn.longest_match(Ipv4Addr::new(45, 238,152,1)));
    //println!("{:?}", asn.longest_match(Ipv4Addr::new(200, 23,206,58)));
    //return;
    //let _distance = analyze_paths(&graph, &asn, (origin, 0));
    //let _distance = analyze_paths(&graph, &asn, (Ipv4Addr::new(45, 71, 8, 0), 0));
    //let _distance = analyze_paths(&graph, &asn, (Ipv4Addr::new(200, 1, 123, 0), 0));
    //let _distance = analyze_paths(&graph, &asn, (Ipv4Addr::new(190, 153, 177, 0), 0));
    let locations = get_locations();
    info!("{:?}", get_locations_asn(&asn));

    let _distance = analyze_paths(&graph, &asn, locations.get(&origin).unwrap());

    let area = load_area(&tracepath);
    geolocalize(&area);
    geolocalize_weighted(&area);
    geolocalize_asnaware(&area, &asn);

    // Distance test
    let city = generate_citytable();
    geotest_weighted(&area, &city);
}

fn geotest_weighted(area: &HashMap<Ipv4Addr, Vec<u64>>, city: &IpLookupTable<Ipv4Addr, CityLoc>) {
    let weight = load_weights(area);
    let locs = [
        (Point::<f64>::from((-70.6492055, -33.4379781)), "merced"),
        (Point::<f64>::from((-71.9599734, -37.292304)), "tucapel"),
        (Point::<f64>::from((-70.3591886, -18.4724638)), "arica"),
        (Point::<f64>::from((-46.8754996, -23.6821604)), "saopaulo"),
        (Point::<f64>::from((14.3255398, 50.0598058)), "praga"),
        (Point::<f64>::from((4.7585393, 52.354775)), "amsterdam"),
        (Point::<f64>::from((-118.4230595, 34.0784411)), "elsegundo"),
        (Point::<f64>::from((-100.4431833, 25.6490376)), "monterreya"),
    ];

    let mut result = HashMap::new();
    let mut result_count = HashMap::new();
    for (ip, _) in area.iter() {
        if let Some((_, _, loc)) = city.longest_match(*ip) {
            if loc.accuracy >= 1000 {
                continue;
            }
            let current = Point::<f64>::from((loc.longitude, loc.latitude));
            let mut dist = (locs[0].0.haversine_distance(&current), locs[0].1);
            for loc in locs.iter().skip(1) {
                let next = loc.0.haversine_distance(&current);
                if next < dist.0 {
                    dist = (next, loc.1);
                }
            }
            *result.entry(dist.1).or_insert(0f64) += 1f64 * *weight.get(ip).unwrap_or(&0f64);
            *result_count.entry(dist.1).or_insert(0) += 1;
        }
    }

    info!("Distance assigned: {:?}", result_count);
    info!(
        "Weighted distance assignations: {:?} (sum {})",
        result
            .iter()
            .map(|(x, y)| (*x, *y / result.iter().map(|(_, y)| *y).sum::<f64>()))
            .collect::<Vec<(&str, f64)>>(),
        result.iter().map(|(_, y)| *y).sum::<f64>()
    );

    let sum = result_count.iter().map(|(_, y)| *y).sum::<u32>() as f64;
    for (place, count) in result_count {
        println!("assigned:{},{}", place, count as f64 / sum);
    }

    let sum = result.iter().map(|(_, y)| *y).sum::<f64>();
    for (place, count) in result {
        println!("assignedweighted:{},{}", place, count / sum);
    }
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
