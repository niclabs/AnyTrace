extern crate bzip2;
extern crate serde_derive;
extern crate serde_json;
extern crate treebitmap;

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;

use self::bzip2::read::BzDecoder;
use self::treebitmap::IpLookupTable;
use analyze::helper::{ip_normalize, load_asn};

pub fn estimator() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: generate|run <asn.csv>\ngenerate: Generate the asn map with the configured traces\nrun: Run the estimator");
    }
    let asnpath = arguments[3].clone();

    if arguments[2] == "generate" {
        let asn = load_asn(&asnpath);
        load_traceroute(&asn);
    } else if arguments[2] == "run" {
        run_estimator();
    } else {
        panic!("{} not an option", arguments[2]);
    }
}

fn run_estimator() {
    let mut graph = load_graph();
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph);

    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    info!("ASN count: {}", keys.len());

    let mut min = None;
    let mut minasn = 0;
    let mut count = 0;
    let mut results = Vec::new();
    for asn in keys {
        let sum = dijkstra_sum_ms(asn, &graph);
        results.push((asn, sum));
        if min.is_none() || sum < min.unwrap() {
            min = Some(sum);
            minasn = asn;
        }
        count += 1;
        if count % 100 == 0 {
            info!("{}", count);
        }
    }
    info!("Minimal asn: {}, {}", minasn, min.unwrap());
    results.sort_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap_or(Ordering::Equal));
    info!("First minimals: {:?}", &results[0..(10.min(results.len()))]);
}

/// TODO: Update the distances with the area of service of the cloud!
///       Then, we are done (Remember to prevent going through NIC/anycast to skip hops)
///       We have to verify the effect with our test cloud
fn dijkstra_sum_ms(start: u32, graph: &HashMap<u32, HashMap<(u32, u32), f32>>) -> f32 {
    // Naive implementation, use dijstra to populate.
    // TODO: By propagation (hop) distance. (Populate distance matrix with the area of service data)
    let r = dijkstra(start, graph).iter().map(|(_, y)| *y).sum::<f32>();
    return r;
}

fn dijkstra(start: u32, graph: &HashMap<u32, HashMap<(u32, u32), f32>>) -> HashMap<u32, f32> {
    let mut result: HashMap<u32, f32> = HashMap::new();

    let mut heap = BinaryHeap::new(); // Note: This is a max heap
    result.insert(start, 0f32);
    heap.push(DijkstraState {
        asn: start,
        distance: 0f32,
    });

    while let Some(DijkstraState { asn, distance }) = heap.pop() {
        if distance > *result.get(&asn).unwrap_or(&std::f32::MAX) {
            continue;
        }

        for nodes in graph.get(&asn) {
            for ((_, target), &targetms) in nodes.iter() {
                let next = targetms + distance;
                if next < *result.get(target).unwrap_or(&std::f32::MAX) {
                    result.insert(*target, next);
                    heap.push(DijkstraState {
                        asn: *target,
                        distance: next,
                    });
                }
            }
        }
    }

    return result;
}

fn load_graph() -> HashMap<u32, HashMap<(u32, u32), f32>> {
    let mut result: HashMap<u32, HashMap<(u32, u32), Vec<f32>>> = HashMap::new();

    let paths = vec!["result/routes.1.csv", "result/routes.2.csv"];
    for path in paths.iter() {
        let f = File::open(path).unwrap();

        for line in BufReader::new(f).lines() {
            let line = line.unwrap();
            let data = line.split(",").collect::<Vec<&str>>();
            result
                .entry(data[0].parse().unwrap())
                .or_insert(HashMap::new())
                .entry((data[1].parse().unwrap(), data[2].parse().unwrap()))
                .or_insert(Vec::new())
                .extend(data[3..].iter().map(|x| x.parse::<f32>().unwrap()));
        }
    }

    // Collect the vectors to a single value
    let mut reduced = HashMap::new();
    for (a, v) in result.iter_mut() {
        for (b, ms) in v.iter_mut() {
            reduced
                .entry(*a)
                .or_insert(HashMap::new())
                .insert(*b, ms.iter().sum::<f32>() / ms.len() as f32);
        }
    }

    return reduced;
}

/// Fill the given graph with the reverse
fn fill_reverse_graph(graph: &mut HashMap<u32, HashMap<(u32, u32), f32>>) {
    let cp = graph.clone();

    for (a, v) in cp {
        for ((b, c), ms) in v {
            graph
                .entry(c)
                .or_insert(HashMap::new())
                .entry((b, a))
                .or_insert(ms);
        }
    }
}

/// Remove disconnected nodes from a base AS
fn filter_disconnected(base: u32, graph: &mut HashMap<u32, HashMap<(u32, u32), f32>>) {
    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    let founded_keys = dijkstra(base, graph)
        .iter()
        .map(|(x, _)| *x)
        .collect::<HashSet<u32>>();

    for k in keys {
        if !founded_keys.contains(&k) {
            debug!("Removing disconnected {}", k);
            graph.remove(&k);
        }
    }
}

#[derive(serde_derive::Deserialize, Debug)]
struct TracerouteMeasurement {
    result: Vec<TraceResult>,
}

#[derive(serde_derive::Deserialize, Debug)]
struct TraceResult {
    //hop: Option<u8>,
    result: Option<Vec<Trace>>,
}

#[derive(serde_derive::Deserialize, Debug)]
struct Trace {
    from: Option<Ipv4Addr>,
    rtt: Option<f32>,
}

fn load_traceroute(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let path = "./data/ripe/traceroute-2018-12-06T0100.bz2";

    let f = File::open(path).unwrap();
    let zip = BzDecoder::new(f);

    let mut table = HashMap::new();
    for line in BufReader::new(zip).lines() {
        let line = line.unwrap();
        // Skip IPv6
        if !line.starts_with("{\"af\":4") {
            continue;
        }

        let data: TracerouteMeasurement =
            serde_json::from_str(&line).unwrap_or_else(|x| panic!("{}", line));
        //let data: TracerouteMeasurement = serde_json::from_str(&line).unwrap();

        // Store the route and add it to the result in the format: (src, middle, target): [rtt]
        let mut route = HashMap::new();
        let mut route_order = Vec::new();
        for result in data.result {
            for trace in result.result.unwrap_or_default() {
                if let Some(ip) = trace.from {
                    if let Some(rtt) = trace.rtt {
                        if !ip.is_private() {
                            if let Some((_, _, asn)) = asn.longest_match(ip) {
                                for asn in asn {
                                    route.entry(asn).or_insert(Vec::new()).push(rtt);
                                    if !route_order.contains(asn) {
                                        route_order.push(*asn);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for i in 0..(route_order.len().saturating_sub(2)) {
            let r0 = route.get(&route_order[i]).unwrap();
            let r1 = route.get(&route_order[i + 2]).unwrap();
            let rtt0: f32 = r0.iter().sum::<f32>() / r0.len() as f32;
            let rtt1: f32 = r1.iter().sum::<f32>() / r1.len() as f32;
            let diff = rtt1 - rtt0;

            if diff > 0f32 {
                table
                    .entry(route_order[i])
                    .or_insert(HashMap::new())
                    .entry((route_order[i + 1], route_order[i + 2]))
                    .or_insert(Vec::new())
                    .push(diff);
            }
        }
    }
    info!("Routes extracted: {:?} routes", table.len());
    for (a1, v) in table.iter() {
        for ((a2, a3), lat) in v {
            println!(
                "{},{},{},{}",
                a1,
                a2,
                a3,
                lat.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            );
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct DijkstraState {
    asn: u32,
    distance: f32,
}

impl Ord for DijkstraState {
    // cmp is inverted to make the BinaryHeap a min heap
    fn cmp(&self, other: &DijkstraState) -> Ordering {
        other
            .distance
            .partial_cmp(&self.distance)
            .unwrap()
            .then_with(|| self.asn.cmp(&other.asn))
    }
}

impl Eq for DijkstraState {}

impl PartialOrd for DijkstraState {
    fn partial_cmp(&self, other: &DijkstraState) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
