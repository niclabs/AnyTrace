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
use analyze::helper::{load_data, load_asn, load_weights_asn};

pub fn estimator() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: generate|run|runweight <asn.csv>\ngenerate: Generate the asn map with the configured traces\nrun: Run the estimator");
    }
    let asnpath = arguments[3].clone();

    if arguments[2] == "generate" {
        let asn = load_asn(&asnpath);
        load_traceroute(&asn);
    } else if arguments[2] == "run" {
        run_estimator(&asnpath);
    } else if arguments[2] == "runweight" {
        let asn = load_asn(&asnpath);
        run_estimator_weighted(&asn);
    } else if arguments[2] == "runhop" {
        let asn = load_asn(&asnpath);
        run_estimator_hop(&asn);
    } else {
        panic!("{} not an option", arguments[2]);
    }
}


/// Generate the distance matrix from the area of service
///
/// 
/// Steps:
///     1. Load graph with all the routes available
///     2. Load all the areas of services
///     3. Merge the traces with the graph so we have a consistent view
///     4. Determine the hop distance of every node
///         - From the area of service
///         - Maybe only add the graph that connect the limits?
fn generate_asmap(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>, trace: &String) -> HashMap<u32, HashSet<u32>> {
    let mut result: HashMap<u32, HashSet<u32>> = HashMap::default();
    {
        use analyze::graph::generate_iplink;
        let graph = generate_iplink(trace);
        for (src, destinations) in graph.iter() {
            if let Some((_, _, src)) = asn.longest_match(*src) {
                for (_, dests) in destinations.iter() {
                    for (dst, _) in dests.iter() {
                        if let Some((_, _, dst)) = asn.longest_match(*dst) {
                            for src in src.iter() {
                                for dst in dst.iter() {
                                    if src == dst {
                                        continue;
                                    }
                                    result.entry(*src).or_insert(HashSet::new()).insert(*dst);
                                    result.entry(*dst).or_insert(HashSet::new()).insert(*src);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}
fn run_estimator_hop(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let traces = [
        "result/arica.icmp.join".to_string(),
        "result/merced.icmp.join".to_string(),
        "result/tucapel.icmp.join".to_string(),
        "result/saopaulo.icmp.join".to_string(),
    ];

    let mut result = HashMap::new();
    for trace in traces.iter() {
        let mut map = generate_asmap(asn, trace);
        let keys = map.keys().map(|x|*x).collect::<Vec<u32>>();
        for k in keys.iter() {
            // Check if repeated, only if the hops are different. (TODO: Change tolerance to one)
            if result.contains_key(k) && map.get(k).unwrap() != result.get(k).unwrap() {
                // Collision detected, change to auxilirary (TODO: What about merging?)
                let newkey = 4200000000 + k;
                let data = map.get(k).unwrap().clone();
                map.remove(k);
                map.insert(newkey, data);

                // Update links
                for (_, v) in map.iter_mut() {
                    if v.contains(k) {
                        v.remove(k);
                        v.insert(newkey);
                    }
                }
            }
        }

        // Merge the graphs
        for (k, v) in map.iter() {
            result.insert(*k, v.clone());
        }
        // statistics
    }
    let dist = dijkstra_hops(4200000000, &result);
    let max = *dist.iter().max_by_key(|(_, x)| *x).unwrap().1;
    for i in 1..(max + 1) {
        debug!("ASN in level {}: {}", i, dist.iter().filter(|(_,v)| **v == i).count());
    }
    /*
    for trace in traces.iter() {
        let map = generate_asmap(asn, trace);
        for k in map.keys() {
            *tmp.entry(*k).or_insert(0) += 1;
        }
        let dist = dijkstra_hops(0, &map);
        //println!("{:?}", map);
        //println!("{:?}", dist);
        let max = *dist.iter().max_by_key(|(_, x)| *x).unwrap().1;
        for i in 1..(max + 1) {
            debug!("ASN in level {}: {}", i, dist.iter().filter(|(_,v)| **v == i).count());
        }

        for (k, v) in dist.iter() {
            // On key collision, we will use an auxiliary ASN
            // Use the private block 4200000000 + x
            if distance.contains_key(k) && v != distance.get(k).unwrap() {
                info!("Collision on ASN {}: {} vs {}", k, distance.get(k).unwrap(), v);
            }
            distance.insert(*k, *v);
        }

    }
    debug!("repeated: {:?}", tmp.iter().filter(|(_,v)| **v > 1).count());
    debug!("singular: {:?}", tmp.iter().filter(|(_,v)| **v == 1).count());*/
    
    // Todo: weight
}

fn dijkstra_hops(start: u32, graph: &HashMap<u32, HashSet<u32>>) -> HashMap<u32, u32> {
    let mut result: HashMap<u32, u32> = HashMap::new();

    let mut heap = BinaryHeap::new(); // Note: This is a max heap
    result.insert(start, 0);
    result.insert(27678, 0); //merced
    result.insert(22548, 0); //saopaulo
    result.insert(25192, 0); //praga
    result.insert(14259, 0); //tucapel
    result.insert(715, 0); //amsterdam
    result.insert(40528, 0); //elsegundo
    result.insert(22894, 0); //monterrey
    result.insert(264806, 0); // arica

    heap.push(DijkstraStateHop { asn: start, distance: 0});
    heap.push(DijkstraStateHop { asn: 27678, distance: 0}); //merced
    heap.push(DijkstraStateHop { asn: 22548, distance: 0}); //saopaulo
    heap.push(DijkstraStateHop { asn: 25192, distance: 0}); //praga
    heap.push(DijkstraStateHop { asn: 14259, distance: 0}); //tucapel
    heap.push(DijkstraStateHop { asn: 715, distance: 0}); //amsterdam
    heap.push(DijkstraStateHop { asn: 40528, distance: 0}); //elsegundo
    heap.push(DijkstraStateHop { asn: 22894, distance: 0}); //monterrey
    heap.push(DijkstraStateHop { asn: 264806, distance: 0}); //arica


    while let Some(DijkstraStateHop { asn, distance }) = heap.pop() {
        if distance > *result.get(&asn).unwrap_or(&std::u32::MAX) {
            continue;
        }

        for nodes in graph.get(&asn) {
            for target in nodes.iter() {
                let next = 1 + distance;
                if next < *result.get(target).unwrap_or(&std::u32::MAX) {
                    result.insert(*target, next);
                    heap.push(DijkstraStateHop {
                        asn: *target,
                        distance: next,
                    });
                }
            }
        }
    }

    return result;
}

/// We will simulate as we are add a new bgp
/*fn run_estimator_hop(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    // TODO: The area of service files tell the current hops
    // we can put a new item, and limit the hops it can advance
    // Like: 1 hop from AS, 2 hops, ... Each AS must have the hops to his router. After we apply 
    // the weights and win?!?!?!?!


    let mut graph = load_graph(&asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph);

    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    info!("ASN count: {}", keys.len());
    
    let mut count = 0;
    //let mut results = Vec::new();
    for asn in keys {
        let sum = dijkstra_sum_ms(asn, &graph);
        count += 1;
        if count % 100 == 0 {
            info!("{}", count);
        }
    }
}

fn dijkstra_sum_hops(start: u32, graph: &HashMap<u32, HashMap<(u32, u32), f32>>) {
    let mut result: HashMap<u32, u32> = HashMap::new();

    let mut heap = BinaryHeap::new(); // Note: This is a max heap
    result.insert(start, 0);
    result.insert(27678, 0); //merced
    result.insert(22548, 0); //saopaulo
    result.insert(25192, 0); //praga
    result.insert(14259, 0); //tucapel
    result.insert(715, 0); //amsterdam
    result.insert(40528, 0); //elsegundo
    result.insert(22894, 0); //monterrey
    // arica
    heap.push(DijkstraStateHop {
        asn: start,
        distance: 0,
    });

    while let Some(DijkstraStateHop { asn, distance }) = heap.pop() {
        if distance > *result.get(&asn).unwrap_or(&std::u32::MAX) {
            continue;
        }

        for nodes in graph.get(&asn) {
            for ((_inter, target), _) in nodes.iter() {
                let next = distance + 1;
                if next < *result.get(inter).unwrap_or(&std::u32::MAX) {
                    result.insert(*inter, next);
                    heap.push(DijkstraStateHop {
                        asn: *inter,
                        distance: next,
                    });
                }

                let next = distance + 2;
                if next < *result.get(target).unwrap_or(&std::u32::MAX) {
                    result.insert(*target, next);
                    heap.push(DijkstraStateHop {
                        asn: *target,
                        distance: next,
                    });
                }
            }
        }
    }
}*/

fn run_estimator_weighted(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let mut graph = load_graph(&asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph);

    let weights = load_weights_asn(&graph.iter().map(|(x,_)| *x).collect::<HashSet<u32>>(), asn);
    // TODO: Get global weights and run the estimator
}

fn run_estimator(asnpath: &String) {
    let asn = load_asn(&asnpath);
    let mut graph = load_graph(&asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph);

    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    info!("ASN count: {}", keys.len());

    let mut count = 0;
    let mut results = Vec::new();
    for asn in keys {
        let sum = dijkstra_sum_ms(asn, &graph);
        results.push((asn, sum));
        count += 1;
        if count % 100 == 0 {
            info!("{}", count);
        }
    }

    results.sort_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap_or(Ordering::Equal));
    info!("First minimals: {:?}", &results[0..(10.min(results.len()))]);
}

/// TODO: Check for anycast
///       We have to verify the effect with our test cloud
fn dijkstra_sum_ms(start: u32, graph: &HashMap<u32, HashMap<(u32, u32), f32>>) -> f32 {
    // Naive implementation, use dijstra to populate.
    let r = dijkstra(start, graph).iter().map(|(_, y)| *y).sum::<f32>();
    return r;
}

// Calculate the dijkstra distance graph
fn dijkstra(start: u32, graph: &HashMap<u32, HashMap<(u32, u32), f32>>) -> HashMap<u32, f32> {
    const base_distance: f32 = 10f32; // Base latency to connect to the given asn
    let mut result: HashMap<u32, f32> = HashMap::new();

    let mut heap = BinaryHeap::new(); // Note: This is a max heap
    result.insert(start, base_distance);
    result.insert(27678, 0f32); //merced
    result.insert(22548, 0f32); //saopaulo
    result.insert(25192, 0f32); //praga
    result.insert(14259, 0f32); //tucapel
    result.insert(715, 0f32); //amsterdam
    result.insert(40528, 0f32); //elsegundo
    result.insert(22894, 0f32); //monterrey
    result.insert(264806, 0f32); // arica

    heap.push(DijkstraState { asn: start, distance: base_distance});
    heap.push(DijkstraState { asn: 27678, distance: 0f32}); //merced
    heap.push(DijkstraState { asn: 22548, distance: 0f32}); //saopaulo
    heap.push(DijkstraState { asn: 25192, distance: 0f32}); //praga
    heap.push(DijkstraState { asn: 14259, distance: 0f32}); //tucapel
    heap.push(DijkstraState { asn: 715, distance: 0f32}); //amsterdam
    heap.push(DijkstraState { asn: 40528, distance: 0f32}); //elsegundo
    heap.push(DijkstraState { asn: 22894, distance: 0f32}); //monterrey
    heap.push(DijkstraState { asn: 264806, distance: 0f32}); //arica


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

/// Load the internet graph based on 
fn load_graph(_asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> HashMap<u32, HashMap<(u32, u32), f32>> {
    let mut result: HashMap<u32, HashMap<(u32, u32), Vec<f32>>> = HashMap::new();
    const MAX_MS: f32 = 210f32;

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

    // Load data from anytrace
    load_anycast_graph(&mut result, _asn);

    // Collect the vectors to a single value
    let mut reduced = HashMap::new();
    for (a, v) in result.iter_mut() {
        for (b, ms) in v.iter_mut() {
            reduced
                .entry(*a)
                .or_insert(HashMap::new())
                .insert(*b, (ms.iter().sum::<f32>() / ms.len() as f32).min(MAX_MS));
                //.insert(*b, (ms[ms.len()/2] as f32).min(MAX_MS));
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

/// Load a traceroute dump of ripe, outputting the ASN links in the format
/// (start_asn,middle_asn,target_asn )
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
            serde_json::from_str(&line).unwrap_or_else(|_| panic!("{}", line));
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

/// Load a base distance matrix to calculate the distances.

fn load_anycast_graph(out_graph: &mut HashMap<u32, HashMap<(u32, u32), Vec<f32>>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let paths = vec!["result/saopaulo.icmp.join"];

    let graph = load_data(&paths[0].to_string());
    let mut table = HashMap::new();
    for (_, measurement) in graph.iter() {
        let data = &measurement.data;
        let l = data.len();
        let mut route = Vec::new();
        let mut route_data = HashMap::new();
        for item in data.iter() {
            if let Some(packet) = item {
                if let Some((_, _, asn)) = asn.longest_match(packet.dst) {
                    for asn in asn {
                        route_data.entry(*asn).or_insert(Vec::new()).push(packet.ms as f32);
                        if !route.contains(asn) {
                            route.push(*asn);
                        }
                    }
                }
            }
        }
        merge_differences(route, route_data, &mut table);
    }
    for (a, v) in table {
        for ((b, c), latency) in v.iter() {
            out_graph
                .entry(a)
                .or_insert(HashMap::new())
                .entry((*b,*c))
                .or_insert(Vec::new())
                .extend(latency)
        }
    }
}

fn merge_differences(route: Vec<u32>, latency: HashMap<u32, Vec<f32>>, table: &mut HashMap<u32, HashMap<(u32, u32), Vec<f32>>>) {
    for i in 0..(route.len().saturating_sub(2)) {
        let r0 = latency.get(&route[i]).unwrap();
        let r1 = latency.get(&route[i + 2]).unwrap();
        let rtt0: f32 = r0.iter().sum::<f32>() / r0.len() as f32;
        let rtt1: f32 = r1.iter().sum::<f32>() / r1.len() as f32;
        let diff = rtt1 - rtt0;

        if diff > 0f32 {
            table
                .entry(route[i])
                .or_insert(HashMap::new())
                .entry((route[i + 1], route[i + 2]))
                .or_insert(Vec::new())
                .push(diff);
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

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq)]
struct DijkstraStateHop {
    asn: u32,
    distance: u32,
}

impl Ord for DijkstraStateHop {
    // cmp is inverted to make the BinaryHeap a min heap
    fn cmp(&self, other: &DijkstraStateHop) -> Ordering {
        other
            .distance
            .cmp(&self.distance)
            .then_with(|| self.asn.cmp(&other.asn))
    }
}