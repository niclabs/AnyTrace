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
use analyze::helper::{load_asn, load_data, load_weights_asn, get_locations_asn, get_all_traces};

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
fn generate_asmap(
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
    trace: &String,
) -> HashMap<u32, HashSet<u32>> {
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
    let traces = get_all_traces();

    let mut result = HashMap::new();
    let mut graph = load_graph(asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph, asn);
    for (k, v) in graph.iter() {
        for (t, _) in v {
            //result.entry(*k).or_insert(HashSet::new()).insert(*t);
        }
    }


    let mut counter = 0;
    for trace in traces.iter() {
        let mut map = generate_asmap(asn, trace);
        let result_dist = dijkstra_hops(4200000000, &result, asn);

        let keys = map.keys().map(|x| *x).collect::<Vec<u32>>();
        for k in keys.iter() {break;
            // Check if repeated, only if the hops are different.
            if result.contains_key(k)
                && result_dist.get(k).unwrap_or(&10000) != result_dist.get(k).unwrap_or(&10000)
            {
                // Collision detected, change to auxilirary
                counter += 1;
                let newkey = 4200000000 + counter;
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
            //result.insert(*k, v.clone());
            result.entry(*k).or_insert(HashSet::new()).extend(v);
        }
        // statistics
        let dist = dijkstra_hops(4200000000, &result, asn);
        let max = *dist.iter().max_by_key(|(_, x)| *x).unwrap().1;
        for i in 1..(max + 1) {
            debug!(
                "ASN in level {}: {}",
                i,
                dist.iter().filter(|(_, v)| **v == i).count()
            );
        }
    }
    let dist = dijkstra_hops(4200000000, &result, asn);
    let max = *dist.iter().max_by_key(|(_, x)| *x).unwrap().1;
    for i in 1..(max + 1) {
        debug!(
            "ASN in level {}: {}",
            i,
            dist.iter().filter(|(_, v)| **v == i).count()
        );
    }

    // Try to optimize this network
    // This will handle when we have nodes with unknown area of service
    // and only offer new places on known networks
    {
        let mut dist = Vec::new();
        for rasn in result.keys() {if *rasn != 1200 {continue;}
            let r = dijkstra_hops(*rasn, &result, asn);
            let value = r.iter().map(|(_, y)| y).sum::<u32>();
            dist.push((*rasn, value));
            println!("{}", value);

            if dist.len() % 100 == 0 {
                debug!("{}", dist.len());
            }
        }
        dist.sort_by_key(|(_, y)| *y);
        info!("Best results raw: {:?}", &dist[0..10.min(dist.len())]);

        let base = dijkstra_hops(4200000000, &result, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>();
        println!("hoprawbase:{}", dijkstra_hops(4200000000, &result, asn).iter().map(|(_, y)| y).sum::<u32>());
        for i in 0..50.min(dist.len()) {
            println!("hopraw:{},{}", dist[i].0, dist[i].1);
            // Local effect
            let (before, after, count) = calculate_effect(&base, &dijkstra_hops(dist[i].0, &result, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>());
            println!(
                "hoprawcompare:{},{},{},{}",
                dist[i].0, before, after, count
            );
        }
    }

    // Dijstra applying a limit on the hops
    // Use the empty distance matrix, and then apply dijstra only on that node, updating uptil limit X.
    // Force and not the updates to the level shown (to show the effect of badly applied rules)
    // dijkstra_hops_limited

    // Add weights to the ASN:
    let weights = load_weights_asn(&dist.iter().map(|(x, _)| *x).collect::<HashSet<u32>>(), asn);
    {
        let mut dist = Vec::new();
        for rasn in result.keys() {if *rasn != 1200 {continue;}
            let r = dijkstra_hops(*rasn, &result, asn);
            let mut sumweight = 0f64;
            let value = r
                .iter()
                .map(|(x, y)| {
                    let w = *weights.get(x).unwrap_or(&0f64);
                    sumweight += w;
                    (*y as f64) * w}
                )
                .sum::<f64>();
            dist.push((*rasn, value / sumweight));
            if dist.len() % 100 == 0 {
                debug!("{}", dist.len());
            }
        }
        dist.sort_by_key(|(_, y)| (*y * 100_000f64) as u64);
        let dist = dist
            .iter()
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<(u32, f64)>>();
        
        info!("Best results weighted: {:?}", &dist[0..10.min(dist.len())]);

        let base = dijkstra_hops(4200000000, &result, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>();
        for i in 0..50.min(dist.len()) {
            println!("hopweight:{},{}", dist[i].0, dist[i].1);
            // Local effect
            let (before, after, count) = calculate_effect_weighted(&base, &dijkstra_hops(dist[i].0, &result, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>(), &weights);
            println!(
                "hopweightcompare:{},{},{},{}",
                dist[i].0, before, after, count
            );
        }
    }

    // Limited movement by steps
    for max_hops in 1..5
    {
        let base = dijkstra_hops(4200000000, &result, asn);
        let base_dist = base.iter().map(|(_, y)| y).sum::<u32>();
        //let max_hops = 0;
        let mut dist = Vec::new();
        for rasn in result.keys() {if *rasn != 1200 {continue;}
            let r = dijkstra_hops_limited(*rasn, max_hops, &result, &base, asn);
            let value = r.iter().map(|(_, y)| y).sum::<u32>();
            dist.push((*rasn, value));
        }
        dist.sort_by_key(|(_, y)| *y);
        let dist = dist
            .iter()
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<(u32, u32)>>();
        info!(
            "Limited movement by {}, from {}, best results: {:?}",
            max_hops,
            base_dist,
            &dist[0..10.min(dist.len())]
        );

        let tmpbase = base.iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>();
        for i in 0..50.min(dist.len()) {
            println!("limitedraw{}:{},{}", max_hops, dist[i].0, dist[i].1);
            // Local effect
            let (before, after, count) = calculate_effect(&tmpbase, &dijkstra_hops_limited(dist[i].0, max_hops, &result, &base, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>());
            println!(
                "limitedrawcompare{}:{},{},{},{}",
                max_hops, dist[i].0, before, after, count
            );
        }
    }

    // Limited movement by step weighted
    for max_hops in 1..5
    {
        let base = dijkstra_hops(4200000000, &result, asn);
        let base_dist = base
            .iter()
            .map(|(x, y)| (*y as f64) * *weights.get(x).unwrap_or(&0f64))
            .sum::<f64>();
        let mut dist = Vec::new();
        //let max_hops = 0;
        for rasn in result.keys() {if *rasn != 1200 {continue;}
            let mut sumweight = 0f64;
            let r = dijkstra_hops_limited(*rasn, max_hops, &result, &base, asn);
            let value = r
                .iter()
                .map(|(x, y)| {
                    let w = *weights.get(x).unwrap_or(&0f64);
                    sumweight += w;
                    (*y as f64) * w
                })
                .sum::<f64>();
            dist.push((*rasn, value/sumweight));
        }

        dist.sort_by_key(|(_, y)| (*y * 100_000f64) as u64);
        let dist = dist
            .iter()
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<(u32, f64)>>();
        info!(
            "Limited movement by {} weighted, from {}, best results: {:?}",
            max_hops,
            base_dist,
            &dist[0..10.min(dist.len())]
        );

        let tmpbase = base.iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>();
        for i in 0..50.min(dist.len()) {
            println!("hopweight{}:{},{}", max_hops, dist[i].0, dist[i].1);
            // Local effect
            let (before, after, count) = calculate_effect_weighted(&tmpbase,
                &dijkstra_hops_limited(dist[i].0, max_hops, &result, &base, asn).iter().map(|(x,y)| (*x,*y as f32)).collect::<HashMap<u32, f32>>(),
                &weights
            );
            println!(
                "hopweightcompare{}:{},{},{},{}",
                max_hops, dist[i].0, before, after, count
            );
        }
    }
}

pub fn dijkstra_hops(start: u32, graph: &HashMap<u32, HashSet<u32>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> HashMap<u32, u32> {
    let mut result: HashMap<u32, u32> = HashMap::new();
    let mut heap = BinaryHeap::new(); // Note: This is a max heap

    result.insert(start, 1);
    heap.push(DijkstraStateHop {
        asn: start,
        distance: 1,
    });

    for (_, v) in get_locations_asn(&asn) {
        for asn in v {
            heap.push(DijkstraStateHop {
                asn: asn,
                distance: 1,
            });
            result.insert(asn, 1);
        }
    }

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

fn dijkstra_hops_limited(
    start: u32,
    max_hops: u32,
    graph: &HashMap<u32, HashSet<u32>>,
    base: &HashMap<u32, u32>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
) -> HashMap<u32, u32> {
    let mut result: HashMap<u32, u32> = base.clone();
    let mut heap = BinaryHeap::new(); // Note: This is a max heap

    if result.get(&start).unwrap_or(&std::u32::MAX) > &1 {
        result.insert(start, 1);
        heap.push(DijkstraStateHop {
            asn: start,
            distance: 1,
        });
    }

    for (_, v) in get_locations_asn(&asn) {
        for asn in v {
            heap.push(DijkstraStateHop {
                asn: asn,
                distance: 1,
            });
            result.insert(asn, 1);
        }
    }

    while let Some(DijkstraStateHop { asn, distance }) = heap.pop() {
        // dont exceed the max distance
        if distance >= max_hops {
            continue;
        }
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

fn run_estimator_weighted(asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let mut graph = load_graph(&asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph, asn);

    let weights = load_weights_asn(
        &graph.iter().map(|(x, _)| *x).collect::<HashSet<u32>>(),
        asn,
    );
    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();

    let mut results = Vec::new();
    for rasn in keys {
        let mut total = 0f64;
        let res = dijkstra(rasn, &graph, asn);
        let sum = res
            .iter()
            .map(|(x, y)| {
                let weight = *weights.get(x).unwrap_or(&0f64);
                total += weight;
                weight * (*y as f64)
            }).sum::<f64>();
        results.push((rasn, sum / total));
        if results.len() % 100 == 0 {
            debug!("{}", results.len());
        }
    }

    let base = dijkstra(64513, &graph, asn);
    results.sort_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap_or(Ordering::Equal));
    for i in 0..50.min(results.len()) {
        println!("weightedminimal:{},{}", results[i].0, results[i].1);
        // Local effect
        let (before, after, count) =
            calculate_effect_weighted(&base, &dijkstra(results[i].0, &graph, asn), &weights);
        println!(
            "rawminimalcompare:{},{},{},{}",
            results[i].0, before, after, count
        );
    }

    let mut baset = 0f64;
    let base = dijkstra(64512, &graph, asn)
        .iter()
        .map(|(x, y)| {
            let weight = *weights.get(x).unwrap_or(&0f64);
            baset += weight;
            weight * (*y as f64)
        }).sum::<f64>()
        / baset;
    info!(
        "First minimals weighted (base {}): {:?}",
        base,
        &results[0..(10.min(results.len()))]
    );
    println!("weightedminimalbase:{}", base);
}

fn calculate_effect_weighted(
    base: &HashMap<u32, f32>,
    result: &HashMap<u32, f32>,
    weights: &HashMap<u32, f64>,
) -> (f32, f32, u32) {
    let mut before = 0f64;
    let mut after = 0f64;
    let mut count = 0;
    let mut sumweights = 0f64;
    for (asn, ms) in result.iter() {
        if let Some(r) = base.get(asn) {
            if !almost_equal(*ms, *r) {
                let w = *weights.get(asn).unwrap_or(&0f64);
                count += 1;
                after += *ms as f64 * w;
                before += *r as f64 * w;
                sumweights += w;
            }
        }
    }

    return (
        (before / sumweights) as f32,
        (after / sumweights) as f32,
        count,
    );
}

/// Calculate the difference between the hashmaps, returning (valuebefore, valueafter, count)
fn calculate_effect(base: &HashMap<u32, f32>, result: &HashMap<u32, f32>) -> (f32, f32, u32) {
    let mut before = 0f32;
    let mut after = 0f32;
    let mut count = 0;
    for (asn, ms) in result.iter() {
        if let Some(r) = base.get(asn) {
            if !almost_equal(*ms, *r) {
                count += 1;
                after += ms;
                before += r;
                println!("changeasn:{}", asn);
            }
        }
    }
    trace!(
        "{} from {} (count: {}, {} from {})",
        after / count as f32,
        before / count as f32,
        count,
        after,
        before
    );
    return (before / count as f32, after / count as f32, count);
}

fn run_estimator(asnpath: &String) {
    let asn = &load_asn(&asnpath);
    let mut graph = load_graph(&asn);
    fill_reverse_graph(&mut graph);
    filter_disconnected(2914, &mut graph, asn);

    let mut keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    keys.sort();
    info!("ASN count: {}", keys.len());

    {
        let mut results = Vec::new();
        for rasn in &keys {if *rasn != 1200 {continue;}
            let sum = dijkstra_sum_ms(*rasn, &graph, asn);
            results.push((*rasn, sum / graph.len() as f32));
            if results.len() % 100 == 0 {
                debug!("{}", results.len());
            }
        }

        results.sort_by(|(_, x), (_, y)| x.partial_cmp(y).unwrap_or(Ordering::Equal));
        let base = dijkstra(64513, &graph, asn);
        info!(
            "First minimals (base: {}): {:?}",
            dijkstra_sum_ms(64513, &graph, asn) / graph.len() as f32,
            &results[0..(10.min(results.len()))]
        );
        println!(
            "rawminimalbase:{}",
            dijkstra_sum_ms(64513, &graph, asn) / graph.len() as f32
        );
        for i in 0..50.min(results.len()) {
            println!("rawminimal:{},{}", results[i].0, results[i].1);
            // Local effect
            let (before, after, count) = calculate_effect(&base, &dijkstra(results[i].0, &graph, asn));
            println!(
                "rawminimalcompare:{},{},{},{}",
                results[i].0, before, after, count
            );
        }
    }

    // Place with the most effect
    {
        let mut results = Vec::new();
        let base = dijkstra(64513, &graph, asn);
        for rasn in &keys {if *rasn != 1200 {continue;}
            let res = dijkstra(*rasn, &graph, asn);
            let mut count = 0;
            for (asn, ms) in &base {
                if let Some(r) = res.get(&asn) {
                    if !almost_equal(*r, *ms) {
                        count += 1;
                    }
                }
            }

            results.push((rasn, count));
            if results.len() % 100 == 0 {
                debug!("{}", results.len());
            }
        }
        results.sort_by(|(_, x), (_, y)| y.partial_cmp(x).unwrap_or(Ordering::Equal));
        for i in 0..50.min(results.len()) {
            let (before, after, count) = calculate_effect(&base, &dijkstra(*results[i].0, &graph, asn));
            println!(
                "rawareamaximal:{},{},{},{}",
                results[i].0, before, after, count
            );
        }
    }
}

fn dijkstra_sum_ms(start: u32, graph: &HashMap<u32, HashMap<u32, f32>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> f32 {
    // Naive implementation, use dijstra to populate.
    let r = dijkstra(start, graph, asn).iter().map(|(_, y)| *y).sum::<f32>();
    return r;
}

// Calculate the dijkstra distance graph
fn dijkstra(start: u32, graph: &HashMap<u32, HashMap<u32, f32>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> HashMap<u32, f32> {
    const BASE_DISTANCE: f32 = 10f32; // Base latency to connect to the given asn
    let mut result: HashMap<u32, f32> = HashMap::new();
    let mut heap = BinaryHeap::new(); // Note: This is a max heap
    result.insert(start, BASE_DISTANCE);
    heap.push(DijkstraState {
        asn: start,
        distance: BASE_DISTANCE,
    });
    
    for (_, v) in get_locations_asn(&asn) {
        for asn in v {
            heap.push(DijkstraState {
                asn: asn,
                distance: 0f32,
            });
            result.insert(asn, 0f32);
        }
    }

    while let Some(DijkstraState { asn, distance }) = heap.pop() {
        if distance > *result.get(&asn).unwrap_or(&std::f32::MAX) {
            continue;
        }

        for nodes in graph.get(&asn) {
            for (target, &targetms) in nodes.iter() {
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
fn load_graph(_asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) -> HashMap<u32, HashMap<u32, f32>> {
    let mut result: HashMap<u32, HashMap<u32, Vec<f32>>> = HashMap::new();
    const MAX_MS: f32 = 210f32;

    let paths = vec!["result/routes.v2.1.csv", "result/routes.v2.2.csv"];
    for path in paths.iter() {
        let f = File::open(path).unwrap();

        for line in BufReader::new(f).lines() {
            let line = line.unwrap();
            let data = line.split(",").collect::<Vec<&str>>();
            result
                .entry(data[0].parse().unwrap())
                .or_insert(HashMap::new())
                .entry(data[1].parse().unwrap())
                .or_insert(Vec::new())
                .extend(data[2..].iter().map(|x| x.parse::<f32>().unwrap()));
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
fn fill_reverse_graph(graph: &mut HashMap<u32, HashMap<u32, f32>>) {
    let cp = graph.clone();

    for (a, v) in cp {
        for (b, ms) in v {
            graph
                .entry(a)
                .or_insert(HashMap::new())
                .entry(b)
                .or_insert(ms);
        }
    }
}

/// Remove disconnected nodes from a base AS
fn filter_disconnected(base: u32, graph: &mut HashMap<u32, HashMap<u32, f32>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    let keys = graph.iter().map(|(x, _)| *x).collect::<Vec<u32>>();
    let founded_keys = dijkstra(base, graph, asn)
        .iter()
        .map(|(x, _)| *x)
        .collect::<HashSet<u32>>();

    for k in keys {
        if !founded_keys.contains(&k) {
            trace!("Removing disconnected {}", k);
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
    let path = "./data/ripe/traceroute-2018-12-06T0000.bz2";

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

        for i in 0..(route_order.len().saturating_sub(1)) {
            let r0 = route.get(&route_order[i]).unwrap();
            let r1 = route.get(&route_order[i + 1]).unwrap();
            let rtt0: f32 = r0.iter().sum::<f32>() / r0.len() as f32;
            let rtt1: f32 = r1.iter().sum::<f32>() / r1.len() as f32;
            let diff = rtt1 - rtt0;

            if diff > 0f32 {
                table
                    .entry(route_order[i])
                    .or_insert(HashMap::new())
                    .entry(route_order[i + 1])
                    .or_insert(Vec::new())
                    .push(diff);
            }
        }
    }

    info!("Routes extracted: {:?} routes", table.len());
    for (a1, v) in table.iter() {
        for (a2, lat) in v {
            println!(
                "{},{},{}",
                a1,
                a2,
                lat.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            );
        }
    }
}

/// Load a base distance matrix to calculate the distances.

fn load_anycast_graph(
    out_graph: &mut HashMap<u32, HashMap<u32, Vec<f32>>>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
) {
    let paths = get_all_traces();

    for path in paths.iter() {
        let mut table = HashMap::new();
        let graph = load_data(&path.to_string());
        for (_, measurement) in graph.iter() {
            let data = &measurement.data;
            let mut route = Vec::new();
            let mut route_data = HashMap::new();
            for item in data.iter() {
                if let Some(packet) = item {
                    if let Some((_, _, asn)) = asn.longest_match(packet.dst) {
                        for asn in asn {
                            route_data
                                .entry(*asn)
                                .or_insert(Vec::new())
                                .push(packet.ms as f32);
                            if !route.contains(asn) {
                                route.push(*asn);
                            }
                        }
                    }
                }
            }

            for i in 0..(route.len().saturating_sub(1)) {
                let r0 = route_data.get(&route[i]).unwrap();
                let r1 = route_data.get(&route[i + 1]).unwrap();
                let rtt0: f32 = r0.iter().sum::<f32>() / r0.len() as f32;
                let rtt1: f32 = r1.iter().sum::<f32>() / r1.len() as f32;
                let diff = rtt1 - rtt0;

                if diff > 0f32 {
                    table
                        .entry(route[i])
                        .or_insert(HashMap::new())
                        .entry(route[i + 1])
                        .or_insert(Vec::new())
                        .push(diff);
                }
            }
        }
        for (a, v) in table {
            for (b, latency) in v.iter() {
                out_graph
                    .entry(a)
                    .or_insert(HashMap::new())
                    .entry(*b)
                    .or_insert(Vec::new())
                    .extend(latency);
            }
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

fn almost_equal(a: f32, b: f32) -> bool {
    const THRESHOLD: f32 = 0.00001;
    return (a - b).abs() < THRESHOLD;
}
