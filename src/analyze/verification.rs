extern crate serde_derive;
extern crate serde_json;

use analyze::helper::{ip_normalize, load_area};

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

pub fn verify() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: <traces.csv> <capture.json>");
    }
    let tracepath = arguments[2].clone();
    let capture = arguments[3].clone();

    let (capture, assigned) = load_capture(&capture);
    let area = load_area(&tracepath);
    verify_data(&area, &capture);
    check_ping(assigned);
    //check_latency_distance(&area, assigned);
}

#[derive(serde_derive::Deserialize, Debug)]
struct DnsMeasurement {
    //dst_addr: Ipv4Addr,
    from: Ipv4Addr,
    result: Option<DnsResult>,
    prb_id: u32,
}

#[derive(serde_derive::Deserialize, Debug)]
struct DnsResult {
    answers: Option<Vec<DnsAnswer>>,
}

#[derive(serde_derive::Deserialize, Debug)]
#[allow(non_snake_case)]
struct DnsAnswer {
    RDATA: Vec<String>,
}

fn load_capture(path: &String) -> (HashMap<Ipv4Addr, String>, HashMap<u32, String>) {
    let f = File::open(path).unwrap();
    let mut mapping = HashMap::new();
    let locations = vec![
        ("saopaulo", "200.160.0.214".parse::<Ipv4Addr>().unwrap()),
        ("amsterdam", "74.80.109.104".parse::<Ipv4Addr>().unwrap()),
        ("praga", "217.31.202.71".parse::<Ipv4Addr>().unwrap()),
        ("merced", "200.1.123.37".parse::<Ipv4Addr>().unwrap()),
        ("tucapel", "190.153.177.154".parse::<Ipv4Addr>().unwrap()),
        ("arica", "170.79.233.58".parse::<Ipv4Addr>().unwrap()),
        ("elsegundo", "192.0.33.136".parse::<Ipv4Addr>().unwrap()),
        ("monterrey", "200.94.183.155".parse::<Ipv4Addr>().unwrap()),
    ].iter()
    .map(|(x, y)| (*y, *x))
    .collect::<HashMap<Ipv4Addr, &str>>();

    let mut count = 0;
    let mut assigned = HashMap::new();
    for line in BufReader::new(f).lines() {
        let data: Vec<DnsMeasurement> = serde_json::from_str(&line.unwrap()).unwrap();
        count += data.len();
        for item in data {
            if let Some(result) = item.result {
                for answer in result.answers.unwrap_or(Vec::new()) {
                    for i in answer.RDATA {
                        for (_, node) in locations.iter() {
                            if i.contains(node) {
                                mapping.insert(ip_normalize(item.from), node.to_string());
                                assigned.insert(item.prb_id, node.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    info!("{}", count);

    return (mapping, assigned);
}

fn verify_data(area: &HashMap<Ipv4Addr, Vec<u64>>, dns: &HashMap<Ipv4Addr, String>) {
    let mut result = HashMap::new();
    for (ip, loc) in dns.iter() {
        if area.contains_key(&ip) {
            *result.entry(loc).or_insert(0) += 1;
        } else {
        }
    }
    info!("Area verification: {:?}", result);
}

fn check_ping(assigned: HashMap<u32, String>) {
    let locations = vec![
        ("saopaulo", "200.160.0.214".parse::<Ipv4Addr>().unwrap()),
        ("amsterdam", "74.80.109.104".parse::<Ipv4Addr>().unwrap()),
        ("praga", "217.31.202.71".parse::<Ipv4Addr>().unwrap()),
        ("merced", "200.1.123.37".parse::<Ipv4Addr>().unwrap()),
        ("tucapel", "190.153.177.154".parse::<Ipv4Addr>().unwrap()),
        ("arica", "170.79.233.58".parse::<Ipv4Addr>().unwrap()),
        ("elsegundo", "192.0.33.136".parse::<Ipv4Addr>().unwrap()),
        ("monterrey", "200.94.183.155".parse::<Ipv4Addr>().unwrap()),
    ].iter()
    .map(|(x, y)| (*y, *x))
    .collect::<HashMap<Ipv4Addr, &str>>();

    let measurements = vec![
        "18682923.json",
        "18682924.json",
        "18682925.json",
        "18682926.json",
        "18682927.json",
        "18682928.json",
        "18682929.json",
        "18682930.json",
    ];

    let mut latency = HashMap::new();
    for filename in measurements.iter() {
        let path = format!("data/ripe/measurement/{}", filename);
        let f = File::open(path).unwrap();
        for line in BufReader::new(f).lines() {
            let data: Vec<PingMeasurement> = serde_json::from_str(&line.unwrap()).unwrap();
            for m in data.iter() {
                if let Some(min) = m.min {
                    if let Some(origin) = locations.get(&m.dst_addr) {
                        latency
                            .entry(m.prb_id)
                            .or_insert(HashMap::new())
                            .insert(origin, min);
                    }
                }
            }
        }
    }

    // Check every probe, store in the format: assigned->should_be->Number
    let mut result: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for (prb, data) in latency.iter() {
        if let Some(assign) = assigned.get(prb) {
            let mut min = std::f64::MAX;
            let mut minloc = "";
            for (loc, rtt) in data.iter() {
                if *rtt < min {
                    min = *rtt;
                    minloc = loc;
                }
            }
            *result
                .entry(assign.to_string())
                .or_insert(HashMap::new())
                .entry(minloc.to_string())
                .or_insert(0) += 1;
        }
    }
    info!("{:?}", result);
    info!("{:?}", result.values().map(|x| x.values().sum::<u32>()).sum::<u32>());
}

fn check_latency_distance(_area: &HashMap<Ipv4Addr, Vec<u64>>, assigned: HashMap<u32, String>) {
    let locations = vec![
        ("saopaulo", "200.160.0.214".parse::<Ipv4Addr>().unwrap()),
        ("amsterdam", "74.80.109.104".parse::<Ipv4Addr>().unwrap()),
        ("praga", "217.31.202.71".parse::<Ipv4Addr>().unwrap()),
        ("merced", "200.1.123.37".parse::<Ipv4Addr>().unwrap()),
        ("tucapel", "190.153.177.154".parse::<Ipv4Addr>().unwrap()),
        ("arica", "170.79.233.58".parse::<Ipv4Addr>().unwrap()),
        ("elsegundo", "192.0.33.136".parse::<Ipv4Addr>().unwrap()),
        ("monterrey", "200.94.183.155".parse::<Ipv4Addr>().unwrap()),
    ].iter()
    .map(|(x, y)| (*y, *x))
    .collect::<HashMap<Ipv4Addr, &str>>();
    let measurements = vec![
        "18682923.json",
        "18682924.json",
        "18682925.json",
        "18682926.json",
        "18682927.json",
        "18682928.json",
        "18682929.json",
        "18682930.json",
    ];

    let mut latency = HashMap::new();
    for filename in measurements.iter() {
        let path = format!("data/ripe/measurement/{}", filename);
        let f = File::open(path).unwrap();
        for line in BufReader::new(f).lines() {
            let data: Vec<TraceMeasurement> = serde_json::from_str(&line.unwrap()).unwrap();
            for m in data.iter() {
                for item in m.result.iter() {
                    for result in item.result.iter() {
                        if let Some(origin) =
                            locations.get(&result.from.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)))
                        {
                            if let Some(rtt) = result.rtt {
                                latency
                                    .entry(m.prb_id)
                                    .or_insert(HashMap::new())
                                    .entry(origin)
                                    .or_insert(Vec::new())
                                    .push(rtt);
                            }
                        }
                    }
                }
            }
        }
    }

    // Check every probe, store in the format: assigned->should_be->Number
    let mut result: HashMap<String, HashMap<String, u32>> = HashMap::new();
    for (prb, data) in latency.iter() {
        if let Some(assign) = assigned.get(prb) {
            info!("{}; {:?}", assign, data);
            let mut min = std::f64::MAX;
            let mut minloc = "";
            for (loc, lat) in data {
                let rtt = lat[lat.len() / 2];
                if rtt < min {
                    min = rtt;
                    minloc = loc;
                }
            }
            *result
                .entry(assign.to_string())
                .or_insert(HashMap::new())
                .entry(minloc.to_string())
                .or_insert(0) += 1;
        }
    }
    info!("{:?}", result);
}

#[derive(serde_derive::Deserialize)]
struct TraceMeasurement {
    prb_id: u32,
    result: Vec<Trace>,
}

#[derive(serde_derive::Deserialize)]
struct Trace {
    result: Vec<TraceData>,
}

#[derive(serde_derive::Deserialize)]
struct TraceData {
    from: Option<Ipv4Addr>,
    rtt: Option<f64>,
}

#[derive(serde_derive::Deserialize)]
struct PingMeasurement {
    min: Option<f64>,
    prb_id: u32,
    dst_addr: Ipv4Addr,
}

