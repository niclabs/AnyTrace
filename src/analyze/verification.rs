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

    let capture = load_capture(&capture);
    let area = load_area(&tracepath);
    verify_data(&area, &capture);
}

#[derive(serde_derive::Deserialize, Debug)]
struct DnsMeasurement {
    //dst_addr: Ipv4Addr,
    from: Ipv4Addr,
    result: Option<DnsResult>,
}

#[derive(serde_derive::Deserialize, Debug)]
struct DnsResult {
    answers: Vec<DnsAnswer>,
}

#[derive(serde_derive::Deserialize, Debug)]
#[allow(non_snake_case)]
struct DnsAnswer {
    RDATA: Vec<String>,
}

fn load_capture(path: &String) -> HashMap<Ipv4Addr, String> {
    let f = File::open(path).unwrap();
    let mut mapping = HashMap::new();
    let nodes = vec![
        "saopaulo",
        "amsterdam",
        "praga",
        "merced",
        "tucapel",
        "arica",
        "elsegundo",
        "monterrey",
    ];

    for line in BufReader::new(f).lines() {
        let data: Vec<DnsMeasurement> = serde_json::from_str(&line.unwrap()).unwrap();
        for item in data {
            if let Some(result) = item.result {
                for answer in result.answers {
                    for i in answer.RDATA {
                        for node in &nodes {
                            if i.contains(node) {
                                mapping.insert(ip_normalize(item.from), node.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    return mapping;
}

fn verify_data(area: &HashMap<Ipv4Addr, Vec<u64>>, dns: &HashMap<Ipv4Addr, String>) {
    for (ip, loc) in dns.iter() {
        if area.contains_key(&ip) {
            info!("loc: {}; area: {:?}", loc, area.get(ip));
        }
    }
}
/*
#[derive(serde_derive::Deserialize)]
struct TraceMeasurement {
    dst_addr: Ipv4Addr,
    from: Ipv4Addr,
    result: Vec<Trace>
}

#[derive(serde_derive::Deserialize)]
struct Trace {
    hop: u8,
    result: Vec<TraceData>
}

#[derive(serde_derive::Deserialize)]
struct TraceData {
    from: Ipv4Addr,
    rtt: f64,
}
*/
