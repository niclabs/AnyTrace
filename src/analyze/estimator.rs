extern crate bzip2;
extern crate serde_derive;
extern crate serde_json;
extern crate treebitmap;

use std::env;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::Ipv4Addr;

use self::bzip2::read::BzDecoder;
use self::treebitmap::IpLookupTable;
use analyze::helper::{ip_normalize, load_asn};

pub fn estimator() {
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 3 {
        panic!("Argments: <asn.csv>");
    }
    let asnpath = arguments[2].clone();

    let asn = load_asn(&asnpath);
    load_traceroute(&asn);
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

        let data: TracerouteMeasurement = serde_json::from_str(&line).unwrap_or_else(|x| panic!("{}", line));
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
            let r1 = route.get(&route_order[i+2]).unwrap();
            let rtt0: f32 = r0.iter().sum::<f32>() / r0.len() as f32;
            let rtt1: f32 = r1.iter().sum::<f32>() / r1.len() as f32;
            let diff = rtt1 - rtt0;

            if diff > 0f32 {
                table
                .entry(route_order[i])
                .or_insert(HashMap::new())
                .entry((route_order[i+1], route_order[i+2]))
                .or_insert(Vec::new())
                .push(diff);
            }
        }
    }
    info!("Routes extracted: {:?} routes", table.len());
    for (a1, v) in table.iter() {
        for ((a2, a3), lat) in v {
            println!("{},{},{},{}", a1, a2, a3, lat.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","));
        }
    }
}
