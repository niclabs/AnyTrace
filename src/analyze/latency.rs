extern crate treebitmap;

use self::treebitmap::IpLookupTable;
use analyze::helper::{load_area, load_asn, load_weights};
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;

use std::u32;

pub fn check_latency() {
    // arica: (45.71.8.0, 0)
    // merced: (200.1.123.0, 0)
    // saopaulo: (200.160.0.0, 0)
    // tucapel: (190.153.177.0, 0)
    let arguments = env::args().collect::<Vec<String>>();
    if arguments.len() < 4 {
        panic!("Argments: <traces.csv> <asn.csv>");
    }
    let tracepath = arguments[2].clone();
    let asnpath = arguments[3].clone();

    let asn = load_asn(&asnpath);
    let area = load_area(&tracepath);

    bucket_data(&area);
    bucket_data_as(&area, &asn);
    bucket_data_weighted(&area);
}

fn bucket_data(area: &HashMap<Ipv4Addr, Vec<u64>>) {
    const BUCKETS_COUNT: usize = 50;
    let mut buckets = vec![0; BUCKETS_COUNT];
    for (_, data) in area.iter() {
        let mut tmp = data.clone();
        tmp.sort();
        let mid = {
            if tmp.len() % 2 == 1 {
                tmp[tmp.len() / 2]
            } else {
                (tmp[tmp.len() / 2 - 1] + tmp[tmp.len() / 2]) / 2
            }
        } as usize;

        buckets[(mid / 10).min(BUCKETS_COUNT - 1) as usize] += 1;

        if data.len() < 3 {
            continue;
        }

        let avg: f64 = tmp.iter().sum::<u64>() as f64 / tmp.len() as f64;
        let sum = tmp
            .iter()
            .fold(0f64, |sum, curr| sum + (*curr as f64 - avg).powf(2.) as f64);
        let _sd = (sum / (data.len() as f64 - 1.)).sqrt();
    }
    info!("Network Buckets: {:?}", buckets);
}

fn bucket_data_as(area: &HashMap<Ipv4Addr, Vec<u64>>, asn: &IpLookupTable<Ipv4Addr, Vec<u32>>) {
    const BUCKETS_COUNT: usize = 50;
    let mut join = HashMap::new();

    for (ip, data) in area.iter() {
        if let Some((_, _, asn)) = asn.longest_match(*ip) {
            for asn in asn {
                join.entry(asn).or_insert(Vec::<u64>::new()).extend(data);
            }
        }
    }

    let mut buckets = vec![0; BUCKETS_COUNT];
    for (_, data) in join.iter() {
        let mut tmp = data.clone();
        tmp.sort();
        let mid = {
            if tmp.len() % 2 == 1 {
                tmp[tmp.len() / 2]
            } else {
                (tmp[tmp.len() / 2 - 1] + tmp[tmp.len() / 2]) / 2
            }
        } as usize;

        buckets[(mid / 10).min(BUCKETS_COUNT - 1) as usize] += 1;

        if data.len() < 3 {
            continue;
        }

        let avg: f64 = tmp.iter().sum::<u64>() as f64 / tmp.len() as f64;
        let sum = tmp
            .iter()
            .fold(0f64, |sum, curr| sum + (*curr as f64 - avg).powf(2.) as f64);
        let _sd = (sum / (data.len() as f64 - 1.)).sqrt();
    }
    info!("AS Buckets: {:?}", buckets);
}

// Get the bucket weights by percentage
fn bucket_data_weighted(area: &HashMap<Ipv4Addr, Vec<u64>>) {
    let weight = load_weights(area);
    const BUCKETS_COUNT: usize = 50;
    let mut buckets = vec![0f64; BUCKETS_COUNT];
    for (ip, data) in area.iter() {
        let mut tmp = data.clone();
        tmp.sort();
        let mid = {
            if tmp.len() % 2 == 1 {
                tmp[tmp.len() / 2]
            } else {
                (tmp[tmp.len() / 2 - 1] + tmp[tmp.len() / 2]) / 2
            }
        } as usize;

        buckets[(mid / 10).min(BUCKETS_COUNT - 1) as usize] += weight.get(ip).unwrap_or(&0f64);

        if data.len() < 3 {
            continue;
        }

        let avg: f64 = tmp.iter().sum::<u64>() as f64 / tmp.len() as f64;
        let sum = tmp
            .iter()
            .fold(0f64, |sum, curr| sum + (*curr as f64 - avg).powf(2.) as f64);
        let _sd = (sum / (data.len() as f64 - 1.)).sqrt();
    }
    info!("Weighted Network Buckets: {:?}", buckets);
}
