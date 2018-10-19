extern crate treebitmap;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::File;
use std::io::stdin;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

use self::treebitmap::IpLookupTable;

#[derive(Debug)]
pub struct Data {
    pub dst: Ipv4Addr,
    pub hops: u8,
    pub ms: u64,
}

#[derive(Debug)]
pub struct Measurement {
    pub data: Vec<Option<Data>>,
}

impl Measurement {
    fn new(capacity: usize) -> Measurement {
        let mut data = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            data.push(None);
        }
        return Measurement { data: data };
    }
}

pub fn load_data() -> HashMap<Ipv4Addr, Measurement> {
        let mut map: HashMap<Ipv4Addr, Measurement> = HashMap::new();
    let stdin = stdin();
    let stdin = stdin.lock();
    for line in stdin.lines() {
        let line = line.unwrap();
        let data = line.split(",").collect::<Vec<&str>>();
        let real_dst: Ipv4Addr = data[0].parse().unwrap();
        let dst: Ipv4Addr = data[1].parse().unwrap();
        let hops: u8 = data[2].parse().unwrap();
        let ms: u64 = data[3].parse().unwrap();

        match map.entry(real_dst) {
            Entry::Occupied(mut o) => {
                let m = o.get_mut();
                while m.data.len() <= hops.saturating_sub(1) as usize {
                    m.data.push(None)
                }
                m.data[hops.saturating_sub(1) as usize] = Some(Data {
                    dst: dst,
                    hops: hops,
                    ms: ms,
                });
            }
            Entry::Vacant(v) => {
                let m = v.insert(Measurement::new(hops as usize));
                m.data[hops.saturating_sub(1) as usize] = Some(Data {
                    dst: dst,
                    hops: hops,
                    ms: ms,
                });
            }
        }
    }
    return map;
}

pub fn load_asn() -> IpLookupTable<Ipv4Addr, Vec<u32>> {
    let mut tbl : IpLookupTable<Ipv4Addr, Vec<u32>> = IpLookupTable::new();
    let filename = "data/bgp.csv";
    let f = File::open(filename).unwrap();
    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        let line = line.replace("{", "").replace("}", "");
        let data = line.split(",").collect::<Vec<&str>>();
        let network = data[0].split("/").collect::<Vec<&str>>();
        // store something about the length, or calculate manually.
        if let Ok(ip) = network[0].parse::<Ipv4Addr>() {
            for asn in data[1..].iter() {
                tbl.insert(
                    ip,
                    network[1].parse().unwrap(),
                    vec!(asn.parse().unwrap()),
                );
                break;
            }
        }
    }
    return tbl;
}
