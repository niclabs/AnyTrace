use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::io::{BufRead, stdin};
use std::net::Ipv4Addr;

#[derive(Debug)]
struct Data {
    dst: Ipv4Addr,
    hops: u8,
    ms: u64,
    measured: bool,
}

#[derive(Debug)]
struct Measurement {
    data: Vec<Option<Data>>,
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

pub fn join_data(log_statistics: bool) {
    let mut map: HashMap<Ipv4Addr, Measurement> = HashMap::new();
    let stdin = stdin();
    let stdin = stdin.lock();
    for line in stdin.lines() {
        let line = line.unwrap();
        let data = line.split(", ").collect::<Vec<&str>>();
        let real_dst: Ipv4Addr = data[0].parse().unwrap();
        let dst: Ipv4Addr = data[1].parse().unwrap();
        let hops: u8 = data[2].parse().unwrap();
        let ms: u64 = data[3].parse().unwrap();

        match map.entry(real_dst) {
            Entry::Occupied(mut o) => {
                process_measurement(
                    o.get_mut(),
                    real_dst,
                    Data {
                        dst: dst,
                        hops: hops,
                        ms: ms,
                        measured: false,
                    },
                );
            }
            Entry::Vacant(v) => {
                let v = v.insert(Measurement::new(hops as usize));
                process_measurement(
                    v,
                    real_dst,
                    Data {
                        dst: dst,
                        hops: hops,
                        ms: ms,
                        measured: false,
                    },
                );
            }
        }
    }

    if log_statistics {
        let (mut matched, mut nomatch) = (0, 0);
        let mut net = HashSet::new();
        for (or, item) in map.iter() {
            net.insert(u32::from(*or) & 0xFFFFFF00);
            for k in &item.data {
                if let Some(d) = k {
                    net.insert(u32::from(d.dst) & 0xFFFFFF00);
                    if d.measured { 
                        matched += 1;
                    } else {
                        nomatch += 1;
                    }
                }
            }
        }
        
        //println!("{:?}", map);
        info!("Statistics");
        info!("len: {}", map.len());
        info!("Matched: {}, NoMatched: {}", matched, nomatch);
        info!("Networks: {}", net.len());
    }
}

fn process_measurement(m: &mut Measurement, origin: Ipv4Addr, data: Data) {
    let slice = &mut m.data[data.hops.saturating_sub(1) as usize];
    if let Some(slice) = slice {
        let identity = Ipv4Addr::new(0, 0, 0, 0);
        if !slice.measured {
            if slice.dst == identity {
                slice.dst = data.dst;
            }
            slice.measured = true;
            println!(
                "{},{},{},{}",
                origin,
                slice.dst,
                slice.hops,
                slice.ms.max(data.ms) - slice.ms.min(data.ms)
            );
        }
    } else {
        *slice = Some(data);
    }
}
