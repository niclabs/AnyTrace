extern crate flate2;
extern crate treebitmap;

use self::flate2::read::GzDecoder;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

use self::treebitmap::IpLookupTable;

use std::u32;

/// Normalize the ip address, converting it in a /24 network address
/// by removing the list 8 bits
pub fn ip_normalize(address: Ipv4Addr) -> Ipv4Addr {
    return Ipv4Addr::from(u32::from(address) & 0xFFFFFF00);
}

#[derive(Debug, Clone)]
pub struct Data {
    pub dst: Ipv4Addr,
    pub hops: u8,
    pub ms: u64,
}

#[derive(Debug, Clone)]
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

pub fn load_data(tracepath: &String) -> HashMap<Ipv4Addr, Measurement> {
    debug!("Loading data from {}", tracepath);
    let mut map: HashMap<Ipv4Addr, Measurement> = HashMap::new();
    let f = File::open(tracepath).unwrap();

    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        let data = line.split(",").collect::<Vec<&str>>();
        let real_dst: Ipv4Addr = data[0].parse().unwrap();
        let dst: Ipv4Addr = data[1].parse().unwrap();
        let hops: u8 = data[2].parse().unwrap();
        let ms: u64 = data[3].parse().unwrap();

        // Filter private ip addresses
        if dst.is_private() {
            continue;
        }

        match map.entry(real_dst) {
            // TODO: Revisar hops/orden
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

    let mut uniq = HashSet::new();
    for (ip, m) in map.iter() {
        uniq.insert(*ip);
        for i in m.data.iter() {
            if let Some(x) = i {
                uniq.insert(x.dst);
            }
        }
    }
    info!("Uniq prefixes: {}", uniq.len());
    return map;
}

/// Load the area of service, return the /24 addresses and a vector with the milliseconds
pub fn load_area(tracepath: &String) -> HashMap<Ipv4Addr, Vec<u64>> {
    let f = File::open(tracepath).unwrap();
    let mut result = HashMap::new();

    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        let data = line.split(",").collect::<Vec<&str>>();
        let _real_dst: Ipv4Addr = data[0].parse().unwrap();
        let dst: Ipv4Addr = data[1].parse().unwrap();
        let _hops: u8 = data[2].parse().unwrap();
        let ms: u64 = data[3].parse().unwrap();

        if dst.is_private() {
            continue;
        }

        result
            .entry(ip_normalize(dst))
            .or_insert(Vec::new())
            .push(ms);
    }

    return result;
}

pub fn load_asn(asnpath: &String) -> IpLookupTable<Ipv4Addr, Vec<u32>> {
    debug!("Loading asn from {}", asnpath);
    let mut tbl: IpLookupTable<Ipv4Addr, Vec<u32>> = IpLookupTable::new();
    let f = File::open(asnpath).unwrap();
    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        if line.contains("{") {
            let count = line.chars().filter(|x| x == &'{').count();
            if count > 1 {
                panic!("ASN with multiple AS_SETS not handled ({})", line);
            }
            let subline = line.split("{").skip(1).next().unwrap();
            let set = subline.split("}").next().unwrap();
            let set = set.split(",").collect::<HashSet<&str>>();
            if set.len() > 1 {
                //println!("{} {:?}", line, set);
            }
        }
        let line = line.replace("{", "").replace("}", "");
        let data = line.split(",").collect::<Vec<&str>>();
        let network = data[0].split("/").collect::<Vec<&str>>();
        // store something about the length, or calculate manually.
        if let Ok(ip) = network[0].parse::<Ipv4Addr>() {
            for asn in data[1..].iter() {
                tbl.insert(ip, network[1].parse().unwrap(), vec![asn.parse().unwrap()]);
                break;
            }
        }
    }
    return tbl;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct GeoLoc {
    pub continent: String,
    pub country: String,
}

pub fn generate_geotable() -> IpLookupTable<Ipv4Addr, GeoLoc> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let mut geocode = HashMap::new();
    let f = File::open("data/GeoLite2-Country-Locations-en.csv").unwrap();
    for line in BufReader::new(f).lines().skip(1) {
        let data = line
            .unwrap()
            .split(",")
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let geoid: u32 = data[0].parse().unwrap();
        geocode.insert(
            geoid,
            GeoLoc {
                continent: data[2].to_string(),
                country: data[4].to_string(),
            },
        );
    }

    let mut tbl: IpLookupTable<Ipv4Addr, GeoLoc> = IpLookupTable::new();
    let f = File::open("data/GeoLite2-Country-Blocks-IPv4.csv").unwrap();
    for line in BufReader::new(f).lines().skip(1) {
        let data = line
            .unwrap()
            .split(",")
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let network = data[0].split("/").collect::<Vec<&str>>();
        let ip: Ipv4Addr = network[0].parse().unwrap();
        let netmask: u32 = network[1].parse().unwrap();
        let geoid: u32 = data[1].parse().unwrap_or(0);
        tbl.insert(
            ip,
            netmask,
            geocode
                .get(&geoid)
                .unwrap_or(&GeoLoc {
                    continent: "".to_string(),
                    country: "".to_string(),
                }).clone(),
        );
    }

    return tbl;
}

/*pub fn asn_geoloc(asnpath: &String) -> HashMap<u32, HashSet<GeoLoc>> {
    let mut result: HashMap<u32, HashSet<GeoLoc>> = HashMap::new();
    let geo = generate_geotable();
    let f = File::open(asnpath).unwrap();
    for line in BufReader::new(f).lines() {
        let line = line.unwrap();
        let line = line.replace("{", "").replace("}", "");
        let data = line.split(",").collect::<Vec<&str>>();
        let network = data[0].split("/").collect::<Vec<&str>>();

        if let Ok(ip) = network[0].parse::<Ipv4Addr>() {
            for asn in data[1..].iter() {
                if let Some((_, _, loc)) = geo.longest_match(ip) {
                    let entry = result
                        .entry(asn.parse::<u32>().unwrap())
                        .or_insert(HashSet::new());
                    entry.insert(loc.clone());
                }
                // TODO: Only use the top countries of the AS
            }
        }
    }
    return result;
}*/

#[derive(Debug)]
pub struct CityLoc {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: u32,
}

pub fn generate_citytable() -> IpLookupTable<Ipv4Addr, CityLoc> {
    debug!("Loading citytable");
    let mut tbl: IpLookupTable<Ipv4Addr, CityLoc> = IpLookupTable::new();
    let f = File::open("data/GeoLite2-City-Blocks-IPv4.csv").unwrap();
    for line in BufReader::new(f).lines().skip(1) {
        let data = line
            .unwrap()
            .split(",")
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        if data[7] == "" || data[8] == "" || data[9] == "" {
            continue;
        }

        let network = data[0].split("/").collect::<Vec<&str>>();
        let ip: Ipv4Addr = network[0].parse().unwrap();
        let netmask: u32 = network[1].parse().unwrap();
        let latitude: f64 = data[7].parse().unwrap();
        let longitude: f64 = data[8].parse().unwrap();
        let accuracy: u32 = data[9].parse().unwrap();
        tbl.insert(
            ip,
            netmask,
            CityLoc {
                latitude: latitude,
                longitude: longitude,
                accuracy: accuracy,
            },
        );
    }
    return tbl;
}

pub fn load_weights_asn(
    filter: &HashSet<u32>,
    asn: &IpLookupTable<Ipv4Addr, Vec<u32>>,
) -> HashMap<u32, f64> {
    let weights = load_weights_lambda(|_| true);
    let mut result = HashMap::new();
    for (ip, w) in weights {
        if let Some((_, _, asn)) = asn.longest_match(ip) {
            for asn in asn {
                if filter.contains(&asn) {
                    *result.entry(*asn).or_insert(0f64) += w;
                }
            }
        }
    }

    return result;
    /*    // Normalize
    let normalized = result
        .iter()
        .map(|(x, y)| (*x, (*y as f64) / sum))
        .collect::<HashMap<u32, f64>>();
    {
        let mut count = normalized.iter().collect::<Vec<(&u32, &f64)>>();
        count.sort_by_key(|(_, y)| (*y * 100000f64) as u64);
        count.reverse();
        info!("ASN Most weight table: {:?}", &count[0..10.min(count.len())]);
    }
    return normalized;*/
}

fn load_weights_lambda<F>(filter: F) -> HashMap<Ipv4Addr, f64>
where
    F: Fn(&Ipv4Addr) -> bool,
{
    let captures = vec![
        /*
            "data/merced.gz",
            "data/captures/amsterdam.gz",
            "data/captures/elsegundo.gz",
            "data/captures/monterreya.gz",
            "data/captures/redwood.gz",
            "data/captures/buenosaires.gz",
            "data/captures/lima.gz",
            "data/captures/praga.gz",
            "data/captures/tokio.gz",*/
        "data/capture/saopaulo.gz",
        "data/capture/merced.gz",
        "data/capture/tucapel.gz",
        "data/captures/redwood.gz",
    ];
    let mut result = HashMap::new();
    for path in captures {
        let f = File::open(path).unwrap();
        let zip = GzDecoder::new(f);

        for line in BufReader::new(zip).lines() {
            let data = line.unwrap();
            let r = data.split("\t").collect::<Vec<&str>>();
            let ip: Ipv4Addr = ip_normalize(r[1].parse().unwrap());
            if filter(&ip) {
                *result.entry(ip).or_insert(0f64) += 1f64;
            }
        }
    }

    return result;
}

/// Load the weights from dump
pub fn load_weights(filter: &HashMap<Ipv4Addr, Vec<u64>>) -> HashMap<Ipv4Addr, f64> {
    return load_weights_lambda(|x| filter.contains_key(x));
}
