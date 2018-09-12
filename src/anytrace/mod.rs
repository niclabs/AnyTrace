extern crate ping;
extern crate pnet;

use self::ping::{PingHandler, PingHandlerBuilder, PingMethod};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration};

use std::fs::File;
use std::io::{BufRead, BufReader};

mod helper;
use self::helper::{encode_id_seq,verify_packet,get_max_ttl,parse_icmp,get_ip_mask,time_from_epoch_ms};


#[derive(Debug)]
struct TraceConfiguration {
    source: Ipv4Addr,
    max_hop: u8,
    current_ttl: u8,
    traces: Vec<Option<Trace>>, //TODO: Check before overriding, as some ips (91.68.246.158) may send multiple packets
}

#[derive(Debug, Clone)]
struct Trace {
    router: Ipv4Addr,
    hops: u8,
    ms: u64,
}

impl TraceConfiguration {
    fn new(source: Ipv4Addr, max_hops: u8) -> TraceConfiguration {
        let opts = vec![Option::None; max_hops as usize];
        return TraceConfiguration {
            source: source,
            max_hop: max_hops,
            traces: opts,
            current_ttl: max_hops,
        };
    }
}

/// Start listening to ICMP packets, and generating a traceroute as new networks  start coming.
/// Packets can be verified by their identifier, sequence_address and origin
/// The process is as follow
///     Receive [A] EchoResponce
///         Check if address is not on HashMap:
///             Send EchoRequests to [A] with ttl of 1..n (DONT WRITE THE IP, as its not verified if its spoofing)
///             Add to the HashMap
///         else
///             Check the signature of the packet, to verify that is valid
///                 write
///     Receive [B] timeout
///         Check for original [A] address in HashMap
///             if id/seq are valid:
///                 Write the result, with the ttl (from the source packet) as the distance
///                     and the time diff.
///         If not on HashMap, goto [A] (This mean the packet is not verified, or came from
///             an invalid ip while sending the data)
///
/// Packet format: id: first 16 bits of the dst ip, seq: u8 of the dst ip, u8 ttl
/// Output to stdin (csv): original_target, measured_router, hops, ms
/// TODO: Add random offset/xor as a key of the packets, so we can differentiate which packets are ours and which are not
pub fn run(hitlist: &str, localip: &str, pps: u32) {
    let handler = PingHandlerBuilder::new()
        .localip(localip)
        .method(PingMethod::ICMP)
        .rate_limit(pps)
        .build();

    let mut mapping: HashMap<u32, TraceConfiguration> = HashMap::new();
    let file = File::open(hitlist).unwrap();
    let mut lines = BufReader::new(file).lines();
    let mut check: VecDeque<(u32, u64)> = VecDeque::new(); // (ip, nexttime)
    let mut seen = HashSet::new();
    println!("original_target, measured_router, hops, ms");
    loop {
        let mut end = true;
        for _ in 0..pps {
            if let Some(line) = lines.next() {
                if let Ok(ip) = line.unwrap().parse() {
                    let ip: Ipv4Addr = ip;
                    if !mapping.contains_key(&(u32::from(ip) & 0xFFFFFF00)) {
                        // We don't store the information, as this packet only verifies if
                        // the host is online, and not execute the tracerote
                        handler.writer.send(ip);
                        end = false;
                    }
                }
            }
        }
        if end && check.is_empty() {
            break;
        }

        // Get all ip addresses that we havent received timeout and send the next ttl
        // only if we havent see the /24
        let current_time = time_from_epoch_ms();
        while !check.is_empty() {
            let (ip, time) = check[0];
            if time < current_time {
                check.pop_front();
                if let Some(trace) = mapping.get_mut(&ip) {
                    // Extract next packet metadata and update trace
                    trace.current_ttl = trace.current_ttl.saturating_sub(1);
                    if trace.current_ttl >= 1 {
                        // Send the next packet
                        let (identifier, sequence) = encode_id_seq(ip, trace.current_ttl);
                        handler.writer.send_complete(
                            trace.source,
                            0,
                            0,
                            trace.current_ttl,
                            identifier,
                            sequence,
                        );

                        // Only insert if the next ttl is valid
                        if trace.current_ttl > 1 {
                            check.push_back((ip, time_from_epoch_ms() + 1 * 1000));
                        }
                    }
                } else {
                    panic!(
                        "IP Address {:?} in trace queue while not in `mapping`",
                        Ipv4Addr::from(ip)
                    );
                }
            } else {
                break;
            }
        }

        // TODO: Change rec_timeout break, as we arent counting packets that are not ours
        while let Ok(packet) = handler
            .reader
            .reader()
            .recv_timeout(Duration::from_millis(1_000))
        {
            match &packet.icmp {
                ping::Responce::Echo(icmp) => {
                    // Check if this is a new IP Address, only using his /24
                    let ip = u32::from(packet.source) & 0xFFFFFF00;
                    if mapping.contains_key(&ip) {
                        info!(
                            "Network {}/24 already seen ({}) (ttl: {}, dist: {})",
                            Ipv4Addr::from(ip),
                            packet.source,
                            packet.ttl,
                            get_max_ttl(&packet)
                        );
                        if let Ok(_) = PingHandler::verify_signature(&icmp.payload) {
                            if verify_packet(packet.source, icmp.identifier, icmp.sequence_number) {
                                // TODO (Optional): use the packet time instead of the calculated for better accuracy
                                update_trace_entry(
                                    &mut mapping,
                                    packet.source,
                                    packet.source,
                                    icmp.sequence_number as u8,
                                    packet.time_ms,
                                );
                            } else {
                                error!("Error verifying packet from {}", packet.source);
                            }
                        } else {
                            error!("Error verifying signature");
                        }
                    } else {
                        // New network, send the traceroute packets. There is no need to verify as
                        // We dont store the information of this packet.
                        info!("New Network {}/24, ttl: {}", Ipv4Addr::from(ip), packet.ttl);
                        mapping.insert(
                            ip,
                            TraceConfiguration::new(packet.source, get_max_ttl(&packet)),
                        );

                        // Send the max ttl and add it to the queue
                        let ttl = get_max_ttl(&packet);
                        let (identifier, sequence) = encode_id_seq(ip, ttl);
                        handler.writer.send_complete(
                            packet.source,
                            0,
                            0,
                            ttl as u8,
                            identifier,
                            sequence,
                        );
                        check.push_back((
                            get_ip_mask(packet.source),
                            time_from_epoch_ms() + 1 * 1000,
                        ));
                    }
                }
                ping::Responce::Timeout(icmp) => {
                    // The payload contains the EchoRequest packet + 64 bytes of payload if its over UDP or TCP
                    if let Ok((target, echo)) = parse_icmp(&icmp.payload) {
                        info!(
                            "Received timeout from ({:?}, {:?} => {})",
                            echo.identifier, echo.sequence_number, target
                        );
                        // Verify the packet
                        if verify_packet(target, echo.identifier, echo.sequence_number) {
                            let mut founded = false;
                            if let Some(trace) = mapping.get_mut(&get_ip_mask(target)) {
                                founded = true;
                                update_trace(
                                    trace,
                                    target,
                                    packet.source,
                                    echo.sequence_number as u8,
                                    packet.time_ms,
                                );
                                // Check if ip was already seen, and mark as done if the route has already been processed
                                if seen.contains(&packet.source) {
                                    // Only skip if the last hop is not the same ip address, as some use the same router for more than one hop
                                    let mut skip = false;
                                    if let Some(Some(upper)) = trace.traces.get(((echo.sequence_number as u8) as usize) + 1 - 1) {
                                        if upper.router == packet.source {
                                            skip = true;
                                        }
                                    }
                                    if !skip {
                                        debug!(
                                            "Already seen router timeout, skipping {}",
                                            packet.source
                                        );
                                        trace.current_ttl = 0;
                                    }
                                    continue;
                                }

                                // Add the router to the seen table, so we dont process it again
                                seen.insert(packet.source);
                            }
                            if founded {
                                // Mark the /24 of the router in the table, so we don't start new traces to the target
                                let netsrc = u32::from(packet.source) & 0xFFFFFF00;
                                match mapping.entry(netsrc) {
                                    Entry::Vacant(v) => {
                                        v.insert(TraceConfiguration::new(packet.source, 0));
                                    }
                                    Entry::Occupied(mut trace) => {
                                        // The router is already in the map, mark the trace as done
                                        trace.get_mut().current_ttl = 0;
                                    }
                                }
                            }
                        }
                    }
                }
                ping::Responce::Unreachable(icmp) => {
                    // This is received from the UDP ping
                    println!("{:?}", parse_icmp(&icmp.payload));
                    println!("Received unreachable for ({:?}, {:?})", icmp.icmp_type, icmp.icmp_code);
                }
                ping::Responce::LocalSendedEcho(target) => {
                    // Receive the locally written packets, and store the timestamp.
                    update_trace_entry(
                        &mut mapping,
                        *target,
                        Ipv4Addr::new(0, 0, 0, 0),
                        packet.ttl,
                        packet.time_ms,
                    );
                }
            }
        }
    }
}

/// Update the entry with the given information
fn update_trace_entry(
    mapping: &mut HashMap<u32, TraceConfiguration>,
    original_target: Ipv4Addr,
    packet_source: Ipv4Addr,
    ttl: u8,
    time_ms: u64,
) {
    let source_net = u32::from(original_target) & 0xFFFFFF00;
    if let Some(trace) = mapping.get_mut(&source_net) {
        update_trace(trace, original_target, packet_source, ttl, time_ms);
    }
}

/// Update the entry with the given information
fn update_trace(
    traceconf: &mut TraceConfiguration,
    original_target: Ipv4Addr,
    packet_source: Ipv4Addr,
    ttl: u8,
    time_ms: u64,
) {
    // get the index as ttl-1, making sure we dont overflow
    let index = ttl.saturating_sub(1);

    // This should always be set, as we do preallocation
    // Unless it is a router/middlebox, where we dont store the values.
    if let Some(trace) = traceconf.traces.get_mut(index as usize) {
        if let Some(measurement) = trace {
            // We have already setted the value before, calculate the time difference
            measurement.ms = u64::max(measurement.ms, time_ms) - u64::min(measurement.ms, time_ms);

            if measurement.router.is_unspecified() {
                measurement.router = packet_source;
            }
            println!(
                "{}, {}, {}, {}",
                original_target, measurement.router, measurement.hops, measurement.ms
            );
        } else {
            *trace = Some(Trace {
                router: packet_source,
                hops: ttl,
                ms: time_ms,
            });
        }
    }
}

