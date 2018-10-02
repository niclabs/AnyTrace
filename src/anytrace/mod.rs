extern crate ping;
extern crate pnet;

use self::pnet::packet::icmp::destination_unreachable::DestinationUnreachable;
use self::pnet::packet::icmp::echo_reply::EchoReply;
use self::pnet::packet::icmp::time_exceeded::TimeExceeded;

pub use self::ping::PingMethod;
use self::ping::{IcmpResponce, PingHandler, PingHandlerBuilder};

use std;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::time::Duration;

mod helper;
use self::helper::{encode_id_seq, get_ip_mask, get_max_ttl, parse_icmp, time_from_epoch_ms,
                   verify_packet};

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
    done: bool,
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

struct Anytrace {
    handler: PingHandler,
    mapping: HashMap<u32, TraceConfiguration>,
    check: VecDeque<(u32, u64)>,
    seen: HashSet<Ipv4Addr>,
    lines: std::io::Lines<std::io::BufReader<std::fs::File>>,
    pps: u32,
}

impl Anytrace {
    pub fn new(hitlist: &str, localip: &str, pps: u32, method: PingMethod) -> Anytrace {
        let handler = PingHandlerBuilder::new()
            .localip(localip)
            .method(method)
            .rate_limit(pps)
            .build();
        let file = File::open(hitlist).unwrap();
        return Anytrace {
            handler: handler,
            mapping: HashMap::new(),
            check: VecDeque::new(),
            seen: HashSet::new(),
            lines: BufReader::new(file).lines(),
            pps: pps,
        };
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
    pub fn run(&mut self) {
        println!("original_target, measured_router, hops, ms");
        loop {
            if self.check.len() < self.pps as usize * 5usize {
                let mut end = true;
                for _ in 0..self.pps*5 {
                    if let Some(line) = self.lines.next() {
                        if let Ok(ip) = line.unwrap().parse() {
                            let ip: Ipv4Addr = ip;
                            if !self.seen.contains(&Ipv4Addr::from(get_ip_mask(ip) | 0xFF)) {
                                // We don't store the information, as this packet only verifies if
                                // the host is online, and not execute the tracerote
                                self.handler.writer.send(ip);
                                end = false;
                            }
                        }
                    } else {
                        break;
                    }
                }
                if end && self.check.is_empty() {
                    break;
                }
            }

            // Get all ip addresses that we havent received timeout and send the next ttl
            // only if we havent see the /24
            let current_time = time_from_epoch_ms();
            while !self.check.is_empty() {
                let (ip, time) = self.check[0];
                if time < current_time {
                    self.check.pop_front();

                    let ttl = self.mapping.get(&ip).unwrap().current_ttl;
                    if ttl == 0 {
                        self.mapping.remove(&ip);
                        continue;
                    }

                    if let Some(trace) = self.mapping.get_mut(&ip) {
                        // Extract next packet metadata and update trace
                        trace.current_ttl = trace.current_ttl.saturating_sub(1);
                        if trace.current_ttl >= 1 {
                            // Send the next packet
                            let (identifier, sequence) = encode_id_seq(ip, trace.current_ttl);
                            self.handler.writer.send_complete(
                                trace.source,
                                identifier,
                                sequence,
                                trace.current_ttl,
                                identifier,
                                sequence,
                            );
                        }
                        // Queue the next update
                        self.check.push_back((ip, time_from_epoch_ms() + 1 * 1000));
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
            let mut last_update = time_from_epoch_ms();
            while let Ok(packet) = self.handler
                .reader
                .reader()
                .recv_timeout(Duration::from_millis(200))
            {
                let result = match &packet.icmp {
                    ping::Responce::Echo(icmp) => {
                        self.process_echo_responce(&packet, &icmp)
                    }
                    ping::Responce::Timeout(icmp) => {
                        self.process_timeout(&packet, &icmp)
                    }
                    ping::Responce::Unreachable(icmp) => {
                        self.process_unreachable(&packet, &icmp)
                    }
                    ping::Responce::LocalSendedEcho(target) => {
                        // Receive the locally written packets, and store the timestamp.
                        self.update_trace_entry(
                            *target,
                            Ipv4Addr::new(0, 0, 0, 0),
                            packet.ttl,
                            packet.time_ms,
                        )
                    }
                };

                if let Ok(_) = result {
                    last_update = time_from_epoch_ms();
                } else {
                    // We only loop for a max of 2 seconds after the last usable packet
                    if Duration::from_secs(2) > Duration::from_millis(time_from_epoch_ms()) - Duration::from_millis(last_update) {
                        //break;
                    }
                }
            }
        }
    }

    /// Process an ICMP echo responce
    fn process_echo_responce(&mut self, packet: &IcmpResponce, icmp: &EchoReply) -> Result<(),()> {
        // Check if this is a new IP Address, only using his /24
        let ip = u32::from(packet.source) & 0xFFFFFF00;
        if self.mapping.contains_key(&ip) {
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
                    return self.update_trace_entry(
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
            // Only process packets generated by our system
            if let Ok(_) = PingHandler::verify_signature(&icmp.payload) {
                return self.process_new_entry(&packet);
            }
        }
        return Err(());
    }

    fn process_timeout(&mut self, packet: &IcmpResponce, icmp: &TimeExceeded) -> Result<(), ()> {
        // The payload contains the EchoRequest packet + 64 bytes of payload if its over UDP or TCP
        info!("Received timeout from ({})", packet.source);
        if let Ok((target, id, seq)) = parse_icmp(&icmp.payload) {
            info!(
                "Received timeout from (id: {:?}, seq: {:?} => target: {})",
                id, seq, target
            );
            // Verify the packet
            if verify_packet(target, id, seq) {
                let mut founded = false;
                if let Some(trace) = self.mapping.get_mut(&get_ip_mask(target)) {
                    founded = true;
                    if let Ok(_) = update_trace_conf(trace, target, packet.source, seq as u8, packet.time_ms) {
                        // If the router is market as done, we don't need to check for skips
                        if trace.current_ttl == 0 {
                            return Ok(());
                        }

                        // Check if ip was already seen, and mark as done if the route has already been processed
                        if self.seen.contains(&packet.source) {
                            // Only skip if the last hop is not the same ip address, as some use the same router for more than one hop
                            let mut skip = true;
                            if let Some(Some(upper)) = trace.traces.get(((seq as u8) as usize) + 1 - 1)
                            {
                                if upper.router == packet.source {
                                    skip = false;
                                }
                            }
                            if skip {
                                debug!("Already seen router timeout, skipping {}", packet.source);
                                trace.current_ttl = 0;
                            }
                            return Ok(());
                        }

                        // Add the router to the seen table, so we dont process it again
                        self.seen.insert(packet.source);
                    }
                }
                if founded {
                    // Mark the /24 of the router in the table, so we don't start new traces to the target
                    let netsrc = get_ip_mask(packet.source);
                    self.seen.insert(Ipv4Addr::from(netsrc | 0xFF));
                    if let Some(trace) = self.mapping.get_mut(&netsrc) {
                        // If its another trace, set the current_ttl to 0 to stop it, as we have a common router
                        if target != packet.source {
                            // The router is already in the map, mark the trace as done
                            trace.current_ttl = 0;
                        }
                    }
                    return Ok(());
                }
            }
        }
        return Err(());
    }

    fn process_unreachable(&mut self, packet: &IcmpResponce, icmp: &DestinationUnreachable) -> Result<(), ()> {
        // This is received from the UDP ping. the payload contains the inner UDP request and first two bytes of payload
        // TODO: verify the packet without the signature to calculate the latency
        debug!(
            "Unreachable from {}, {:?}",
            packet.source,
            parse_icmp(&icmp.payload)
        );
        let ip = get_ip_mask(packet.source);
        if self.mapping.contains_key(&ip) {
            info!(
                "Network {}/24 already seen ({}) (ttl: {}, dist: {})",
                Ipv4Addr::from(ip),
                packet.source,
                packet.ttl,
                get_max_ttl(&packet)
            );

            if let Ok((_, id, seq)) = parse_icmp(&icmp.payload) {
                if verify_packet(packet.source, id, seq) {
                    return self.update_trace_entry(
                        packet.source,
                        packet.source,
                        seq as u8,
                        packet.time_ms,
                    );
                } else {
                    error!("Error verifying from {} {} {}", packet.source, id, seq);
                }
            } else {
                error!("Error parsing Unreachable from {}", packet.source);
            }
        } else {
            return self.process_new_entry(&packet);
        }
        return Err(());
    }

    /// Add a new entry to the mapping table and send the first ping packet
    /// You MUST verify that the ip is not in the mapping before calling this function, or it will override other calls
    fn process_new_entry(&mut self, packet: &IcmpResponce) -> Result<(), ()> {
        let ip = get_ip_mask(packet.source);
        // New network, send the traceroute packets. There is no need to verify as
        // We dont store the information of this packet.

        // If we have seen the network, discard it
        if self.seen.contains(&Ipv4Addr::from(ip | 0xff)) {
            debug!("New network {}/24 already seen, not processing", Ipv4Addr::from(ip));
            return Err(());
        }

        info!(
            "New Network {}/24, ttl: {}, starting dist: {}",
            Ipv4Addr::from(ip),
            packet.ttl,
            get_max_ttl(&packet)
        );
        self.mapping.insert(
            ip,
            TraceConfiguration::new(packet.source, get_max_ttl(&packet)),
        );

        // Send the max ttl and add it to the queue
        let ttl = get_max_ttl(&packet);
        let (identifier, sequence) = encode_id_seq(ip, ttl);
        self.handler
            .writer
            .send_complete(packet.source, 0, 0, ttl as u8, identifier, sequence);
        self.check
            .push_back((get_ip_mask(packet.source), time_from_epoch_ms() + 1 * 1000));
        return Ok(());
    }

    /// Update the entry with the given information
    fn update_trace_entry(
        &mut self,
        original_target: Ipv4Addr,
        packet_source: Ipv4Addr,
        ttl: u8,
        time_ms: u64,
    ) -> Result<(), ()>{
        let source_net = u32::from(original_target) & 0xFFFFFF00;
        if let Some(trace) = self.mapping.get_mut(&source_net) {
            return update_trace_conf(trace, original_target, packet_source, ttl, time_ms);
        }
        return Err(());
    }
}

/// Update the entry with the given information
fn update_trace_conf(
    traceconf: &mut TraceConfiguration,
    original_target: Ipv4Addr,
    packet_source: Ipv4Addr,
    ttl: u8,
    time_ms: u64,
) -> Result <(), ()> {
    // get the index as ttl-1, making sure we dont underflow
    let index = ttl.saturating_sub(1);

    // This should always be set, as we do preallocation
    // Unless it is a router/middlebox, where we dont store the values.
    if let Some(trace) = traceconf.traces.get_mut(index as usize) {
        if let Some(measurement) = trace {
            if !measurement.done {
                // We have already setted the value before, calculate the time difference
                measurement.ms = u64::max(measurement.ms, time_ms) - u64::min(measurement.ms, time_ms);

                if measurement.router.is_unspecified() {
                    measurement.router = packet_source;
                }
                println!(
                    "{}, {}, {}, {}",
                    original_target, measurement.router, measurement.hops, measurement.ms
                );

                // Mark the measurement as done, to prevent duplicated answers.
                measurement.done = true;
                return Ok(());
            } else {
                error!("Duplicated answer from origin_target: {}, router: {}", original_target, measurement.router);
            }
        } else {
            *trace = Some(Trace {
                router: packet_source,
                hops: ttl,
                ms: time_ms,
                done: false,
            });
            return Ok(());
        }
    }
    return Err(());
}

pub fn run(hitlist: &str, localip: &str, pps: u32, method: PingMethod) {
    Anytrace::new(hitlist, localip, pps, method).run();
}
