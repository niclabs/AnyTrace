use ping::PingMethod;
use ping::reader::PingReader;
use ping::writer::PingWriter;

use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;

pub struct PingHandler {
    pub reader: PingReader,
    pub writer: PingWriter,
}

impl PingHandler {
    /// Construct a new PingHandler.
    ///
    /// This will write and read the received packets asynchronously.
    /// The writting will be limited to `rate_limit` packet per second.
    pub fn new(localip: Ipv4Addr, method: PingMethod, rate_limit: u32) -> PingHandler {
        let (reader, writer) = Self::generate_transport(localip, method, rate_limit);
        return PingHandler {
            reader: reader,
            writer: writer,
        };
    }

    /// Construct the PingReader and PingWriter using the given local IPv4 Address.
    fn generate_transport(
        local: Ipv4Addr,
        method: PingMethod,
        rate_limit: u32,
    ) -> (PingReader, PingWriter) {
        // We use Icmp as transport for Icmp and Udp, as it only filter the received packets
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return (
            PingReader::new(rx, local),
            PingWriter::new(tx, local, method, rate_limit),
        );
    }

    /// Check the packet payload and get the timestamp
    pub fn get_packet_timestamp_ms(payload: &[u8], check_payload: bool) -> Result<u64, &str> {
        // The packet should be 10 bytes long
        if payload.len() < 10 {
            return Err("Payload is not of length 10");
        }

        // Check the payload key
        if check_payload && payload[8..10] != *PingWriter::get_payload_key() {
            return Err("Payload key invalid");
        }

        // Get the timestamp from the payload and convert it from Big Endian
        return Ok(u64::from_be(Self::array_to_u64(&payload[..8])));
    }

    fn array_to_u64(data: &[u8]) -> u64 {
        return data[7] as u64 | (data[6] as u64) << 8 | (data[5] as u64) << 16
            | (data[4] as u64) << 24 | (data[3] as u64) << 32
            | (data[2] as u64) << 40 | (data[1] as u64) << 48
            | (data[0] as u64) << 56;
    }
}
