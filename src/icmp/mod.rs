mod reader;
mod writer;

use self::reader::IcmpReader;

use std::net::Ipv4Addr;

pub struct IcmpHandler {
    reader: IcmpReader
}

impl IcmpHandler {
    pub fn new(localip: &str) -> IcmpHandler {
        let local : Ipv4Addr = localip.parse().unwrap();
        return IcmpHandler {
            reader: IcmpReader::new(local),
        }
    }

    pub fn run(&mut self) {
        self.reader.run();
    }
}