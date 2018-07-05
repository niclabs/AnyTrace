mod reader;
mod writer;

use self::reader::IcmpReader;
use self::writer::IcmpWriter;

use std::net::Ipv4Addr;

pub struct IcmpHandler {
    reader: IcmpReader,
    writer: IcmpWriter,
}

impl IcmpHandler {
    pub fn new(localip: &str) -> IcmpHandler {
        let local : Ipv4Addr = localip.parse().unwrap();
        let (reader, writer) = IcmpReader::new(local);
        return IcmpHandler {
            reader: reader,
            writer: writer,
        }
    }

    pub fn run(&mut self) {
        self.writer.send_icmp();
        self.reader.run();
    }
}