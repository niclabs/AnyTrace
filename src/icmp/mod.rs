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
        let target : Ipv4Addr = "172.30.65.176".parse().unwrap();
        for _ in 0..1000000 {
            self.writer.send_icmp(target);
        }
        println!("ended");
        //self.reader.run();
    }
}