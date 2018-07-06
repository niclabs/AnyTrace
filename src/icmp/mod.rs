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
        let local: Ipv4Addr = localip.parse().unwrap();
        let (reader, writer) = IcmpReader::new(local);
        return IcmpHandler {
            reader: reader,
            writer: writer,
        };
    }

    pub fn run(&mut self) {
        let target: Ipv4Addr = "1.1.1.1".parse().unwrap();
        for _ in 0..10 {
            self.writer.send(target);
        }
        use std::{thread, time};
        thread::sleep(time::Duration::from_millis(10000));
        while let Ok(packet) = self.reader.reader.try_recv() {
            println!("{:?}, {:?}", packet.source, packet.ttl);
        }

        println!("ended");
    }
}
