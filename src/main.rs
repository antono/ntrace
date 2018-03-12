#[macro_use]
extern crate clap;
extern crate pcap;
extern crate rshark;

use clap::{App, Arg};
use pcap::{Capture, Device, Packet};
use std::ops::Range;

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .author(crate_authors!())
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .value_name("PID")
                .default_value("0")
                .help("Specify process id to trace")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dev")
                .short("d")
                .long("dev")
                .value_name("DEVICE")
                .default_value("DEFAULT_DEVICE")
                .help("A network device name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .short("c")
                .long("count")
                .value_name("COUNT")
                .default_value("0")
                .help("Number of packets to capture (0 = unlimited)")
                .takes_value(true),
        )
        .get_matches();

    let count = matches.value_of("count").unwrap().parse::<u8>().unwrap();
    let pid = matches.value_of("pid").unwrap();

    println!("Tracing PID: {}", pid);

    let mut capture = start_capture().unwrap();

    print_packets(&mut capture, count);

    let stats = capture.stats().unwrap();
    println!(
        "Received: {}, dropped: {}, if_dropped: {}",
        stats.received, stats.dropped, stats.if_dropped
    );
}

fn start_capture() -> Result<Capture<pcap::Active>, pcap::Error> {
    let device = Device::lookup().unwrap();
    println!("Capturing on device: {:?}", device);

    let cap = Capture::from_device(device);

    cap.unwrap()
        .promisc(true)
        .snaplen(5000)
        .timeout(10000)
        .open()
}

fn print_packets(capture: &mut Capture<pcap::Active>, count: u8) {
    if count == 0 {
        println!("Capturing unlimited packets");
        loop {
            while let Ok(packet) = (*capture).next() {
                display_packet(packet);
            }
        }
    } else {
        println!("Capturing {} packets", count);
        let range = Range {
            start: 0,
            end: count,
        };
        for _ in range {
            match (*capture).next() {
                Ok(packet) => display_packet(packet),
                Err(_) => println!("Cannot capture next packet"),
            }
        }
    }
}

fn display_packet(packet: Packet) {
    match rshark::ethernet::dissect(&packet.data) {
        Err(e) => println!("Error: {}", e),
        Ok(val) => print!("{}", val.pretty_print(0)),
    }
}
