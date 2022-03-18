#![feature(unboxed_closures)]
mod colorprint;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use std::process::exit;

macro_rules! error_and_exit_app {
  ($msg:expr, $print_usage:expr) => {
    error_and_exit_internal_app($msg, $print_usage)
  };
  ($msg:expr) => {
    error_and_exit_internal_app($msg, false)
  };
}

fn error_and_exit_internal_app(msg: &str, print_usage: bool) -> ! {
  redln!("Error: {}", msg);
  if print_usage {
    usage();
  }
  exit(1);
}

fn usage() -> ! {
  let args: Vec<String> = std::env::args().collect();
  println!("Usage:\n\t {} <interface name>\n", args[0]);
  exit(1);
}

fn extract_utf(data: &[u8]) -> String {
  let mut extracted = String::new();
  while extracted.len() < data.len() {
    let data = &data[extracted.len()..];
    extracted += match std::str::from_utf8(data) {
      Ok(res) => res,
      Err(why) => {
        if why.valid_up_to() == 0 {
          "."
        } else {
          std::str::from_utf8(&data[..why.valid_up_to()]).unwrap()
        }
      }
    };
  }
  extracted
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let interface_name = match args.get(1) {
    None => usage(),
    Some(res) => res.clone(),
  };
  let words_base_fn = match args.get(2) {
    None => usage(),
    Some(res) => res.clone(),
  };
  let file = match std::fs::read_to_string(words_base_fn) {
    Err(why) => {
      redln!("Invalid filename for words base provided: {}", why);
      usage();
    }
    Ok(res) => res,
  };
  let words: Vec<&str> = file.split("\n").collect();

  let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

  // Find the network interface with the provided name
  let interfaces = datalink::interfaces();
  let interface = match interfaces.into_iter().filter(interface_names_match).next() {
    None => error_and_exit_app!("Invalid interface name", true),
    Some(res) => res,
  };
  let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
    Ok(Ethernet(tx, rx)) => (tx, rx),
    Ok(_) => error_and_exit_app!("Unhandled channel type"),
    Err(_) => error_and_exit_app!("An error occurred when creating the datalink channel: {}"),
  };
  loop {
    match rx.next() {
      Ok(packet) => {
        let packet = match EthernetPacket::new(packet) {
          Some(res) => res,
          None => {
            redln!("Invalid packet received!");
            continue;
          }
        };
        let packet_data = extract_utf(packet.payload()).escape_debug().to_string();
        let mymac = interface.mac.unwrap();
        let txrx: &str = if packet.get_source() == mymac {
          "sent"
        } else {
          "received"
        };
        for word in words.iter() {
          if packet_data.contains(word) {
            redln!("Potentially malicious packet {}: {}", txrx, packet_data);
          }
        }
      }
      Err(why) => {
        // If an error occurs, we can handle it here
        redln!("An error occurred while reading: {}", why);
      }
    }
  }
}
