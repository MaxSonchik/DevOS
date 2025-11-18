use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub size: usize,
}

pub struct PacketCapture {
    interface: String,
    packet_count: u64,
    protocol_stats: HashMap<String, u64>,
    connection_stats: HashMap<String, u64>,
}

impl PacketCapture {
    pub fn new(interface_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(PacketCapture {
            interface: interface_name.to_string(),
            packet_count: 0,
            protocol_stats: HashMap::new(),
            connection_stats: HashMap::new(),
        })
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🎯 Starting packet capture on {}", self.interface);
        println!("Press Ctrl+C to stop capture");
        
        // Симуляция захвата пакетов
        self.simulate_capture()?;
        
        Ok(())
    }

    fn simulate_capture(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let protocols = vec!["TCP", "UDP", "HTTP", "DNS", "HTTPS", "ICMP"];
        let ips = vec!["192.168.1.", "10.0.0.", "172.16.1."];
        
        for i in 1..=20 {
            self.packet_count += 1;
            
            let protocol = protocols[i % protocols.len()];
            let src_ip = format!("{}{}", ips[i % ips.len()], i);
            let dst_ip = format!("{}{}", ips[(i + 1) % ips.len()], i + 1);
            
            let packet_info = PacketInfo {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                source_ip: src_ip.clone(),
                dest_ip: dst_ip.clone(),
                protocol: protocol.to_string(),
                source_port: Some(30000 + (i % 1000) as u16),
                dest_port: match protocol {
                    "HTTP" => Some(80),
                    "HTTPS" => Some(443),
                    "DNS" => Some(53),
                    _ => Some(8080 + (i % 100) as u16),
                },
                size: 64 + (i * 10) as usize,
            };
            
            self.process_packet(&packet_info);
            
            if i % 5 == 0 {
                self.print_stats();
            }
            
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        
        println!("✅ Capture completed. Total packets: {}", self.packet_count);
        Ok(())
    }

    fn process_packet(&mut self, packet: &PacketInfo) {
        // Обновляем статистику протоколов
        *self.protocol_stats.entry(packet.protocol.clone()).or_insert(0) += 1;
        
        // Обновляем статистику соединений
        let connection_key = format!("{} -> {}", packet.source_ip, packet.dest_ip);
        *self.connection_stats.entry(connection_key).or_insert(0) += 1;
        
        // Выводим информацию о пакете
        let src_port = packet.source_port.map_or("?".to_string(), |p| p.to_string());
        let dst_port = packet.dest_port.map_or("?".to_string(), |p| p.to_string());
        
        println!("📦 Packet {}: {} {}:{} -> {}:{} ({} bytes)", 
                 self.packet_count, 
                 packet.protocol, 
                 packet.source_ip, 
                 src_port,
                 packet.dest_ip, 
                 dst_port,
                 packet.size);
    }

    fn print_stats(&self) {
        println!("\n📊 === Capture Statistics ===");
        println!("Total packets: {}", self.packet_count);
        println!("Protocol distribution:");
        
        for (protocol, count) in &self.protocol_stats {
            println!("  {}: {}", protocol, count);
        }
        
        println!("Unique connections: {}", self.connection_stats.len());
        println!("================================\n");
    }
}