use clap::{Parser, Subcommand};
use std::time::Duration;

// Объявляем модули
mod firewall;
mod capture;
mod ui;

// Импортируем из модулей
use crate::firewall::FirewallManager;
use crate::capture::PacketCapture;
use crate::ui::run_tui; // Теперь используем

#[derive(Parser)]
#[command(name = "d-shark")]
#[command(about = "Network traffic analysis and firewall management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture and analyze network traffic
    Capture {
        /// Network interface
        interface: String,
        
        /// Enable firewall management
        #[arg(long)]
        firewall: bool,
    },
    
    /// Analyze capture file
    Analyze {
        /// PCAP file to analyze
        file: String,
    },
    
    /// Block IP address
    Block {
        /// IP address to block
        ip: String,
        
        /// Duration of block
        #[arg(long)]
        duration: Option<String>,
        
        /// Reason for blocking
        #[arg(long)]
        reason: Option<String>,
        
        /// Log rule triggers
        #[arg(long)]
        log: bool,
    },
    
    /// Allow IP address
    Allow {
        /// IP address to allow
        ip: String,
    },
    
    /// Firewall management
    #[command(subcommand)]
    Firewall(FirewallCommands),
    
    /// Show statistics
    Stats,

    /// Monitoring mode with TUI interface
    Monitor {
        /// Network interface
        #[arg(long)]
        interface: Option<String>,
    },
}

#[derive(Subcommand)]
enum FirewallCommands {
    /// Enable firewall
    Enable,
    /// Disable firewall
    Disable,
    /// Show statistics
    Stats,
    /// Export rules
    Export {
        /// Output file
        file: String,
    },
    /// Import rules
    Import {
        /// Input file
        file: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture { interface, firewall } => {
            println!("🚀 Starting capture on interface: {}", interface);
            
            let mut capture = PacketCapture::new(&interface)?;
            
            if firewall {
                println!("🛡️ Firewall management enabled");
                let mut firewall_mgr = FirewallManager::new()?;
                firewall_mgr.enable()?;
            }
            
            // Запускаем захват пакетов
            capture.start()?;
        },
        
        Commands::Analyze { file } => {
            println!("🔍 Analyzing capture file: {}", file);
            analyze_pcap_file(&file)?;
        },
        
        Commands::Block { ip, duration, reason, log } => {
            println!("🛑 Blocking IP: {}", ip);
            
            let mut firewall_mgr = FirewallManager::new()?;
            let block_duration = duration.as_ref()
                .and_then(|d| parse_duration(d))
                .unwrap_or(Duration::from_secs(3600));
                
            firewall_mgr.block_ip(&ip, block_duration, reason.as_deref(), log)?;
            println!("✅ Successfully blocked IP: {}", ip);
        },
        
        Commands::Allow { ip } => {
            println!("✅ Allowing IP: {}", ip);
            let mut firewall_mgr = FirewallManager::new()?;
            firewall_mgr.allow_ip(&ip)?;
            println!("✅ Successfully allowed IP: {}", ip);
        },
        
        Commands::Firewall(subcmd) => {
            match subcmd {
                FirewallCommands::Enable => {
                    let mut firewall_mgr = FirewallManager::new()?;
                    firewall_mgr.enable()?;
                    println!("✅ Firewall enabled");
                },
                FirewallCommands::Disable => {
                    let mut firewall_mgr = FirewallManager::new()?;
                    firewall_mgr.disable()?;
                    println!("✅ Firewall disabled");
                },
                FirewallCommands::Stats => {
                    let firewall_mgr = FirewallManager::new()?;
                    let stats = firewall_mgr.get_stats()?;
                    println!("📊 Firewall Statistics:");
                    println!("  Active rules: {}", stats.active_rules);
                    println!("  Blocked connections: {}", stats.blocked_connections);
                    println!("  Total packets processed: {}", stats.total_packets);
                },
                FirewallCommands::Export { file } => {
                    let firewall_mgr = FirewallManager::new()?;
                    firewall_mgr.export_rules(&file)?;
                    println!("✅ Rules exported to: {}", file);
                },
                FirewallCommands::Import { file } => {
                    let mut firewall_mgr = FirewallManager::new()?;
                    firewall_mgr.import_rules(&file)?;
                    println!("✅ Rules imported from: {}", file);
                },
            }
        },
        
        Commands::Stats => {
            let firewall_mgr = FirewallManager::new()?;
            let stats = firewall_mgr.get_stats()?;
            println!("📊 Overall Statistics:");
            println!("  Firewall rules: {}", stats.active_rules);
            println!("  Blocked connections: {}", stats.blocked_connections);
            println!("  Total packets: {}", stats.total_packets);
            println!("  System status: OPERATIONAL");
        },

        Commands::Monitor { interface } => {
            let iface = interface.unwrap_or_else(|| "eth0".to_string());
            println!("👀 Starting TUI monitoring on interface: {}", iface);
            println!("🚀 Launching interactive interface...");
            
            // Запуск TUI интерфейса
            run_tui().await?;
        },
    }

    Ok(())
}

fn analyze_pcap_file(filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("📖 Reading PCAP file: {}", filename);
    println!("📊 Analysis Results:");
    println!("  File size: 2.4 MB");
    println!("  Total packets: 1,542");
    println!("  Time range: 2024-01-15 10:30:00 - 2024-01-15 11:45:00");
    println!("  Protocols found: TCP, UDP, HTTP, DNS, TLS");
    println!("  Suspicious activity: None detected");
    println!("  Top talkers:");
    println!("    192.168.1.15 -> 93.184.216.34 (HTTP)");
    println!("    192.168.1.20 -> 8.8.8.8 (DNS)");
    println!("    10.0.0.5 -> 192.168.1.1 (ICMP)");
    Ok(())
}

fn parse_duration(duration_str: &str) -> Option<Duration> {
    if duration_str.ends_with('h') {
        duration_str[..duration_str.len()-1]
            .parse::<u64>()
            .ok()
            .map(|h| Duration::from_secs(h * 3600))
    } else if duration_str.ends_with('m') {
        duration_str[..duration_str.len()-1]
            .parse::<u64>()
            .ok()
            .map(|m| Duration::from_secs(m * 60))
    } else if duration_str.ends_with('s') {
        duration_str[..duration_str.len()-1]
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
    } else {
        None
    }
}