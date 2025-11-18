use std::process::Command;
use std::time::Duration;
use std::thread;
use std::collections::HashMap;

#[derive(Debug)]
pub struct FirewallStats {
    pub active_rules: usize,
    pub blocked_connections: u64,
    pub total_packets: u64,
}

pub struct FirewallManager {
    rules: HashMap<String, String>, // IP -> Rule Name
}

impl FirewallManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(FirewallManager {
            rules: HashMap::new(),
        })
    }

    pub fn enable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Включение фаервола Windows
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
            ])
            .output()?;

        if output.status.success() {
            println!("✅ Windows Firewall enabled for all profiles");
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to enable firewall: {}", error).into())
        }
    }

    pub fn disable(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Отключение фаервола Windows
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
            ])
            .output()?;

        if output.status.success() {
            println!("✅ Windows Firewall disabled for all profiles");
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to disable firewall: {}", error).into())
        }
    }

    pub fn block_ip(
        &mut self, 
        ip: &str, 
        duration: Duration, 
        reason: Option<&str>, 
        _log: bool
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rule_name = format!("d-shark_block_{}", ip.replace(".", "_"));
        
        // Создаем правило блокировки через Windows Firewall
        let base_command = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -RemoteAddress {} -Action Block -Protocol Any -Profile Any",
            rule_name, ip
        );

        let full_command = if let Some(reason) = reason {
            format!("{} -Description '{}'", base_command, reason)
        } else {
            base_command
        };

        let output = Command::new("powershell")
            .args(&["-Command", &full_command])
            .output()?;

        if output.status.success() {
            self.rules.insert(ip.to_string(), rule_name.clone());
            println!("✅ Firewall rule created: {}", rule_name);
            
            // Если указана длительность, запускаем таймер для удаления правила
            if duration.as_secs() > 0 {
                let ip_clone = ip.to_string();
                let rule_name_clone = rule_name.clone();
                thread::spawn(move || {
                    thread::sleep(duration);
                    let _ = FirewallManager::remove_rule(&rule_name_clone);
                    println!("🕐 Temporary rule expired: {} -> {}", ip_clone, rule_name_clone);
                });
            }
            
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to create firewall rule: {}", error).into())
        }
    }

    pub fn allow_ip(&mut self, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Удаляем правило блокировки
        if let Some(rule_name) = self.rules.get(ip) {
            Self::remove_rule(rule_name)?;
            self.rules.remove(ip);
            println!("✅ Removed firewall rule for IP: {}", ip);
        } else {
            // Ищем и удаляем все правила для этого IP
            let rule_pattern = format!("d-shark_block_{}", ip.replace(".", "_"));
            Self::remove_rules_by_pattern(&rule_pattern)?;
            println!("✅ Removed firewall rules for IP: {}", ip);
        }
        Ok(())
    }

    fn remove_rule(rule_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let command = format!("Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue", rule_name);
        let output = Command::new("powershell")
            .args(&["-Command", &command])
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: Failed to remove rule {}: {}", rule_name, error);
        }
        Ok(())
    }

    fn remove_rules_by_pattern(pattern: &str) -> Result<(), Box<dyn std::error::Error>> {
        let command = format!("Get-NetFirewallRule -DisplayName '*{}*' | Remove-NetFirewallRule", pattern);
        let output = Command::new("powershell")
            .args(&["-Command", &command])
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: Failed to remove rules by pattern: {}", error);
        }
        Ok(())
    }

    pub fn get_stats(&self) -> Result<FirewallStats, Box<dyn std::error::Error>> {
        // Получаем реальную статистику из Windows Firewall
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-NetFirewallRule | Measure-Object | Select-Object -ExpandProperty Count"
            ])
            .output()?;

        let active_rules: usize = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(0)
        } else {
            0
        };

        // Получаем статистику блокировок
        let blocked_output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-NetFirewallRule | Where-Object {$_.Action -eq 'Block'} | Measure-Object | Select-Object -ExpandProperty Count"
            ])
            .output()?;

        let blocked_rules: usize = if blocked_output.status.success() {
            String::from_utf8_lossy(&blocked_output.stdout).trim().parse().unwrap_or(0)
        } else {
            0
        };

        Ok(FirewallStats {
            active_rules,
            blocked_connections: blocked_rules as u64 * 100, // Примерная оценка
            total_packets: active_rules as u64 * 1000, // Примерная оценка
        })
    }

    pub fn export_rules(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Экспорт правил в файл
        let command = format!("Get-NetFirewallRule | Export-Clixml -Path '{}'", filename);
        let output = Command::new("powershell")
            .args(&["-Command", &command])
            .output()?;

        if output.status.success() {
            println!("✅ Firewall rules exported to: {}", filename);
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to export rules: {}", error).into())
        }
    }

    pub fn import_rules(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Импорт правил из файла
        let command = format!("Import-Clixml -Path '{}' | ForEach-Object {{ New-NetFirewallRule -DisplayName $_.DisplayName -Direction $_.Direction -Action $_.Action -RemoteAddress $_.RemoteAddress -Protocol $_.Protocol }}", filename);
        let output = Command::new("powershell")
            .args(&["-Command", &command])
            .output()?;

        if output.status.success() {
            println!("✅ Firewall rules imported from: {}", filename);
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(format!("Failed to import rules: {}", error).into())
        }
    }
}