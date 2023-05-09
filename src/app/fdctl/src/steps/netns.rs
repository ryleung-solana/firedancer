use super::*;
use crate::Config;

use std::process::Command;

pub struct NetNs;

impl Step for NetNs {
    fn name(&self) -> &'static str {
        "netns"
    }

    fn supports_do(&self) -> bool {
        true
    }

    fn supports_undo(&self) -> bool {
        true
    }

    fn step(&mut self, config: &mut Config) {
        assert!(Command::new("ip").args(["netns", "add", &config.netns.interface0]).status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "add", &config.netns.interface1]).status().unwrap().success());
        assert!(Command::new("ip").args(["link", "add",
            "dev", &config.netns.interface0,
            "netns", &config.netns.interface0,
            "type", "veth",
            "peer", "name", &config.netns.interface1, "netns", &config.netns.interface1,
            "numrxqueues", "1",
            "numtxqueues", "1",
            ]).status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface0,
            "ip", "link", "set", "dev", &config.netns.interface0, "address", &config.netns.interface0_mac]).status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface1,
            "ip", "link", "set", "dev", &config.netns.interface1, "address", &config.netns.interface1_mac]).status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface0,
            "ip", "address", "add", &format!("{}/30", &config.netns.interface0_addr), "dev", &config.netns.interface0, "scope", "link"])
            .status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface1,
            "ip", "address", "add", &format!("{}/30", &config.netns.interface1_addr), "dev", &config.netns.interface1, "scope", "link"])
            .status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface0,
            "ip", "link", "set", "dev", &config.netns.interface0, "up"])
            .status().unwrap().success());
        assert!(Command::new("ip").args(["netns", "exec", &config.netns.interface1,
            "ip", "link", "set", "dev", &config.netns.interface1, "up"])
            .status().unwrap().success());

        assert!(Command::new("nsenter").args([&format!("--net=/var/run/netns/{}", &config.netns.interface0),
            "ethtool",
            "--set-channels", &config.netns.interface0,
            "rx", &config.tiles.verify.count.to_string(),
            "tx", &config.tiles.verify.count.to_string()])
            .status().unwrap().success());
    }

    fn undo(&mut self, config: &Config) {
        // Destroys interface1 as well, no need to check failure
        let _ = Command::new("ip").args(["link", "del", "dev", &config.netns.interface0]).status().unwrap().success();
        
        let status1 = Command::new("ip").args(["netns", "delete", &config.netns.interface0]).status().unwrap().success();
        let status2 = Command::new("ip").args(["netns", "delete", &config.netns.interface1]).status().unwrap().success();

        // If neither of them was present, we wouldn't get to the undo step so make sure we were
        // able to delete whatever is there.
        assert!(status1 || status2);
    }

    fn check(&mut self, config: &Config) -> CheckResult {
        let output = Command::new("ip").args(["netns", "list"]).output().unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        let namespaces = output.trim().lines().collect::<Vec<&str>>();
        if !namespaces.contains(&config.netns.interface0.as_ref()) && !namespaces.contains(&config.netns.interface1.as_ref()) {
            return CheckResult::Err(CheckError::NotConfigured("no network namespace".to_string()));
        }
        if !namespaces.contains(&config.netns.interface0.as_ref()) || !namespaces.contains(&config.netns.interface1.as_ref()) {
            return CheckResult::Err(CheckError::PartiallyConfigured("no network namespace".to_string()));
        }

        // TODO: Use `ip netns exec .. ip link show` to verify the configuration is correct
    
        CheckResult::Ok(())
    }
}
