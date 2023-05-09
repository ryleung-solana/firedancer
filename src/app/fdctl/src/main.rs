//! Binary harness for spinning up a full Firedancer + Solana instance.
//! 
//! Three processes are started,
//! 
//!  1. The root process, this binary. Sets up and verifies operating system configuration
//!     and performs general housekeeping. Monitors both child processes and terminates
//!     the system if anything goes wrong.
//! 
//!  2. The Solana process. A full Solana instance, with some special configuration information
//!     to enable it to talk to Firedancer.
//! 
//!  3. The Firedancer process. A Firedancer instance, with corresponding configuration to
//!     enable it to talk to Solana.
//! 
//! If any process crashes, all three will be bought down.
//! 
//! For packaging, all three processes are contained in the one binary, and switched between
//! based on the command line.
mod steps;

use steps::*;

use clap::{Parser, Subcommand, Args};
use std::{env, fs, path};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ffi::{CStr, CString, c_char};

use serde::Deserialize;
use log::*;
use libc::getpwnam_r;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,

    /// Location of a configuration TOML file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Location of the Firedancer build binary directory. For example `/home/user/firedancer/build/linux/gcc/x86_65/bin/`
    #[arg(long)]
    binary_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Setup and verify the static configuration of the system
    Configure(Configure),

    /// Run a Firedancer validator node
    Run(Run),
}

#[derive(Debug, Args)]
struct Configure {
    #[command(subcommand)]
    command: ConfigureCommand,
}

#[derive(Debug, Subcommand, Copy, Clone)]
enum ConfigureCommand {
    Ensure,
    Verify,
    Clean,
}

#[derive(Debug, Args)]
struct Run {
    #[command(subcommand)]
    subprocess: Option<Subprocess>,

    #[arg(long)]
    clean: bool,

    #[arg(long)]
    monitor: bool,
}

#[derive(Debug, Subcommand)]
enum Subprocess {
    Solana,
    Firedancer,
}

#[link(name = "c")]
extern "C" {
    fn getlogin_r(name: *mut i8, name_len: u64) -> i32;
}

fn get_uid_by_username(username: &str) -> Option<u32> {
    let c_username = CString::new(username).unwrap();

    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize > 0 { bufsize as usize } else { 1024 };

    let mut buf = Vec::with_capacity(bufsize);

    let err = unsafe {
        getpwnam_r(
            c_username.as_ptr(),
            &mut passwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.capacity(),
            &mut result,
        )
    };

    if err == 0 && !result.is_null() {
        Some(unsafe { (*result).pw_uid })
    } else {
        None
    }
}

fn configure(command: ConfigureCommand, config: &mut Config) {
    let mut steps: [Box<dyn Step>; 6] = [
        Box::new(steps::Shmem {}),
        Box::new(steps::LargePages {}),
        Box::new(steps::Xdp {}),
        Box::new(steps::XdpLeftover {}),
        // Box::new(steps::Workspaces {}),
        Box::new(steps::NetNs {}),
        Box::new(steps::Frank {}),
    ];

    for step in steps.iter_mut() {
        let stage = step.name();

        match command {
            ConfigureCommand::Ensure => {
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(reason)) => info!("[Configure] {stage} ... unconfigured ... {reason}"),
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                        if !step.supports_undo() {
                            panic!("[Configure] {stage} ... does not support undo but was not valid ... {reason}");
                        }

                        info!("[Configure] {stage} ... undoing ... {reason}");
                        step.undo(config);
                        match step.check(config) {
                            CheckResult::Ok(()) => (),
                            CheckResult::Err(CheckError::NotConfigured(_)) => (),
                            CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... clean was unable to get back to an unconfigured state ... {reason}"),
                        };
                    },
                    CheckResult::Ok(()) => {
                        info!("[Configure] {stage} ... already valid");
                        continue;
                    }
                };
        
                info!("[Configure] {stage} ... initializing");
                step.step(config);
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(reason)) => panic!("[Configure] {stage} ... tried to initialize but didn't do anything ... {reason}"),
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... tried to initialize but was still unconfigured ... {reason}"),
                    CheckResult::Ok(()) => (),
                }
            },
            ConfigureCommand::Verify => {
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(reason)) => panic!("[Configure] {stage} ... not configured ... {reason}"),
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... invalid ... {reason}"),
                    CheckResult::Ok(()) => (),
                }
            },
            ConfigureCommand::Clean => (),
        }
    }

    for step in steps.iter_mut().rev() {
        let stage = step.name();

        match command {
            ConfigureCommand::Ensure | ConfigureCommand::Verify => (),
            ConfigureCommand::Clean => {
                match step.check(config) {
                    CheckResult::Err(CheckError::NotConfigured(_)) => continue,
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => {
                        if !step.supports_undo() {
                            panic!("[Configure] {stage} ... not valid ... {reason:?}");
                        }
                    }
                    CheckResult::Ok(()) => (),
                };


                info!("[Configure] {stage} ... undoing");
                step.undo(config);
                match step.check(config) {
                    CheckResult::Ok(()) => if step.supports_do() && step.supports_undo() {
                        // If the step does nothing, it's fine if it's fully configured after being undone.
                        panic!("[Configure] {stage} ... not undone")
                    },
                    CheckResult::Err(CheckError::PartiallyConfigured(reason)) => panic!("[Configure] {stage} ... invalid ... {reason}"),
                    CheckResult::Err(CheckError::NotConfigured(_)) => (),
                };
            }
        }
    }
}

fn default_user() -> String {
    match env::var("SUDO_USER") {
        Ok(name) => return name,
        _ => (),
    };

    match env::var("LOGNAME") {
        Ok(name) => name,
        _ => {
            let mut username: [i8; 32] = [0; 32];
            assert_eq!(0, unsafe { getlogin_r(username.as_mut_ptr(), 32) });
            unsafe { CStr::from_ptr(username.as_ptr()).to_str().unwrap().to_owned() }
        },
    }
}

#[derive(Deserialize)]
struct UserConfig {
    name: String,
    user: String,

    scratch_directory: String,

    affinity: String,
    pod_size: u32,
    cnc_app_size: u32,

    workspace: WorkspaceConfig,
    shmem: ShmemConfig,
    netns: NetNsConfig,

    tiles: TilesConfig,
}

pub struct Config {
    name: String,
    user: String,
    uid: u32,
    gid: u32,

    frank: FrankConfig,

    binary_dir: PathBuf,
    scratch_directory: String,

    affinity: String,
    pod_size: u32,
    cnc_app_size: u32,

    workspace: WorkspaceConfig,
    shmem: ShmemConfig,
    netns: NetNsConfig,

    tiles: TilesConfig,
}

struct FrankConfig {
    pod: u32,
    main_cnc: u32,
    src_mac_address: String,
    listen_addresses: Vec<String>
}

#[derive(Deserialize)]
struct TilesConfig {
    quic: QuicConfig,
    verify: VerifyConfig,
    pack: PackConfig,
    dedup: DedupConfig,
}

#[derive(Deserialize)]
struct VerifyConfig {
    count: u32,
    depth: u32,
    mtu: u32,
}

#[derive(Deserialize)]
struct PackConfig {
    bank_count: u32,
    prq_size: u32,
    cu_est_table_size: u32,
    cu_est_history: u32,
    cu_est_default: u32,
    cu_limit: u32,
}

#[derive(Deserialize)]
struct DedupConfig {
    tcache_depth: u32,
    tcache_map_count: u32,
}

#[derive(Deserialize)]
struct NetNsConfig {
    enabled: bool,
    workspace: String,
    interface0: String,
    interface0_mac: String,
    interface0_addr: String,
    interface1: String,
    interface1_mac: String,
    interface1_addr: String,
}

#[derive(Deserialize)]
struct WorkspaceConfig {
    page_count: u32,
    page_size: String,
}

#[derive(Deserialize)]
struct ShmemConfig {
    path: String,
    gigantic_pages: u32,
    huge_pages: u32,
}

#[derive(Deserialize)]
struct QuicConfig {
    interface: String,
    listen_port: u32,
    connection_count: u32,
    connection_id_count: u32,
    stream_count: u32,
    handshake_count: u32,
    max_inflight_packets: u32,
    tx_buf_size: u32,
    rx_buf_size: u32,
    xdp_mode: String,
    xdp_frame_size: u32,
    xdp_rx_depth: u32,
    xdp_tx_depth: u32,
    xdp_aio_depth: u32,
}

fn load_config(config: &Option<path::PathBuf>) -> UserConfig {
    let config_str = match config {
        Some(path) => fs::read_to_string(path).unwrap(),
        None => {
            match env::var("FIREDANCER_CONFIG_TOML") {
                Ok(path) => fs::read_to_string(path).unwrap(),
                Err(_) => panic!("No configuration file specified. Either set `--config <path>` or FIREDANCER_CONFIG_TOML environment variable"),
            }
        }
    };

    toml::from_str(&config_str).unwrap()
}

fn load_binary_dir(args: &Cli) -> PathBuf {
    match &args.binary_dir {
        Some(path) => path.clone(),
        None => {
            match env::var("FIREDANCER_BINARY_DIR") {
                Ok(path) => PathBuf::from(path),
                Err(_) => panic!("No binary directory specified. Either set `--binary-dir <path>` or FIREDANCER_BINARY_DIR environment variable"),
            }
        }
    }
}

fn dump_bash_config(config: &Config) {
    let build = config.binary_dir.parent().unwrap().display();
    let name = &config.name;
    let affinity = &config.affinity;
    let pod = &config.frank.pod;
    let main_cnc = &config.frank.main_cnc;
    let interface = &config.tiles.quic.interface;
    let src_mac_address = &config.frank.src_mac_address;
    let quic_listen_port = &config.tiles.quic.listen_port;
    let quic_connection_count = &config.tiles.quic.connection_count;
    let quic_connection_id_count = &config.tiles.quic.connection_id_count;
    let quic_stream_count = &config.tiles.quic.stream_count;
    let quic_handshake_count = &config.tiles.quic.handshake_count;
    let quic_max_inflight_packets = &config.tiles.quic.max_inflight_packets;
    let quic_tx_buf_size = &config.tiles.quic.tx_buf_size;
    let quic_rx_buf_size = &config.tiles.quic.rx_buf_size;
    let listen_addresses = config.frank.listen_addresses.join(",");

    std::fs::write(&format!("{}/{}.cfg", config.scratch_directory, config.name), format!("#!/bin/bash \
        # AUTOGENERATED \n\
        BUILD={build} \n\
        WKSP={name}.wksp \n\
        AFFINITY={affinity} \n\
        APP={name} \n\
        POD={name}.wksp:{pod} \n\
        RUN_ARGS=--pod\\ {name}.wksp:{pod}\\ --cfg\\ {name}\\ --log-app\\ {name}\\ --log-thread\\ main \n\
        MON_ARGS=--pod\\ {name}.wksp:{pod}\\ --cfg\\ {name}\\ --log-app\\ {name}\\ --log-thread\\ mon \n\
        MAIN_CNC={name}.wksp:{main_cnc} \n\
        IFACE={interface} \n\
        LISTEN_ADDRS={listen_addresses} \n\
        SRC_MAC_ADDR={src_mac_address} \n\
        QUIC_LISTEN_PORT={quic_listen_port} \n\
        QUIC_CONN_CNT={quic_connection_count} \n\
        QUIC_CONN_ID_CNT={quic_connection_id_count} \n\
        QUIC_STREAM_CNT={quic_stream_count} \n\
        QUIC_HANDSHAKE_CNT={quic_handshake_count} \n\
        QUIC_MAX_INFLIGHT_PKTS={quic_max_inflight_packets} \n\
        QUIC_TX_BUF_SZ={quic_tx_buf_size} \n\
        QUIC_RX_BUF_SZ={quic_rx_buf_size} \n\
    ")).unwrap();
}

fn main() {
    env_logger::init();
    
    let args = Cli::parse();
    let user_config = load_config(&args.config);

    let user = if user_config.user == "" {
        default_user()
    } else {
        user_config.user
    };

    let mut config = Config {
        name: user_config.name.clone(),
        user: user.clone(),

        uid: get_uid_by_username(&user).unwrap(),
        gid: get_uid_by_username(&user).unwrap(),

        frank: FrankConfig {
            pod: 0,
            main_cnc: 0,
            src_mac_address: "".to_string(),
            listen_addresses: vec![],
        },

        binary_dir: load_binary_dir(&args),
        scratch_directory: user_config.scratch_directory.replace("{user}", &user).replace("{name}", &user_config.name),

        affinity: user_config.affinity,
        pod_size: user_config.pod_size,
        cnc_app_size: user_config.cnc_app_size,

        workspace: user_config.workspace,
        shmem: user_config.shmem,
        netns: user_config.netns,

        tiles: user_config.tiles,
    };

    match args.command {
        CliCommand::Configure(command) => configure(command.command, &mut config),
        CliCommand::Run(ref run) => {
            if run.clean {
                configure(ConfigureCommand::Clean, &mut config);
            }
            configure(ConfigureCommand::Ensure, &mut config);
            dump_bash_config(&config);

            let pod = format!("{}.wksp:{}", &config.name, &config.frank.pod);

            if !run.monitor {
                let mut child = Command::new("nsenter")
                    .args(vec![
                        &format!("--net=/var/run/netns/{}", &config.tiles.quic.interface),
                        &format!("{}/fd_frank_run.bin", config.binary_dir.display()),
                        "--pod", &pod,
                        "--cfg", &config.name,
                        "--log-app", &config.name,
                        "--log-thread", "main",
                        "--tile-cpus", &config.affinity,
                    ])
                    .spawn()
                    .unwrap();

                let status = child.wait().unwrap();
                assert!(status.success());
            } else {
                let mut child = Command::new("nsenter")
                    .args(vec![
                        &format!("--net=/var/run/netns/{}", &config.tiles.quic.interface),
                        &format!("{}/fd_frank_run.bin", config.binary_dir.display()),
                        "--pod", &pod,
                        "--cfg", &config.name,
                        "--log-app", &config.name,
                        "--log-thread", "main",
                        "--tile-cpus", &config.affinity,
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();

                let mut monitor = Command::new(format!("{}/fd_frank_mon.bin", config.binary_dir.display()))
                        .args([
                            "--pod", &format!("{}.wksp:{}", &config.name, &config.frank.pod),
                            "--cfg", &config.name,
                            "--log-app", &config.name,
                            "--log-thread", "mon",
                            "--duration-", &"31536000000000000".to_string(),
                        ])
                        .spawn()
                        .unwrap();

                let status = monitor.wait().unwrap();
                assert!(status.success());

                let status = child.wait().unwrap();
                assert!(status.success());
            }
        },
    }
}
