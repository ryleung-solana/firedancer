mod shmem;
mod large_pages;
mod xdp;
mod xdp_leftover;
mod workspaces;
mod netns;
mod frank;

pub use shmem::Shmem;
pub use large_pages::LargePages;
pub use xdp::Xdp;
pub use xdp_leftover::XdpLeftover;
pub use workspaces::Workspaces;
pub use netns::NetNs;
pub use frank::Frank;

use super::Config;

use std::io::ErrorKind;
use std::fs::metadata;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug)]
pub enum CheckError {
    NotConfigured(String),
    PartiallyConfigured(String),
}
pub type CheckResult = Result<(), CheckError>;

pub trait Step {
    fn name(&self) -> &'static str;

    /// If this step supports doing anything, or is just here for undo and check.
    fn supports_do(&self) -> bool;

    /// If the step supports being undone.
    fn supports_undo(&self) -> bool;
    
    /// Perform the step, assuming that it has not been done before.
    fn step(&mut self, config: &mut Config);

    /// Undo the step. The step may be not performed, partially, or fully performed.
    fn undo(&mut self, config: &Config);

    /// Check if the step has been performed.
    fn check(&mut self, config: &Config) -> CheckResult;
}

fn path_exists(path: &str, expected_uid: u32, expected_gid: u32, expected_mode: u32, expected_dir: bool) -> CheckResult {
    let metadata = match metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return CheckResult::Err(CheckError::PartiallyConfigured(format!("{} does not exist", path))),
        result => return CheckResult::Err(CheckError::PartiallyConfigured(format!("error reading {} {result:?}", &path))),
    };

    if expected_dir && !metadata.is_dir() {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!("{path} is a file, not a directory")));
    } else if !expected_dir && metadata.is_dir() {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!("{path} is a directory, not a file")));
    }

    let uid = metadata.uid();
    if uid != expected_uid {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!("owner of {} is {uid}, not {}", path, expected_uid)));
    }

    let gid = metadata.gid();
    if gid != expected_gid {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!("group of {} is {gid}, not {}", path, expected_gid)));
    }

    let mode = metadata.permissions().mode();
    if mode != expected_mode {
        return CheckResult::Err(CheckError::PartiallyConfigured(format!("permissions of {} is {mode:o}, not {:o}", path, expected_mode)));
    }

    CheckResult::Ok(())
}

#[must_use]
fn check_directory(path: &str, expected_uid: u32, expected_gid: u32, expected_mode: u32) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, true)
}

#[must_use]
fn check_file(path: &str, expected_uid: u32, expected_gid: u32, expected_mode: u32) -> CheckResult {
    path_exists(path, expected_uid, expected_gid, expected_mode, false)
}
