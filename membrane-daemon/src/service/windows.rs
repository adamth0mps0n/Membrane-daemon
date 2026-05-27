//! Windows Service Control Manager integration.
//!
//! Registers the daemon as a Windows service that runs at boot under
//! the LocalService account. The daemon's normal `run` subcommand is
//! used; we don't need a special "service mode" because the SCM handles
//! lifecycle (start/stop/restart) externally.
//!
//! v1 limitation: the service runs as LocalService rather than as the
//! logged-in user, which doesn't match the user-level posture we have
//! on Linux and macOS. For v1.1 we should support per-user installation
//! via Task Scheduler or per-user services (Win10+ supports them).

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use windows_service::{
    service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use super::ServiceStatus;

const SERVICE_NAME: &str = "MembraneDaemon";
const DISPLAY_NAME: &str = "Membrane Daemon";
const DESCRIPTION: &str = "Customer-side daemon for the membrane cloud.";

fn open_manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .context("open service control manager")
}

pub fn install(exe: &Path) -> Result<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None,        // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .context("create service")?;
    service.set_description(DESCRIPTION).ok();
    eprintln!("installed Windows service: {SERVICE_NAME}");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(s) => s,
        Err(_) => return Ok(()),  // already gone
    };
    let _ = service.stop();
    service.delete().context("delete service")?;
    eprintln!("uninstalled Windows service");
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)
        .context("open service")?;
    service.start::<&str>(&[]).context("start service")?;
    Ok(())
}

pub fn stop() -> Result<()> {
    let manager = open_manager(ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("open service")?;
    service.stop().context("stop service")?;
    Ok(())
}

pub fn status() -> Result<ServiceStatus> {
    let manager = match open_manager(ServiceManagerAccess::CONNECT) {
        Ok(m) => m,
        Err(_) => return Ok(ServiceStatus::Unknown("cannot open SCM".into())),
    };
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(_) => return Ok(ServiceStatus::NotInstalled),
    };
    let st = service.query_status().context("query status")?;
    Ok(match st.current_state {
        ServiceState::Running => ServiceStatus::Running,
        ServiceState::Stopped => ServiceStatus::Stopped,
        other => ServiceStatus::Unknown(format!("{:?}", other)),
    })
}
