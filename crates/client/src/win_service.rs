//! Native Windows Service Control Manager integration.
//!
//! The service is installed with a hidden `rtunnel service run` command line.
//! `service_dispatcher::start` must only be called when the process was
//! launched by the SCM; running it from a normal console fails immediately.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

/// Name used by `sc.exe create` in the installer.
const SERVICE_NAME: &str = "rtunnel";

struct ServiceConfig {
    state_dir: PathBuf,
    target: String,
}

/// The SCM entry point cannot receive application arguments, so the parsed CLI
/// configuration is stored here before the dispatcher is started.
static SERVICE_CONFIG: OnceLock<ServiceConfig> = OnceLock::new();

/// Runs the current process as the `rtunnel` Windows service.
///
/// This blocks until the SCM stops the service. Host output is redirected to
/// `<state_dir>/service.log` because services have no usable console handles.
pub fn run(state_dir: &Path, target: &str) -> Result<()> {
    crate::initialize_service_log(state_dir);
    SERVICE_CONFIG
        .set(ServiceConfig {
            state_dir: state_dir.to_path_buf(),
            target: target.to_owned(),
        })
        .map_err(|_| anyhow!("service configuration was already initialized"))?;

    crate::write_host_line(format_args!(
        "rtunnel: starting Windows service (target {target}, state {})",
        state_dir.display()
    ));

    service_dispatcher::start(SERVICE_NAME, service_main)
        .context("failed to start the Windows service dispatcher")
}

/// Low-level service entry point invoked by the SCM on a background thread.
///
/// The service arguments are unused: the command line was already parsed by
/// `main` before `service_dispatcher::start` was called.
extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    if let Err(error) = run_service() {
        crate::write_host_warning(format_args!("rtunnel: Windows service failed: {error:#}"));
    }
}

fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);

    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("failed to register the service control handler")?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::NO_ERROR,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("failed to report the service as running")?;

    let config = SERVICE_CONFIG
        .get()
        .context("service configuration is unavailable")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create the service Tokio runtime")?;

    let result = runtime.block_on(async {
        let mut stop_rx = stop_rx;
        tokio::select! {
            result = crate::run_host(&config.state_dir, &config.target) => result,
            () = wait_for_stop(&mut stop_rx) => Ok(()),
        }
    });

    if let Err(error) = &result {
        crate::write_host_warning(format_args!(
            "rtunnel: host stopped with an error: {error:#}"
        ));
    }

    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("failed to report the service as stopped")?;

    result
}

async fn wait_for_stop(stop_rx: &mut watch::Receiver<bool>) {
    loop {
        if *stop_rx.borrow() {
            return;
        }
        if stop_rx.changed().await.is_err() {
            return;
        }
    }
}
