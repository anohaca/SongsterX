use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

const GATEWAY_CHILD_STOP_GRACE: Duration = Duration::from_millis(900);

use crate::process_group::{ManagedChild, ManagedCommandSpec, OwnedRuntimeArtifacts};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRole {
    VmnetBridged,
    VmnetHostOnly,
    Vfkit,
    GuestAgent,
}

impl RuntimeRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::VmnetBridged => "vmnet-bridged",
            Self::VmnetHostOnly => "vmnet-host-only",
            Self::Vfkit => "vfkit",
            Self::GuestAgent => "guest-agent",
        }
    }
}

pub(crate) trait StartupProbe: Send {
    fn ready(&mut self) -> io::Result<bool>;

    fn diagnostic(&self) -> Option<String> {
        None
    }
}

pub(crate) struct FnProbe<F> {
    probe: F,
    last_error: Option<String>,
}

impl<F> FnProbe<F> {
    pub(crate) fn new(probe: F) -> Self {
        Self {
            probe,
            last_error: None,
        }
    }
}

impl<F> StartupProbe for FnProbe<F>
where
    F: FnMut() -> io::Result<bool> + Send,
{
    fn ready(&mut self) -> io::Result<bool> {
        match (self.probe)() {
            Ok(ready) => Ok(ready),
            Err(error) => {
                self.last_error = Some(error.to_string());
                Ok(false)
            }
        }
    }

    fn diagnostic(&self) -> Option<String> {
        self.last_error.clone()
    }
}

pub(crate) struct AlwaysReadyProbe;

impl StartupProbe for AlwaysReadyProbe {
    fn ready(&mut self) -> io::Result<bool> {
        Ok(true)
    }
}

/// vmnet-helper creates a UnixGram socket and waits for vfkit to become its
/// single client. Connecting from a readiness probe would consume that client
/// slot (and is rejected by macOS in some app launch contexts), so readiness is
/// the presence of the helper-created socket instead. vfkit performs the real
/// UnixGram connection once all helpers are ready.
pub(crate) struct UnixSocketPathProbe {
    path: PathBuf,
}

impl UnixSocketPathProbe {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl StartupProbe for UnixSocketPathProbe {
    fn ready(&mut self) -> io::Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} 不是 Unix socket", self.path.display()),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub(crate) struct LaunchStep {
    pub role: RuntimeRole,
    pub command: Option<ManagedCommandSpec>,
    pub probe: Box<dyn StartupProbe>,
    pub timeout: Duration,
    pub pid_file: Option<PathBuf>,
}

pub(crate) struct GatewayRuntimePlan {
    pub artifacts: OwnedRuntimeArtifacts,
    pub steps: Vec<LaunchStep>,
}

impl GatewayRuntimePlan {
    pub(crate) fn new(artifacts: OwnedRuntimeArtifacts, steps: Vec<LaunchStep>) -> Self {
        Self { artifacts, steps }
    }
}

pub(crate) struct GatewayRuntime {
    children: Vec<(RuntimeRole, ManagedChild)>,
    artifacts: OwnedRuntimeArtifacts,
}

impl GatewayRuntime {
    pub(crate) fn start(plan: GatewayRuntimePlan) -> Result<Self, String> {
        fn never_cancelled() -> bool {
            false
        }

        Self::start_with_cancellation(plan, &never_cancelled)
    }

    pub(crate) fn start_with_cancellation(
        plan: GatewayRuntimePlan,
        cancellation: &(dyn Fn() -> bool + Sync),
    ) -> Result<Self, String> {
        let GatewayRuntimePlan {
            mut artifacts,
            steps,
        } = plan;
        let mut children = Vec::new();

        if cancellation() {
            return Err(startup_error(
                RuntimeRole::GuestAgent,
                "启动已取消".into(),
                &mut children,
                &mut artifacts,
            ));
        }

        // Keep the small synthetic plans used by unit tests and diagnostics
        // valid. The production plan contains all four roles and takes the
        // parallel helper path below; a partial plan remains sequential.
        let complete_plan = [
            RuntimeRole::VmnetHostOnly,
            RuntimeRole::VmnetBridged,
            RuntimeRole::Vfkit,
            RuntimeRole::GuestAgent,
        ]
        .iter()
        .all(|role| steps.iter().any(|step| step.role == *role));
        if !complete_plan {
            return Self::start_sequential(artifacts, steps, cancellation);
        }

        let mut host_only = None;
        let mut bridged = None;
        let mut vfkit = None;
        let mut guest_agent = None;
        for step in steps {
            match step.role {
                RuntimeRole::VmnetHostOnly => host_only = Some(step),
                RuntimeRole::VmnetBridged => bridged = Some(step),
                RuntimeRole::Vfkit => vfkit = Some(step),
                RuntimeRole::GuestAgent => guest_agent = Some(step),
            }
        }
        let host_only =
            host_only.ok_or_else(|| "Gateway runtime 缺少 host-only 启动步骤".to_string())?;
        let bridged = bridged.ok_or_else(|| "Gateway runtime 缺少 bridged 启动步骤".to_string())?;
        let vfkit = vfkit.ok_or_else(|| "Gateway runtime 缺少 vfkit 启动步骤".to_string())?;
        let mut guest_agent =
            guest_agent.ok_or_else(|| "Gateway runtime 缺少 guest-agent 启动步骤".to_string())?;

        // The two vmnet providers are independent. Start and probe them in
        // parallel, but keep vfkit behind both readiness gates because it
        // consumes both helper sockets as its network devices.
        let (host_result, bridged_result) = thread::scope(|scope| {
            let host_task = scope.spawn(|| start_step_isolated(host_only, cancellation));
            let bridged_task = scope.spawn(|| start_step_isolated(bridged, cancellation));
            (
                host_task
                    .join()
                    .map_err(|_| "vmnet host-only 启动线程异常退出".to_string())
                    .and_then(|result| result),
                bridged_task
                    .join()
                    .map_err(|_| "vmnet bridged 启动线程异常退出".to_string())
                    .and_then(|result| result),
            )
        });
        let mut helper_errors = Vec::new();
        for result in [host_result, bridged_result] {
            match result {
                Ok((role, Some(child))) => children.push((role, child)),
                Ok((_, None)) => helper_errors.push("vmnet helper 步骤没有产生进程".to_string()),
                Err(error) => helper_errors.push(error),
            }
        }
        if cancellation() {
            return Err(startup_error(
                RuntimeRole::VmnetBridged,
                "启动已取消".into(),
                &mut children,
                &mut artifacts,
            ));
        }
        if !helper_errors.is_empty() {
            return Err(startup_error(
                RuntimeRole::VmnetBridged,
                helper_errors.join("；"),
                &mut children,
                &mut artifacts,
            ));
        }

        if let Err(error) = ensure_children_running(&mut children) {
            return Err(startup_error(
                RuntimeRole::Vfkit,
                error,
                &mut children,
                &mut artifacts,
            ));
        }

        let (vfkit_role, vfkit_child) =
            start_step_isolated(vfkit, cancellation).map_err(|error| {
                startup_error(RuntimeRole::Vfkit, error, &mut children, &mut artifacts)
            })?;
        if let Some(child) = vfkit_child {
            children.push((vfkit_role, child));
        }
        let guest_index = children.len();
        wait_for_step(&mut guest_agent, None, &mut children, cancellation).map_err(|error| {
            startup_error(
                RuntimeRole::GuestAgent,
                error,
                &mut children,
                &mut artifacts,
            )
        })?;
        debug_assert_eq!(guest_index, children.len());

        Ok(Self {
            children,
            artifacts,
        })
    }

    fn start_sequential(
        mut artifacts: OwnedRuntimeArtifacts,
        steps: Vec<LaunchStep>,
        cancellation: &(dyn Fn() -> bool + Sync),
    ) -> Result<Self, String> {
        let mut children = Vec::new();
        for mut step in steps {
            if cancellation() {
                return Err(startup_error(
                    step.role,
                    "启动已取消".into(),
                    &mut children,
                    &mut artifacts,
                ));
            }
            let child_index = if let Some(command) = step.command.as_ref() {
                let child = ManagedChild::spawn(command).map_err(|error| {
                    startup_error(
                        step.role,
                        format!("启动失败：{error}"),
                        &mut children,
                        &mut artifacts,
                    )
                })?;
                children.push((step.role, child));
                Some(children.len() - 1)
            } else {
                None
            };

            if let Some(index) = child_index {
                if let Some(pid_file) = step.pid_file.as_ref() {
                    let pid = children[index].1.leader_pid().map_err(|error| {
                        startup_error(step.role, error.to_string(), &mut children, &mut artifacts)
                    })?;
                    std::fs::write(pid_file, format!("{pid}\n")).map_err(|error| {
                        startup_error(
                            step.role,
                            format!("写入 PID 文件失败：{error}"),
                            &mut children,
                            &mut artifacts,
                        )
                    })?;
                }
            }
            wait_for_step(&mut step, child_index, &mut children, cancellation)
                .map_err(|error| startup_error(step.role, error, &mut children, &mut artifacts))?;
        }
        Ok(Self {
            children,
            artifacts,
        })
    }

    pub(crate) fn stop(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + GATEWAY_CHILD_STOP_GRACE;
        let mut pending = self.children.drain(..).collect::<Vec<_>>();
        let mut errors = Vec::new();
        let mut request_errors = Vec::with_capacity(pending.len());
        for (role, child) in &mut pending {
            request_errors.push(
                child
                    .request_stop()
                    .err()
                    .map(|error| format!("发送 {} 停止信号失败：{error}", role.as_str())),
            );
        }

        // All signals are sent before any wait begins. The shared deadline
        // keeps vfkit and both helpers from paying their grace periods in
        // series, while finish_stop_until still confirms every child is gone.
        let mut survivors = Vec::new();
        thread::scope(|scope| {
            let tasks = pending
                .into_iter()
                .zip(request_errors)
                .map(|((role, mut child), request_error)| {
                    scope.spawn(move || {
                        let finish = child.finish_stop_until(deadline);
                        (role, child, request_error, finish)
                    })
                })
                .collect::<Vec<_>>();
            for task in tasks {
                match task.join() {
                    Ok((_role, child, request_error, Ok(()))) => {
                        // A process that was already gone is a successful
                        // stop even if its initial signal raced with exit.
                        let _ = request_error;
                        drop(child);
                    }
                    Ok((role, child, request_error, Err(error))) => {
                        if let Some(request_error) = request_error {
                            errors.push(request_error);
                        }
                        errors.push(format!("停止 {} 失败：{error}", role.as_str()));
                        survivors.push((role, child));
                    }
                    Err(_) => errors.push("停止 Gateway 进程的回收线程异常退出".into()),
                }
            }
        });
        self.children = survivors;
        if self.children.is_empty() {
            if let Err(error) = self.artifacts.cleanup() {
                errors.push(format!("清理 Gateway 运行文件失败：{error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("；"))
        }
    }

    pub(crate) fn leaders_running(&mut self) -> io::Result<bool> {
        for (_, child) in &mut self.children {
            if !child.leader_running()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Drop for GatewayRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn wait_for_step(
    step: &mut LaunchStep,
    child_index: Option<usize>,
    children: &mut [(RuntimeRole, ManagedChild)],
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let deadline = Instant::now() + step.timeout;
    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        if let Some(index) = child_index {
            if !children[index]
                .1
                .leader_running()
                .map_err(|error| format!("检查 {} 进程失败：{error}", step.role.as_str()))?
            {
                let output = children[index].1.output_summary();
                return Err(if output.is_empty() {
                    format!("{} 进程提前退出", step.role.as_str())
                } else {
                    format!("{} 进程提前退出：{output}", step.role.as_str())
                });
            }
        }
        for (role, child) in children.iter_mut() {
            if *role == step.role {
                continue;
            }
            if !child
                .leader_running()
                .map_err(|error| format!("检查 {} 进程失败：{error}", role.as_str()))?
            {
                let output = child.output_summary();
                return Err(if output.is_empty() {
                    format!("{} 进程提前退出", role.as_str())
                } else {
                    format!("{} 进程提前退出：{output}", role.as_str())
                });
            }
        }
        if step
            .probe
            .ready()
            .map_err(|error| format!("检查 {} readiness 失败：{error}", step.role.as_str()))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let diagnostic = step
                .probe
                .diagnostic()
                .map(|value| format!("；最后一次探测：{value}"))
                .unwrap_or_default();
            return Err(format!(
                "{} readiness 超时{}",
                step.role.as_str(),
                diagnostic
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn start_step_isolated(
    mut step: LaunchStep,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(RuntimeRole, Option<ManagedChild>), String> {
    let role = step.role;
    let mut child = if let Some(command) = step.command.as_ref() {
        match ManagedChild::spawn(command) {
            Ok(child) => Some(child),
            Err(error) => return Err(format!("{} 启动失败：{error}", role.as_str())),
        }
    } else {
        None
    };

    if let (Some(child), Some(pid_file)) = (child.as_mut(), step.pid_file.as_ref()) {
        let pid = match child.leader_pid() {
            Ok(pid) => pid,
            Err(error) => {
                let _ = child.stop_group(GATEWAY_CHILD_STOP_GRACE);
                return Err(format!("{} 获取 PID 失败：{error}", role.as_str()));
            }
        };
        if let Err(error) = fs::write(pid_file, format!("{pid}\n")) {
            let _ = child.stop_group(GATEWAY_CHILD_STOP_GRACE);
            return Err(format!("{} 写入 PID 文件失败：{error}", role.as_str()));
        }
    }

    if let Err(error) = wait_for_step_single(&mut step, child.as_mut(), cancellation) {
        if let Some(child) = child.as_mut() {
            let _ = child.stop_group(GATEWAY_CHILD_STOP_GRACE);
        }
        return Err(error);
    }
    Ok((role, child))
}

fn wait_for_step_single(
    step: &mut LaunchStep,
    mut child: Option<&mut ManagedChild>,
    cancellation: &(dyn Fn() -> bool + Sync),
) -> Result<(), String> {
    let deadline = Instant::now() + step.timeout;
    loop {
        if cancellation() {
            return Err("启动已取消".into());
        }
        if let Some(child) = child.as_deref_mut() {
            if !child
                .leader_running()
                .map_err(|error| format!("检查 {} 进程失败：{error}", step.role.as_str()))?
            {
                let output = child.output_summary();
                return Err(if output.is_empty() {
                    format!("{} 进程提前退出", step.role.as_str())
                } else {
                    format!("{} 进程提前退出：{output}", step.role.as_str())
                });
            }
        }
        if step
            .probe
            .ready()
            .map_err(|error| format!("检查 {} readiness 失败：{error}", step.role.as_str()))?
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let diagnostic = step
                .probe
                .diagnostic()
                .map(|value| format!("；最后一次探测：{value}"))
                .unwrap_or_default();
            return Err(format!(
                "{} readiness 超时{}",
                step.role.as_str(),
                diagnostic
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn ensure_children_running(children: &mut [(RuntimeRole, ManagedChild)]) -> Result<(), String> {
    for (role, child) in children {
        if !child
            .leader_running()
            .map_err(|error| format!("检查 {} 进程失败：{error}", role.as_str()))?
        {
            let output = child.output_summary();
            return Err(if output.is_empty() {
                format!("{} 进程在 vfkit 启动前退出", role.as_str())
            } else {
                format!("{} 进程在 vfkit 启动前退出：{output}", role.as_str())
            });
        }
    }
    Ok(())
}

fn startup_error(
    role: RuntimeRole,
    message: String,
    children: &mut Vec<(RuntimeRole, ManagedChild)>,
    artifacts: &mut OwnedRuntimeArtifacts,
) -> String {
    let mut cleanup_errors = Vec::new();
    while let Some((child_role, mut child)) = children.pop() {
        if let Err(error) = child.stop_group(GATEWAY_CHILD_STOP_GRACE) {
            cleanup_errors.push(format!("停止 {} 失败：{error}", child_role.as_str()));
        }
    }
    if let Err(error) = artifacts.cleanup() {
        cleanup_errors.push(format!("清理运行文件失败：{error}"));
    }
    if cleanup_errors.is_empty() {
        format!("{}：{message}", role.as_str())
    } else {
        format!(
            "{}：{message}；回收失败：{}",
            role.as_str(),
            cleanup_errors.join("；")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_group::unique_runtime_dir;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn plan_with_probe(probe: Box<dyn StartupProbe>, timeout: Duration) -> GatewayRuntimePlan {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        artifacts
            .register_file(runtime_dir.join("vfkit.pid"))
            .unwrap();
        GatewayRuntimePlan::new(
            artifacts,
            vec![LaunchStep {
                role: RuntimeRole::Vfkit,
                command: Some(
                    ManagedCommandSpec::new("vfkit-test", "/bin/sh").with_args(["-c", "sleep 30"]),
                ),
                probe,
                timeout,
                pid_file: Some(runtime_dir.join("vfkit.pid")),
            }],
        )
    }

    #[test]
    fn startup_timeout_rolls_back_children_and_artifacts() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        let socket = runtime_dir.join("helper.sock");
        artifacts.register_file(socket.clone()).unwrap();
        let plan = GatewayRuntimePlan::new(
            artifacts,
            vec![LaunchStep {
                role: RuntimeRole::VmnetBridged,
                command: Some(
                    ManagedCommandSpec::new("helper-test", "/bin/sh").with_args(["-c", "sleep 30"]),
                ),
                probe: Box::new(FnProbe::new(|| Ok(false))),
                timeout: Duration::from_millis(30),
                pid_file: None,
            }],
        );
        let error = match GatewayRuntime::start(plan) {
            Ok(_) => panic!("startup should time out"),
            Err(error) => error,
        };
        assert!(error.contains("readiness 超时"));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn cancellation_rolls_back_a_started_step_without_waiting_for_timeout() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        let artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        let checks = Arc::new(AtomicUsize::new(0));
        let cancellation_checks = Arc::clone(&checks);
        let cancellation = move || cancellation_checks.fetch_add(1, Ordering::SeqCst) >= 2;
        let plan = GatewayRuntimePlan::new(
            artifacts,
            vec![LaunchStep {
                role: RuntimeRole::Vfkit,
                command: Some(
                    ManagedCommandSpec::new("vfkit-test", "/bin/sh").with_args(["-c", "sleep 30"]),
                ),
                probe: Box::new(FnProbe::new(|| Ok(false))),
                timeout: Duration::from_secs(30),
                pid_file: None,
            }],
        );
        let started = Instant::now();
        let error = match GatewayRuntime::start_with_cancellation(plan, &cancellation) {
            Ok(_) => panic!("startup should be cancelled"),
            Err(error) => error,
        };
        assert_eq!(error, "vfkit：启动已取消");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn guest_barrier_reports_a_previous_vfkit_exit() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        let artifacts = OwnedRuntimeArtifacts::new(runtime_dir).unwrap();
        let plan = GatewayRuntimePlan::new(
            artifacts,
            vec![
                LaunchStep {
                    role: RuntimeRole::Vfkit,
                    command: Some(
                        ManagedCommandSpec::new("vfkit", "/bin/sh").with_args(["-c", "sleep 0.05"]),
                    ),
                    probe: Box::new(AlwaysReadyProbe),
                    timeout: Duration::from_secs(1),
                    pid_file: None,
                },
                LaunchStep {
                    role: RuntimeRole::GuestAgent,
                    command: None,
                    probe: Box::new(FnProbe::new(|| Ok(false))),
                    timeout: Duration::from_millis(500),
                    pid_file: None,
                },
            ],
        );
        let error = match GatewayRuntime::start(plan) {
            Ok(_) => panic!("guest barrier should report the exited vfkit"),
            Err(error) => error,
        };
        assert!(error.contains("vfkit 进程提前退出"));
    }

    #[test]
    fn readiness_timeout_keeps_last_probe_error() {
        let probe = FnProbe::new(|| {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "guest agent connection refused",
            ))
        });
        let error = match GatewayRuntime::start(plan_with_probe(
            Box::new(probe),
            Duration::from_millis(30),
        )) {
            Ok(_) => panic!("probe should time out"),
            Err(error) => error,
        };
        assert!(error.contains("最后一次探测：guest agent connection refused"));
    }

    #[test]
    fn runtime_start_and_stop_are_ordered_and_idempotent() {
        let mut runtime = GatewayRuntime::start(plan_with_probe(
            Box::new(AlwaysReadyProbe),
            Duration::from_secs(1),
        ))
        .unwrap();
        runtime.stop().unwrap();
        runtime.stop().unwrap();
    }

    #[test]
    fn complete_gateway_plan_starts_vmnet_helpers_in_parallel() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        for name in ["host.pid", "bridged.pid", "vfkit.pid"] {
            artifacts.register_file(runtime_dir.join(name)).unwrap();
        }
        let delayed_probe = || {
            let started = Instant::now();
            Box::new(FnProbe::new(move || {
                Ok(started.elapsed() >= Duration::from_millis(120))
            })) as Box<dyn StartupProbe>
        };
        let plan = GatewayRuntimePlan::new(
            artifacts,
            vec![
                LaunchStep {
                    role: RuntimeRole::VmnetHostOnly,
                    command: Some(
                        ManagedCommandSpec::new("host-only-test", "/bin/sh")
                            .with_args(["-c", "sleep 30"]),
                    ),
                    probe: delayed_probe(),
                    timeout: Duration::from_secs(1),
                    pid_file: Some(runtime_dir.join("host.pid")),
                },
                LaunchStep {
                    role: RuntimeRole::VmnetBridged,
                    command: Some(
                        ManagedCommandSpec::new("bridged-test", "/bin/sh")
                            .with_args(["-c", "sleep 30"]),
                    ),
                    probe: delayed_probe(),
                    timeout: Duration::from_secs(1),
                    pid_file: Some(runtime_dir.join("bridged.pid")),
                },
                LaunchStep {
                    role: RuntimeRole::Vfkit,
                    command: Some(
                        ManagedCommandSpec::new("vfkit-test", "/bin/sh")
                            .with_args(["-c", "sleep 30"]),
                    ),
                    probe: Box::new(AlwaysReadyProbe),
                    timeout: Duration::from_secs(1),
                    pid_file: Some(runtime_dir.join("vfkit.pid")),
                },
                LaunchStep {
                    role: RuntimeRole::GuestAgent,
                    command: None,
                    probe: Box::new(AlwaysReadyProbe),
                    timeout: Duration::from_secs(1),
                    pid_file: None,
                },
            ],
        );
        let started = Instant::now();
        let mut runtime = GatewayRuntime::start(plan).unwrap();
        assert!(started.elapsed() < Duration::from_millis(220));
        runtime.stop().unwrap();
    }

    #[test]
    fn existing_runtime_directory_is_rejected() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        fs::create_dir_all(&runtime_dir).unwrap();
        assert!(OwnedRuntimeArtifacts::new(runtime_dir.clone()).is_err());
        fs::remove_dir_all(runtime_dir).unwrap();
    }

    #[test]
    fn unix_socket_path_probe_accepts_vmnet_helper_socket() {
        let runtime_dir = unique_runtime_dir(std::env::temp_dir());
        fs::create_dir_all(&runtime_dir).unwrap();
        let socket_path = runtime_dir.join("vmnet-helper.sock");
        let socket = std::os::unix::net::UnixDatagram::bind(&socket_path).unwrap();
        let mut probe = UnixSocketPathProbe::new(socket_path.clone());
        assert!(probe.ready().unwrap());
        drop(socket);
        fs::remove_dir_all(runtime_dir).unwrap();
    }
}
