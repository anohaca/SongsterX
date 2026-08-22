use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FORCE_STOP_CONFIRM_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub(crate) struct ManagedCommandSpec {
    pub role: String,
    pub program: PathBuf,
    pub args: Vec<OsString>,
    launchd_logs: Option<(PathBuf, PathBuf)>,
    launchd_plist: Option<PathBuf>,
}

impl ManagedCommandSpec {
    pub(crate) fn new(role: impl Into<String>, program: impl Into<PathBuf>) -> Self {
        Self {
            role: role.into(),
            program: program.into(),
            args: Vec::new(),
            launchd_logs: None,
            launchd_plist: None,
        }
    }

    pub(crate) fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub(crate) fn with_launchd_logs(mut self, stdout_path: PathBuf, stderr_path: PathBuf) -> Self {
        let plist_path = stdout_path
            .parent()
            .map(|parent| parent.join(format!("{}.launchd.plist", self.role)));
        self.launchd_logs = Some((stdout_path, stderr_path));
        self.launchd_plist = plist_path;
        self
    }
}

pub(crate) struct ManagedChild {
    role: String,
    child: Option<Child>,
    process_group_id: Option<libc::pid_t>,
    launchd_job: Option<LaunchdJob>,
    output: std::sync::Arc<std::sync::Mutex<String>>,
    output_threads: Vec<thread::JoinHandle<()>>,
}

impl ManagedChild {
    pub(crate) fn spawn(spec: &ManagedCommandSpec) -> io::Result<Self> {
        if let Some((stdout_path, stderr_path)) = spec.launchd_logs.as_ref() {
            let job = LaunchdJob::submit(
                spec,
                stdout_path,
                stderr_path,
                spec.launchd_plist.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "launchd plist 路径缺失")
                })?,
            )?;
            return Ok(Self {
                role: spec.role.clone(),
                child: None,
                process_group_id: None,
                launchd_job: Some(job),
                output: std::sync::Arc::new(std::sync::Mutex::new(String::new())),
                output_threads: Vec::new(),
            });
        }

        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if spec.role.starts_with("vmnet-") {
            // vmnet uses XPC internally. A GUI app can inherit launch-context
            // variables from Tauri, Finder, or a development sandbox; those
            // variables can make vmnet_start_interface return VMNET_FAILURE.
            // The helper only needs the system executable search path.
            command.env_clear();
            command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        }
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut child = command.spawn()?;
        let output = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut output_threads = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            output_threads.push(capture_output(stdout, output.clone()));
        }
        if let Some(stderr) = child.stderr.take() {
            output_threads.push(capture_output(stderr, output.clone()));
        }
        Ok(Self {
            role: spec.role.clone(),
            process_group_id: Some(child.id() as libc::pid_t),
            launchd_job: None,
            child: Some(child),
            output,
            output_threads,
        })
    }

    pub(crate) fn role(&self) -> &str {
        &self.role
    }

    pub(crate) fn leader_pid(&self) -> io::Result<u32> {
        if let Some(child) = self.child.as_ref() {
            return Ok(child.id());
        }
        if let Some(job) = self.launchd_job.as_ref() {
            return job.wait_for_pid(Duration::from_secs(1));
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "child already stopped",
        ))
    }

    pub(crate) fn leader_running(&mut self) -> io::Result<bool> {
        if let Some(job) = self.launchd_job.as_ref() {
            let running = job.running()?;
            if !running {
                self.read_launchd_output();
            }
            return Ok(running);
        }

        let Some(child) = self.child.as_mut() else {
            return Ok(false);
        };
        let running = child.try_wait()?.is_none();
        if !running {
            self.collect_output();
        }
        Ok(running)
    }

    pub(crate) fn output_summary(&mut self) -> String {
        self.read_launchd_output();
        self.collect_output();
        self.output
            .lock()
            .map(|output| output.trim().to_string())
            .unwrap_or_default()
    }

    fn collect_output(&mut self) {
        while let Some(thread) = self.output_threads.pop() {
            let _ = thread.join();
        }
    }

    fn read_launchd_output(&mut self) {
        let Some(job) = self.launchd_job.as_ref() else {
            return;
        };
        let mut output = String::new();
        for path in [&job.stdout_path, &job.stderr_path] {
            if let Ok(bytes) = fs::read(path) {
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        if output.len() > 16 * 1024 {
            let trim_before = output.len() - 16 * 1024;
            let boundary = output
                .char_indices()
                .find(|(index, _)| *index >= trim_before)
                .map(|(index, _)| index)
                .unwrap_or(0);
            output.drain(..boundary);
        }
        if let Ok(mut current) = self.output.lock() {
            *current = output;
        }
    }

    fn group_exists(&self) -> io::Result<bool> {
        let Some(process_group_id) = self.process_group_id else {
            return Ok(false);
        };
        let result = unsafe { libc::kill(-process_group_id, 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(_) => Ok(true),
            None => Err(error),
        }
    }

    fn signal_group(&self, signal: libc::c_int) -> io::Result<()> {
        let Some(process_group_id) = self.process_group_id else {
            return Ok(());
        };
        if !self.group_exists()? {
            return Ok(());
        }
        let result = unsafe { libc::kill(-process_group_id, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(()),
            _ => Err(io::Error::new(
                error.kind(),
                format!(
                    "kill process group {} with signal {} failed: {}",
                    process_group_id, signal, error
                ),
            )),
        }
    }

    pub(crate) fn stop_group(&mut self, grace: Duration) -> io::Result<()> {
        let deadline = Instant::now() + grace;
        let request_error = self.request_stop().err();
        let finish_error = self.finish_stop_until(deadline).err();
        match (request_error, finish_error) {
            (None, None) => Ok(()),
            (Some(error), None) => Err(error),
            (None, Some(error)) => Err(error),
            (Some(request), Some(finish)) => Err(io::Error::new(
                finish.kind(),
                format!("发送停止信号失败：{request}；完成停止失败：{finish}"),
            )),
        }
    }

    /// Send the graceful stop signal without waiting for the child to exit.
    /// This lets the caller signal vfkit, both vmnet helpers, and local
    /// processes before any one process consumes its grace period.
    pub(crate) fn request_stop(&mut self) -> io::Result<()> {
        if let Some(job) = self.launchd_job.as_ref() {
            return job.request_stop();
        }
        if self.child.is_none() {
            return Ok(());
        }
        if self.role == "vfkit" {
            return self.signal_leader(libc::SIGTERM);
        }
        self.signal_group(libc::SIGTERM)
    }

    /// Finish a stop using a shared deadline. A SIGKILL fallback remains in
    /// place, and the method only reports success after the process/job is
    /// confirmed gone so callers can safely remove vmnet sockets.
    pub(crate) fn finish_stop_until(&mut self, deadline: Instant) -> io::Result<()> {
        if let Some(job) = self.launchd_job.clone() {
            let result = job.finish_stop_until(deadline);
            self.read_launchd_output_from(&job);
            self.collect_output();
            if result.is_ok() {
                self.launchd_job = None;
            }
            return result;
        }

        if self.child.is_none() {
            // A vfkit leader can exit before a child it created has left its
            // process group. Keep the group id until that owned group is
            // confirmed gone so a retry can still finish the cleanup.
            if self.role == "vfkit" && self.process_group_id.is_some() {
                return self.finish_owned_group_until(deadline);
            }
            return Ok(());
        }

        // vfkit may place helper-created descendants in a different process
        // group. Stop the owned leader first, then reap the process group we
        // created for it. If Darwin rejects that group signal, retain the
        // ownership marker and let the caller retry instead of pretending the
        // Gateway is fully stopped.
        if self.role == "vfkit" {
            return self.finish_leader_stop_until(deadline);
        }

        let process_group_id = self.process_group_id;
        while self.group_exists()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if self.group_exists()? {
            if let Err(error) = self.signal_group(libc::SIGKILL) {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    if let Some(child) = self.child.as_mut() {
                        child.kill()?;
                        child.wait()?;
                    }
                    self.child = None;
                    self.process_group_id = None;
                    self.collect_output();
                    if self.group_exists()? {
                        return Err(error);
                    }
                    return Ok(());
                }
                return Err(error);
            }
        }

        if let Some(child) = self.child.as_mut() {
            let _ = child.wait()?;
        }
        self.child = None;
        self.process_group_id = None;
        self.collect_output();
        let group_still_exists = process_group_id
            .map(|group_id| unsafe { libc::kill(-group_id, 0) == 0 })
            .unwrap_or(false);
        if group_still_exists {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "{} process group {} still exists",
                    self.role,
                    process_group_id.unwrap_or_default()
                ),
            ));
        }
        Ok(())
    }

    fn signal_leader(&self, signal: libc::c_int) -> io::Result<()> {
        let Some(child) = self.child.as_ref() else {
            return Ok(());
        };
        let result = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(io::Error::new(
                error.kind(),
                format!(
                    "kill {} leader with signal {} failed: {}",
                    self.role, signal, error
                ),
            ))
        }
    }

    fn finish_leader_stop_until(&mut self, deadline: Instant) -> io::Result<()> {
        if self.child.is_none() {
            return self.finish_owned_group_until(deadline);
        }
        let mut force_kill = false;
        while self
            .child
            .as_mut()
            .expect("child checked above")
            .try_wait()?
            .is_none()
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        if self
            .child
            .as_mut()
            .expect("child checked above")
            .try_wait()?
            .is_none()
        {
            force_kill = true;
        }

        if force_kill {
            // The group was created by pre_exec/setpgid immediately before
            // vfkit was spawned, so every member still in it is runtime-owned.
            // Prefer the group kill to avoid leaving a vfkit child behind.
            if self.signal_group(libc::SIGKILL).is_err() {
                if let Some(child) = self.child.as_mut() {
                    child.kill()?;
                }
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.wait()?;
        }
        self.child = None;
        self.collect_output();
        self.finish_owned_group_until(deadline)
    }

    fn finish_owned_group_until(&mut self, deadline: Instant) -> io::Result<()> {
        let Some(process_group_id) = self.process_group_id else {
            return Ok(());
        };
        if self.group_exists()? {
            if let Err(error) = self.signal_group(libc::SIGKILL) {
                return Err(error);
            }
        }
        let confirm_deadline = std::cmp::min(
            deadline + FORCE_STOP_CONFIRM_GRACE,
            Instant::now() + FORCE_STOP_CONFIRM_GRACE,
        );
        while self.group_exists()? && Instant::now() < confirm_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if self.group_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("vfkit owned process group {process_group_id} still exists"),
            ));
        }
        self.process_group_id = None;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_group_exists(&self) -> io::Result<bool> {
        self.group_exists()
    }

    fn read_launchd_output_from(&mut self, job: &LaunchdJob) {
        let mut output = String::new();
        for path in [&job.stdout_path, &job.stderr_path] {
            if let Ok(bytes) = fs::read(path) {
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        if let Ok(mut current) = self.output.lock() {
            *current = output;
        }
    }
}

#[derive(Clone)]
struct LaunchdJob {
    label: String,
    target: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    plist_path: PathBuf,
}

impl LaunchdJob {
    fn submit(
        spec: &ManagedCommandSpec,
        stdout_path: &PathBuf,
        stderr_path: &PathBuf,
        plist_path: &PathBuf,
    ) -> io::Result<Self> {
        let label = format!("com.songsterx.gateway.{}", spec.role);
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let target = format!("{domain}/{label}");
        let existing = launchctl_command().arg("print").arg(&target).output()?;
        if existing.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "launchd job {} 已存在，拒绝启动第二个实例；请先停止旧 Gateway。状态：{}",
                    label,
                    command_output(&existing)
                ),
            ));
        }
        let plist = launchd_plist(&label, &spec.program, &spec.args, stdout_path, stderr_path);
        fs::write(plist_path, plist)?;
        let output = launchctl_command()
            .arg("bootstrap")
            .arg(&domain)
            .arg(plist_path)
            .output()?;
        if !output.status.success() {
            let _ = fs::remove_file(plist_path);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "launchctl bootstrap {} 失败：{}",
                    label,
                    command_output(&output)
                ),
            ));
        }
        Ok(Self {
            label,
            target,
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            plist_path: plist_path.clone(),
        })
    }

    fn running(&self) -> io::Result<bool> {
        let output = launchctl_command()
            .arg("print")
            .arg(&self.target)
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        Ok(parse_launchd_pid(&output.stdout).is_some())
    }

    fn wait_for_pid(&self, timeout: Duration) -> io::Result<u32> {
        let deadline = Instant::now() + timeout;
        loop {
            let output = launchctl_command()
                .arg("print")
                .arg(&self.target)
                .output()?;
            if output.status.success() {
                if let Some(pid) = parse_launchd_pid(&output.stdout) {
                    return Ok(pid);
                }
            }
            if Instant::now() >= deadline {
                let state = launchctl_command()
                    .arg("print")
                    .arg(&self.target)
                    .output()
                    .map(|output| command_output(&output))
                    .unwrap_or_else(|error| error.to_string());
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("launchd job {} 未进入运行状态；状态：{}", self.label, state),
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn request_stop(&self) -> io::Result<()> {
        if !self.running()? {
            return Ok(());
        }
        let kill = launchctl_command()
            .arg("kill")
            .arg("SIGTERM")
            .arg(&self.target)
            .status()?;
        if kill.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("launchctl kill SIGTERM {} 失败", self.label),
            ))
        }
    }

    fn finish_stop_until(&self, deadline: Instant) -> io::Result<()> {
        let mut first_error = None;
        while self.running()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if self.running()? {
            let kill = launchctl_command()
                .arg("kill")
                .arg("SIGKILL")
                .arg(&self.target)
                .status()?;
            if !kill.success() {
                first_error = Some(io::Error::new(
                    io::ErrorKind::Other,
                    format!("launchctl kill SIGKILL {} 失败", self.label),
                ));
            }
            let kill_deadline = Instant::now() + FORCE_STOP_CONFIRM_GRACE;
            while self.running()? && Instant::now() < kill_deadline {
                thread::sleep(Duration::from_millis(20));
            }
        }

        let remove = launchctl_command()
            .arg("bootout")
            .arg(&self.target)
            .status()?;
        if !remove.success() && first_error.is_none() {
            first_error = Some(io::Error::new(
                io::ErrorKind::Other,
                format!("launchctl bootout {} 失败", self.label),
            ));
        }
        let still_running = self.running()?;
        if still_running && first_error.is_none() {
            first_error = Some(io::Error::new(
                io::ErrorKind::Other,
                format!("launchd job {} 仍在运行", self.label),
            ));
        }
        if !still_running {
            let _ = fs::remove_file(&self.plist_path);
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn launchctl_command() -> Command {
    let mut command = Command::new("/bin/launchctl");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    // A Tauri application is itself started from a launchd bootstrap context.
    // Calling launchctl directly from that context can return "Reentrancy
    // avoided". Re-enter the user's GUI domain through `asuser` instead.
    command
        .arg("asuser")
        .arg(unsafe { libc::getuid().to_string() })
        .arg("/bin/launchctl");
    command
}

fn launchd_plist(
    label: &str,
    program: &PathBuf,
    args: &[OsString],
    stdout_path: &PathBuf,
    stderr_path: &PathBuf,
) -> String {
    let mut arguments = String::new();
    arguments.push_str("        <string>");
    arguments.push_str(&xml_escape(&program.to_string_lossy()));
    arguments.push_str("</string>\n");
    for arg in args {
        arguments.push_str("        <string>");
        arguments.push_str(&xml_escape(&arg.to_string_lossy()));
        arguments.push_str("</string>\n");
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
    <key>Label</key>\n    <string>{}</string>\n\
    <key>ProgramArguments</key>\n    <array>\n{}{}</array>\n\
    <key>RunAtLoad</key>\n    <true/>\n\
    <key>EnvironmentVariables</key>\n    <dict>\n\
        <key>PATH</key>\n        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>\n\
    </dict>\n\
    <key>StandardOutPath</key>\n    <string>{}</string>\n\
    <key>StandardErrorPath</key>\n    <string>{}</string>\n\
</dict>\n</plist>\n",
        xml_escape(label),
        arguments,
        "",
        xml_escape(&stdout_path.to_string_lossy()),
        xml_escape(&stderr_path.to_string_lossy()),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

fn parse_launchd_pid(output: &[u8]) -> Option<u32> {
    String::from_utf8_lossy(output)
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.parse().ok())
}

fn command_output(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        stderr
    }
}

fn capture_output<R>(
    mut reader: R,
    output: std::sync::Arc<std::sync::Mutex<String>>,
) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(size) => {
                    let text = String::from_utf8_lossy(&buffer[..size]);
                    if let Ok(mut output) = output.lock() {
                        output.push_str(&text);
                        const MAX_OUTPUT_BYTES: usize = 16 * 1024;
                        if output.len() > MAX_OUTPUT_BYTES {
                            let trim_before = output.len() - MAX_OUTPUT_BYTES;
                            let boundary = output
                                .char_indices()
                                .find(|(index, _)| *index >= trim_before)
                                .map(|(index, _)| index)
                                .unwrap_or(0);
                            output.drain(..boundary);
                        }
                    }
                }
            }
        }
    })
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.stop_group(Duration::from_millis(250));
    }
}

pub(crate) struct OwnedRuntimeArtifacts {
    runtime_dir: PathBuf,
    files: Vec<PathBuf>,
}

impl OwnedRuntimeArtifacts {
    pub(crate) fn empty() -> Self {
        Self {
            runtime_dir: PathBuf::new(),
            files: Vec::new(),
        }
    }

    pub(crate) fn new(runtime_dir: PathBuf) -> io::Result<Self> {
        if runtime_dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "runtime directory already exists: {}",
                    runtime_dir.display()
                ),
            ));
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&runtime_dir)?;
        Ok(Self {
            runtime_dir,
            files: Vec::new(),
        })
    }

    pub(crate) fn register_file(&mut self, path: PathBuf) -> io::Result<()> {
        if path == self.runtime_dir
            || path.strip_prefix(&self.runtime_dir).is_err()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "runtime artifact must be inside {}: {}",
                    self.runtime_dir.display(),
                    path.display()
                ),
            ));
        }
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("runtime artifact already exists: {}", path.display()),
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.files.push(path);
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        let mut first_error = None;
        for path in self.files.iter().rev() {
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        // vfkit and vmnet-helper create runtime-owned endpoints lazily after
        // startup (including vfkit's implicit UnixGram client socket). Those
        // files are not all known when the plan is built, so removing only the
        // registered files can leave the directory non-empty on shutdown.
        // This directory was created exclusively by this owner and is never
        // reused, therefore remove its remaining contents as one unit.
        if let Err(error) = fs::remove_dir_all(&self.runtime_dir) {
            if error.kind() != io::ErrorKind::NotFound && first_error.is_none() {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for OwnedRuntimeArtifacts {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(crate) fn unique_runtime_dir(parent: PathBuf) -> PathBuf {
    static NEXT_RUNTIME_ID: AtomicU64 = AtomicU64::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let sequence = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        "sxg-{:x}-{timestamp:x}-{sequence:x}",
        std::process::id(),
    ))
}

pub(crate) fn runtime_parent_dir(preferred: PathBuf) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // Leave room for vfkit's implicit client endpoint in the same
        // directory as the server socket.
        let probe = preferred
            .join("sxg-ffffffff-ffffffffffffffffffffffff-ffffffffffffffff")
            .join("vfkit-ffffffff-ffff.sock");
        if probe.as_os_str().to_string_lossy().len() < 104 {
            return preferred;
        }
        return PathBuf::from("/tmp");
    }
    #[cfg(not(target_os = "macos"))]
    {
        preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "songsterx-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn stop_group_is_idempotent_for_a_real_child() {
        let spec = ManagedCommandSpec::new("test-process", "/bin/sleep").with_args(["30"]);
        let mut child = ManagedChild::spawn(&spec).unwrap();
        assert!(child.leader_running().unwrap());
        child.stop_group(Duration::from_millis(100)).unwrap();
        child.stop_group(Duration::from_millis(100)).unwrap();
        assert!(!child.test_group_exists().unwrap());
    }

    #[test]
    fn vfkit_stop_targets_only_the_owned_leader() {
        let spec = ManagedCommandSpec::new("vfkit", "/bin/sleep").with_args(["30"]);
        let mut child = ManagedChild::spawn(&spec).unwrap();
        child.stop_group(Duration::from_millis(100)).unwrap();
        assert!(!child.test_group_exists().unwrap());
    }

    #[test]
    fn vfkit_stop_reaps_owned_process_group_descendants() {
        let spec = ManagedCommandSpec::new("vfkit", "/bin/sh").with_args(["-c", "sleep 30"]);
        let mut child = ManagedChild::spawn(&spec).unwrap();
        child.stop_group(Duration::from_millis(100)).unwrap();
        assert!(!child.test_group_exists().unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_job_is_started_and_stopped_with_diagnostics() {
        let stdout_path = temp_path("launchd-stdout");
        let stderr_path = temp_path("launchd-stderr");
        let spec = ManagedCommandSpec::new("vmnet-launchd-test", "/bin/sh")
            .with_args(["-c", "printf launchd-ready; sleep 30"])
            .with_launchd_logs(stdout_path.clone(), stderr_path.clone());
        let mut child = ManagedChild::spawn(&spec).unwrap();
        assert!(child.leader_pid().unwrap() > 0);
        assert!(child.leader_running().unwrap());
        thread::sleep(Duration::from_millis(100));
        child.stop_group(Duration::from_secs(2)).unwrap();
        assert!(!child.leader_running().unwrap());
        assert_eq!(child.output_summary(), "launchd-ready");
        let _ = fs::remove_file(stdout_path);
        let _ = fs::remove_file(stderr_path);
    }

    #[test]
    fn exited_child_output_is_available_for_startup_diagnostics() {
        let spec = ManagedCommandSpec::new("test-process", "/bin/sh")
            .with_args(["-c", "printf child-error >&2; exit 7"]);
        let mut child = ManagedChild::spawn(&spec).unwrap();
        for _ in 0..100 {
            if !child.leader_running().unwrap() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(child.output_summary(), "child-error");
    }

    #[test]
    fn runtime_artifacts_reject_existing_files_and_clean_owned_files() {
        let runtime_dir = temp_path("runtime-artifacts");
        let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        let socket = runtime_dir.join("packet.sock");
        assert!(artifacts
            .register_file(temp_path("outside-runtime-artifact"))
            .is_err());
        artifacts.register_file(socket.clone()).unwrap();
        fs::write(&socket, b"owned").unwrap();
        assert!(artifacts.register_file(socket.clone()).is_err());
        artifacts.cleanup().unwrap();
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn runtime_artifacts_clean_unregistered_runtime_files() {
        let runtime_dir = temp_path("runtime-artifacts-unregistered");
        let mut artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        artifacts
            .register_file(runtime_dir.join("known.pid"))
            .unwrap();
        fs::write(runtime_dir.join("known.pid"), b"123\n").unwrap();
        fs::write(
            runtime_dir.join("vfkit-implicit-client.sock"),
            b"socket placeholder",
        )
        .unwrap();
        fs::create_dir(runtime_dir.join("late")).unwrap();
        fs::write(runtime_dir.join("late/output.log"), b"late output").unwrap();

        artifacts.cleanup().unwrap();
        assert!(!runtime_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_artifacts_are_private_and_long_parent_falls_back() {
        use std::os::unix::fs::PermissionsExt;

        let runtime_dir = temp_path("runtime-permissions");
        let artifacts = OwnedRuntimeArtifacts::new(runtime_dir.clone()).unwrap();
        assert_eq!(
            fs::metadata(&runtime_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(artifacts);
        assert!(!runtime_dir.exists());

        #[cfg(target_os = "macos")]
        assert_eq!(
            runtime_parent_dir(PathBuf::from("/tmp").join("x".repeat(160))),
            PathBuf::from("/tmp")
        );
    }
}
