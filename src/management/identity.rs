use std::{io, time::Duration};

use anyhow::{Context, Result};
use tokio::time::{Instant, sleep};

#[derive(Clone, Default)]
pub struct Identity {
    pub start: String,
    pub executable: String,
}
impl Identity {
    pub fn capture(pid: u32) -> Result<Self> {
        anyhow::ensure!(pid > 0, "process PID must be positive");
        capture(pid).with_context(|| format!("inspect process {pid} identity"))
    }
    pub fn matches(&self, pid: u32) -> Result<bool> {
        if !crate::process::running(pid) {
            return Ok(false);
        }
        anyhow::ensure!(
            !self.start.is_empty() && !self.executable.is_empty(),
            "recorded process {pid} has no stable identity"
        );
        let actual = match Self::capture(pid) {
            Ok(identity) => identity,
            Err(_) if !crate::process::running(pid) => return Ok(false),
            Err(error) => return Err(error),
        };
        let same = if cfg!(windows) {
            actual.executable.eq_ignore_ascii_case(&self.executable)
        } else {
            actual.executable == self.executable
        };
        Ok(actual.start == self.start && same)
    }
    pub async fn stop(&self, pid: u32) -> Result<bool> {
        if !self.matches(pid)? {
            return Ok(false);
        }
        terminate(pid)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if !self.matches(pid)? {
                return Ok(true);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "process {pid} did not exit after termination"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }
}

#[cfg(target_os = "macos")]
fn capture(pid: u32) -> Result<Identity> {
    fn start(pid: i32) -> Result<String> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let length = std::mem::size_of_val(&info) as i32;
        // libproc writes exactly one proc_bsdinfo into the supplied buffer.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                length,
            )
        };
        if written != length {
            return Err(io::Error::last_os_error().into());
        }
        let info = unsafe { info.assume_init() };
        anyhow::ensure!(
            info.pbi_pid == pid as u32,
            "process identity is unavailable"
        );
        Ok(format!(
            "{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    let pid = i32::try_from(pid)?;
    let before = start(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut length = 0;
    // Query the kernel's buffer size before reading argc and the executable path.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut buffer = vec![0u8; length];
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let bytes = buffer
        .get(4..length)
        .context("malformed process arguments")?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated executable path")?;
    let executable = String::from_utf8(bytes[..end].to_vec())?;
    anyhow::ensure!(
        !executable.is_empty() && before == start(pid)?,
        "process changed while capturing identity"
    );
    Ok(Identity {
        start: before,
        executable,
    })
}

#[cfg(target_os = "linux")]
fn capture(pid: u32) -> Result<Identity> {
    fn start(pid: u32) -> Result<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        Ok(stat
            .rsplit_once(')')
            .context("malformed process stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("process start time is missing")?
            .to_owned())
    }
    let before = start(pid)?;
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?
        .to_string_lossy()
        .into_owned();
    let executable = executable
        .strip_suffix(" (deleted)")
        .unwrap_or(&executable)
        .to_owned();
    anyhow::ensure!(
        before == start(pid)?,
        "process changed while capturing identity"
    );
    Ok(Identity {
        start: before,
        executable,
    })
}

#[cfg(windows)]
fn capture(pid: u32) -> Result<Identity> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{
            GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    };
    let handle = Handle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    // Both observations use the same process handle.
    unsafe {
        if GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) == 0
            || QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut length) == 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    let nanoseconds = (i128::from(ticks) - 116_444_736_000_000_000) * 100;
    Ok(Identity {
        start: nanoseconds.to_string(),
        executable: String::from_utf16(&buffer[..length as usize])?,
    })
}

#[cfg(unix)]
fn terminate(pid: u32) -> Result<()> {
    let pid = i32::try_from(pid)?;
    // The caller has compared the persisted start time and executable.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn terminate(pid: u32) -> Result<()> {
    use windows_sys::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };
    let handle = match Handle::open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE) {
        Ok(handle) => handle,
        Err(_) if !crate::process::running(pid) => return Ok(()),
        Err(error) => return Err(error),
    };
    if unsafe { TerminateProcess(handle.0, 1) } == 0 && crate::process::running(pid) {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(windows)]
struct Handle(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Handle {
    fn open(pid: u32, access: u32) -> Result<Self> {
        let handle = unsafe { windows_sys::Win32::System::Threading::OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(handle))
    }
}
#[cfg(windows)]
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
