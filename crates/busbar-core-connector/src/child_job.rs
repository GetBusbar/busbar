// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OS containment for trusted helper processes. The safe owner never reaps a
//! Unix group leader before signalling its group, and never resumes a Windows
//! helper until its non-breakaway, kill-on-close Job contains it.

#[cfg(windows)]
use std::time::Duration;
use std::{path::Path, process::ExitStatus};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Content-free process-containment failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No owned process-tree implementation exists for this platform.
    Platform,
    /// A private scratch directory could not be created.
    PrivateDirectory,
    /// The configured child could not be started.
    Spawn,
    /// A child could not enter its required group or Job.
    Containment,
    /// Windows did not return its actual absolute native system directory.
    SystemDirectory,
    /// The suspended Windows process had no unique, validated primary thread.
    PrimaryThread,
    /// A child's exit could not be observed without relinquishing its identity.
    Observation,
    /// The owned process tree could not be stopped and reaped.
    Cleanup,
}

/// Create one new directory accessible only to its owner. A shared Unix parent
/// must have sticky ownership protection; Windows installs a protected owner DACL.
pub fn private_directory(path: &Path) -> Result<(), Error> {
    platform::private_directory(path)
}

/// Open a regular private control file without following a final symlink or
/// reparse point, then validate ownership and permissions on that descriptor.
pub fn open_private_file(path: &Path) -> Result<std::fs::File, Error> {
    platform::open_private_file(path)
}

/// Owns both the helper and its OS process tree. Drop stops the tree; normal
/// completion additionally awaits the leader and, on Windows, an empty Job.
pub struct ContainedChild {
    // Rust drops fields in declaration order: stop the tree before Child's
    // kill-on-drop guard hands the leader to Tokio's orphan reaper.
    job: platform::Job,
    child: Child,
}

impl std::fmt::Debug for ContainedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainedChild").finish_non_exhaustive()
    }
}

impl ContainedChild {
    /// Start the supplied command in an owned process tree. On Windows its
    /// primary thread is suspended until Job assignment succeeds. Failed
    /// assignment terminates and reaps that suspended child before returning.
    pub async fn spawn(command: &mut Command) -> Result<Self, Error> {
        let mut job = platform::Job::prepare(command)?;
        command.kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| Error::Spawn)?;
        if let Err(error) = job.attach(&child) {
            let _ = job.stop();
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(error);
        }
        Ok(Self { job, child })
    }

    /// Take the configured stdin pipe, without exposing process ownership.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the configured stdout pipe, without exposing process ownership.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Observe exit without reaping a Unix PID or relinquishing a Windows handle.
    pub fn has_exited(&self) -> Result<bool, Error> {
        self.job.exited(&self.child)
    }

    /// Stop every member before reaping the leader. Windows also verifies that
    /// the Job has no active descendants before releasing its kill-on-close handle.
    pub async fn terminate_and_reap(&mut self) -> Result<ExitStatus, Error> {
        let stopped = self.job.stop();
        self.job.before_reap();
        let _ = self.child.start_kill();
        let status = self.child.wait().await.map_err(|_| Error::Cleanup)?;
        stopped?;
        self.job.wait_empty().await?;
        Ok(status)
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    pub(super) fn private_directory(path: &Path) -> Result<(), Error> {
        let parent = path.parent().ok_or(Error::PrivateDirectory)?;
        let mode = std::fs::metadata(parent)
            .map_err(|_| Error::PrivateDirectory)?
            .permissions()
            .mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(Error::PrivateDirectory);
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| Error::PrivateDirectory)
    }

    pub(super) fn open_private_file(path: &Path) -> Result<std::fs::File, Error> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Error::PrivateDirectory)?;
        let metadata = file.metadata().map_err(|_| Error::PrivateDirectory)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(Error::PrivateDirectory);
        }
        Ok(file)
    }

    pub(super) struct Job {
        pid: Option<libc::pid_t>,
    }
    impl Job {
        pub(super) fn prepare(command: &mut Command) -> Result<Self, Error> {
            command.process_group(0);
            Ok(Self { pid: None })
        }
        pub(super) fn attach(&mut self, child: &Child) -> Result<(), Error> {
            let pid = i32::try_from(child.id().ok_or(Error::Containment)?)
                .map_err(|_| Error::Containment)?;
            if pid <= 0 {
                return Err(Error::Containment);
            }
            self.pid = Some(pid);
            Ok(())
        }
        pub(super) fn exited(&self, _: &Child) -> Result<bool, Error> {
            let pid = self.pid.ok_or(Error::Observation)?;
            loop {
                // siginfo_t is a plain C output carrier, initialized for WNOHANG.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    return Ok(unsafe { info.si_pid() } != 0);
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    return Err(Error::Observation);
                }
            }
        }
        pub(super) fn stop(&self) -> Result<(), Error> {
            if let Some(pid) = self.pid {
                // The safe owner has not exposed wait/try_wait; this PID remains
                // reserved by its child until before_reap explicitly disarms it.
                let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
                if result != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                {
                    return Err(Error::Cleanup);
                }
            }
            Ok(())
        }
        pub(super) fn before_reap(&mut self) {
            self.pid.take();
        }
        pub(super) async fn wait_empty(&self) -> Result<(), Error> {
            Ok(())
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };
    use windows_sys::Win32::{
        Foundation::{
            GetLastError, LocalFree, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
                JobObjectExtendedLimitInformation, QueryInformationJobObject,
                SetInformationJobObject, TerminateJobObject,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                GetProcessIdOfThread, OpenThread, ResumeThread, WaitForSingleObject,
                CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_QUERY_LIMITED_INFORMATION,
                THREAD_SUSPEND_RESUME,
            },
        },
    };

    fn owned(handle: HANDLE) -> Result<OwnedHandle, Error> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(Error::Containment);
        }
        // This newly returned kernel handle has no other owning Rust value.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
    fn raw(handle: &OwnedHandle) -> HANDLE {
        handle.as_raw_handle()
    }

    pub(super) fn private_directory(path: &Path) -> Result<(), Error> {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        if path[..path.len() - 1].contains(&0) {
            return Err(Error::PrivateDirectory);
        }
        // Protected DACL: only owner rights; children inherit that restriction.
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)".encode_utf16().chain([0]).collect();
        let mut descriptor = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(Error::PrivateDirectory);
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let created = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) };
        unsafe {
            LocalFree(descriptor);
        }
        if created == 0 {
            Err(Error::PrivateDirectory)
        } else {
            Ok(())
        }
    }

    pub(super) fn open_private_file(path: &Path) -> Result<std::fs::File, Error> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::{
            Security::{
                Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
                EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, TokenUser,
                ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
                SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
            },
            Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| Error::PrivateDirectory)?;
        let metadata = file.metadata().map_err(|_| Error::PrivateDirectory)?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::PrivateDirectory);
        }
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(Error::PrivateDirectory);
        }
        let token = owned(token).map_err(|_| Error::PrivateDirectory)?;
        let mut user = [0usize; 128];
        let mut length = 0;
        if unsafe {
            GetTokenInformation(
                raw(&token),
                TokenUser,
                user.as_mut_ptr().cast(),
                std::mem::size_of_val(&user) as u32,
                &mut length,
            )
        } == 0
        {
            return Err(Error::PrivateDirectory);
        }
        let current_sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let mut owner = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        } != 0
        {
            return Err(Error::PrivateDirectory);
        }
        // The returned descriptor owns all SID/ACL pointers until LocalFree.
        let valid = (|| {
            let mut control = 0;
            let mut revision = 0;
            if owner.is_null()
                || dacl.is_null()
                || unsafe { EqualSid(owner, current_sid) } == 0
                || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
                    == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return false;
            }
            let count = unsafe { (*dacl).AceCount };
            if count == 0 {
                return false;
            }
            for index in 0..u32::from(count) {
                let mut ace = std::ptr::null_mut();
                if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                    return false;
                }
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                // Only plain allow ACEs for the current owner are admitted.
                if unsafe { (*allowed).Header.AceType } != 0
                    || unsafe { (*allowed).Header.AceSize }
                        < std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u16
                    || unsafe {
                        EqualSid(
                            std::ptr::addr_of_mut!((*allowed).SidStart).cast(),
                            current_sid,
                        )
                    } == 0
                {
                    return false;
                }
            }
            true
        })();
        unsafe {
            LocalFree(descriptor);
        }
        if valid {
            Ok(file)
        } else {
            Err(Error::PrivateDirectory)
        }
    }

    fn system_directory() -> Result<std::path::PathBuf, Error> {
        let mut buffer = vec![0u16; 32_768];
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(Error::SystemDirectory);
        }
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length]));
        if !path.is_absolute() {
            return Err(Error::SystemDirectory);
        }
        Ok(path)
    }

    pub(super) struct Job {
        handle: OwnedHandle,
    }
    impl Job {
        pub(super) fn prepare(command: &mut Command) -> Result<Self, Error> {
            command.env(
                "BUSBAR_TRUSTED_WINDOWS_SYSTEM_DIRECTORY",
                system_directory()?,
            );
            let handle = owned(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    raw(&handle),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            if configured == 0 {
                return Err(Error::Containment);
            }
            // std's spawn creates only its explicit stdin/stdout/stderr handle
            // whitelist. No helper code runs before attach assigns this Job.
            command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
            Ok(Self { handle })
        }
        pub(super) fn attach(&mut self, child: &Child) -> Result<(), Error> {
            let process = child.raw_handle().ok_or(Error::Containment)?;
            if unsafe { AssignProcessToJobObject(raw(&self.handle), process) } == 0 {
                return Err(Error::Containment);
            }
            let pid = child.id().ok_or(Error::PrimaryThread)?;
            let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })
                .map_err(|_| Error::PrimaryThread)?;
            let mut entry = THREADENTRY32::default();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut found = None;
            let mut present = unsafe { Thread32First(raw(&snapshot), &mut entry) };
            while present != 0 {
                if entry.th32OwnerProcessID == pid {
                    if found.replace(entry.th32ThreadID).is_some() {
                        return Err(Error::PrimaryThread);
                    }
                }
                present = unsafe { Thread32Next(raw(&snapshot), &mut entry) };
            }
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(Error::PrimaryThread);
            }
            let thread = owned(unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    found.ok_or(Error::PrimaryThread)?,
                )
            })
            .map_err(|_| Error::PrimaryThread)?;
            if unsafe { GetProcessIdOfThread(raw(&thread)) } != pid {
                return Err(Error::PrimaryThread);
            }
            // Exactly the suspension installed by CREATE_SUSPENDED must remain.
            if unsafe { ResumeThread(raw(&thread)) } != 1 {
                return Err(Error::PrimaryThread);
            }
            Ok(())
        }
        pub(super) fn exited(&self, child: &Child) -> Result<bool, Error> {
            match unsafe { WaitForSingleObject(child.raw_handle().ok_or(Error::Observation)?, 0) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(Error::Observation),
            }
        }
        pub(super) fn stop(&self) -> Result<(), Error> {
            if unsafe { TerminateJobObject(raw(&self.handle), 1) } == 0 {
                Err(Error::Cleanup)
            } else {
                Ok(())
            }
        }
        pub(super) fn before_reap(&mut self) {}
        pub(super) async fn wait_empty(&self) -> Result<(), Error> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                let read = unsafe {
                    QueryInformationJobObject(
                        raw(&self.handle),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                            .cast::<c_void>(),
                        std::mem::size_of_val(&accounting) as u32,
                        std::ptr::null_mut(),
                    )
                };
                if read == 0 {
                    return Err(Error::Cleanup);
                }
                if accounting.ActiveProcesses == 0 {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(Error::Cleanup);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    // OwnedHandle closes the Job on every return/unwind, killing any remaining
    // descendants even if its parent's future disappears during cleanup.
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) fn private_directory(_: &Path) -> Result<(), Error> {
        Err(Error::Platform)
    }
    pub(super) fn open_private_file(_: &Path) -> Result<std::fs::File, Error> {
        Err(Error::Platform)
    }
    pub(super) struct Job;
    impl Job {
        pub(super) fn prepare(_: &mut Command) -> Result<Self, Error> {
            Err(Error::Platform)
        }
        pub(super) fn attach(&mut self, _: &Child) -> Result<(), Error> {
            Err(Error::Platform)
        }
        pub(super) fn exited(&self, _: &Child) -> Result<bool, Error> {
            Err(Error::Platform)
        }
        pub(super) fn stop(&self) -> Result<(), Error> {
            Err(Error::Platform)
        }
        pub(super) fn before_reap(&mut self) {}
        pub(super) async fn wait_empty(&self) -> Result<(), Error> {
            Err(Error::Platform)
        }
    }
}
