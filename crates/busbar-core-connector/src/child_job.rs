// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OS containment for trusted helper processes. The safe owner never reaps a
//! Unix group leader before signalling its group, and never resumes a Windows
//! helper until its non-breakaway, kill-on-close Job contains it.

use std::path::Path;
use tokio::process::{Child, Command};

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

/// Owns both the helper and its OS process tree. Drop stops the tree.
pub struct ContainedChild {
    // Rust drops fields in declaration order: stop the tree before Child's
    // kill-on-drop guard hands the leader to Tokio's orphan reaper. The job is held for its drop alone.
    _job: platform::Job,
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
        Ok(Self { _job: job, child })
    }

    /// The child's stdin, once, when the command piped it. Taking a pipe never exposes wait or try_wait, so
    /// the leader's PID stays reserved for the group signal until the owner drops.
    pub fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// The child's stdout, once, when the command piped it.
    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
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
        pub(super) fn stop(&self) -> Result<(), Error> {
            if let Some(pid) = self.pid {
                // The safe owner has not exposed wait/try_wait; this PID remains
                // reserved by its child while the owner holds it.
                let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
                if result != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                {
                    return Err(Error::Cleanup);
                }
            }
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
    use std::os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, LocalFree, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
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
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                GetProcessIdOfThread, OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED,
                THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
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

    /// The system directory, read once per process: it does not move while the process runs.
    fn system_directory() -> Result<&'static std::path::Path, Error> {
        static DIRECTORY: std::sync::OnceLock<Option<std::path::PathBuf>> =
            std::sync::OnceLock::new();
        DIRECTORY
            .get_or_init(read_system_directory)
            .as_deref()
            .ok_or(Error::SystemDirectory)
    }

    fn read_system_directory() -> Option<std::path::PathBuf> {
        let mut buffer = vec![0u16; 32_768];
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 || length >= buffer.len() {
            return None;
        }
        let path = crate::off_path::lines::system_directory_path(&buffer[..length]);
        path.is_absolute().then_some(path)
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
        pub(super) fn stop(&self) -> Result<(), Error> {
            if unsafe { TerminateJobObject(raw(&self.handle), 1) } == 0 {
                Err(Error::Cleanup)
            } else {
                Ok(())
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
    pub(super) struct Job;
    impl Job {
        pub(super) fn prepare(_: &mut Command) -> Result<Self, Error> {
            Err(Error::Platform)
        }
        pub(super) fn attach(&mut self, _: &Child) -> Result<(), Error> {
            Err(Error::Platform)
        }
        pub(super) fn stop(&self) -> Result<(), Error> {
            Err(Error::Platform)
        }
    }
}
