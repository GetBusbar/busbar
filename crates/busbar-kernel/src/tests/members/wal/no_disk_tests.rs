// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, TempDir};

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ChildGuard {
    fn finish(&mut self) -> std::process::ExitStatus {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().expect("poll child") {
                self.0.take().unwrap().wait().expect("reap child");
                return status;
            }
            assert!(
                std::time::Instant::now() < until,
                "memory-directory child did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

pub(super) fn in_empty_working_directory(test: &str, body: impl FnOnce()) {
    const CHILD: &str = "BUSBAR_WAL_NO_DIRECTORY_CHILD";
    const FINISHED: &str = "memory-directory-case-finished";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        let before = super::fixtures::cwd_segment_names();
        body();
        assert_eq!(
            before,
            super::fixtures::cwd_segment_names(),
            "a log segment appeared in the child's working directory"
        );
        println!("{FINISHED}:{test}");
        return;
    }
    let dir = TempDir::new("no-disk-child");
    assert!(
        std::fs::read_dir(dir.path())
            .expect("read child directory")
            .next()
            .is_none(),
        "the working directory starts empty"
    );
    let capture = TempDir::new("no-disk-output");
    let stdout_path = capture.path().join("stdout");
    let stderr_path = capture.path().join("stderr");
    let test_name = test.split_once("::").expect("crate-qualified test name").1;
    let mut child = ChildGuard(Some(
        std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
            .env(CHILD, test)
            .current_dir(dir.path())
            .stdout(std::fs::File::create(&stdout_path).expect("capture stdout"))
            .stderr(std::fs::File::create(&stderr_path).expect("capture stderr"))
            .spawn()
            .expect("run the memory-directory case"),
    ));
    let status = child.finish();
    let stdout = std::fs::read_to_string(stdout_path).expect("read stdout");
    let stderr = std::fs::read_to_string(stderr_path).expect("read stderr");
    assert!(
        status.success() && stdout.contains(&format!("{FINISHED}:{test}")),
        "{test}: child status {}; stdout: {stdout}; stderr: {stderr}",
        status
    );
    assert!(
        std::fs::read_dir(dir.path())
            .expect("read child directory after exit")
            .next()
            .is_none(),
        "{test}: files appeared in its working directory"
    );
}

#[test]
fn a_memory_buffered_log_creates_no_working_directory_file() {
    in_empty_working_directory(
        concat!(
            module_path!(),
            "::a_memory_buffered_log_creates_no_working_directory_file"
        ),
        || {
            let mut wal = Wal::memory_buffered_to(
                Box::new(busbar_kernel_wal::ship::NullShipper::new()),
                super::fixtures::wall_ms,
            );
            assert_eq!(wal.mode(), Mode::MemoryBuffered);
            let token = durability_token();

            let mut expected = Vec::new();
            for batch in 0..8u64 {
                let batch_records = records(1, batch * 4 + 1, 4, 900);
                wal.append_batch(
                    &token,
                    busbar_contract::caps::StepName::Meter,
                    &batch_records,
                )
                .unwrap();
                expected.extend(batch_records);
            }
            let back = wal.read_back().unwrap();
            assert_eq!(back.records, expected);
        },
    );
}

#[test]
fn a_memory_buffered_log_ships_every_committed_batch_synchronously() {
    let shipper = super::fixtures::KeepingShipper::new();
    let mut wal = Wal::memory_buffered_to(Box::new(shipper.clone()), super::fixtures::wall_ms);
    let token = durability_token();
    let first = records(4, 1, 3, 30);
    let second = records(4, 4, 2, 30);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &first)
        .unwrap();
    assert_eq!(
        shipper.records().len(),
        3,
        "the batch reached the store as part of the commit"
    );
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &second)
        .unwrap();
    let mut expected = first;
    expected.extend(second);
    assert_eq!(shipper.records(), expected);
}

#[test]
fn a_log_in_a_directory_does_write_files_there_and_nowhere_else() {
    let dir = TempDir::new("on-disk");
    let inner = dir.path().join("wal");
    {
        let mut wal = Wal::in_directory(
            &inner,
            Box::new(busbar_kernel_wal::ship::NullShipper::new()),
            super::fixtures::wall_ms,
        )
        .unwrap();
        assert_eq!(wal.mode(), Mode::OnDisk);
        let token = durability_token();
        wal.append_batch(
            &token,
            busbar_contract::caps::StepName::Meter,
            &records(1, 1, 3, 100),
        )
        .unwrap();
    }
    let files: Vec<_> = dir.walk().into_iter().filter(|p| p.is_file()).collect();
    assert_eq!(
        files.len(),
        1,
        "one segment file, in the named directory: {files:?}"
    );
    assert!(files[0].starts_with(&inner));

    let wal = Wal::in_directory(
        &inner,
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered().len(), 3);
    assert!(wal.holds(1, 2));
}
