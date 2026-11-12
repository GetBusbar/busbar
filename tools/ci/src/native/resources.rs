//! Observe a running candidate step's cgroup and emit a credential-free
//! heartbeat (former `native_resources`). Observation only: nothing here
//! decides a verdict. Docker removes a container's cgroup when it exits, so
//! peak memory is sampled while the step runs.
use super::sp::{self, R};
use crate::json::{self, Value, object};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

pub const SAMPLE_SECONDS: u64 = 15;
pub const HEARTBEAT_SECONDS: f64 = 300.0;

/// The cgroup v2 directory whose name contains the full container id.
pub fn find_cgroup(container_id: &str, root: &Path, depth: usize) -> Option<PathBuf> {
    if container_id.len() < 12 || !root.is_dir() {
        return None;
    }
    let base = root.components().count();
    let mut stack = vec![root.to_owned()];
    while let Some(path) = stack.pop() {
        if path.components().count() - base >= depth {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut directories = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let child = entry.path();
            if child.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.contains(container_id) && child.join("memory.current").is_file() {
                    return Some(child);
                }
                directories.push(child);
            }
        }
        stack.extend(directories.into_iter().rev());
    }
    None
}

fn read_int(path: &Path) -> Option<i128> {
    let text = std::fs::read_to_string(path).ok()?;
    sp::py_int(text.split_whitespace().next()?).ok()
}

/// Selected integer fields of a flat-keyed cgroup file such as memory.stat,
/// in file order (`_keyed(path, *keys)`); empty when unreadable or invalid.
fn keyed(path: &Path, keys: &[&str]) -> Vec<(String, i128)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut values: Vec<(String, i128)> = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        if keys.contains(&key) {
            let Ok(number) = sp::py_int(value) else {
                return Vec::new();
            };
            match values.iter_mut().find(|(k, _)| k == key) {
                Some(row) => row.1 = number,
                None => values.push((key.to_owned(), number)),
            }
        }
    }
    values
}

fn cpu_seconds(cgroup: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(cgroup.join("cpu.stat")).ok()?;
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        if key == "usage_usec" {
            let micros = sp::py_int(value).ok()?;
            return Some(sp::round_float(micros as f64 / 1e6, 3));
        }
    }
    None
}

pub struct StepObserver {
    name: String,
    container_id: Option<String>,
    root: PathBuf,
    started: Instant,
    last_heartbeat: Instant,
    cgroup: Option<PathBuf>,
    samples: u64,
    memory_peak: Option<i128>,
    // memory.peak counts reclaimable page cache, so a compiler step that
    // streams a large target directory reports the full limit whether or not
    // its compilers came near it. Anonymous memory is what an OOM kill is
    // decided on; keep its sampled maximum and the cgroup's event counters.
    anon_peak: Option<i128>,
    events: Option<Value>,
    cpu_seconds: Option<Value>,
    pub emitted: Vec<String>,
    pub quiet: bool,
}

impl StepObserver {
    pub fn new(name: &str, container_id: Option<&str>) -> StepObserver {
        Self::with_root(name, container_id, Path::new("/sys/fs/cgroup"))
    }

    pub fn with_root(name: &str, container_id: Option<&str>, root: &Path) -> StepObserver {
        let now = Instant::now();
        StepObserver {
            name: name.to_owned(),
            container_id: container_id.map(str::to_owned),
            root: root.to_owned(),
            started: now,
            last_heartbeat: now,
            cgroup: None,
            samples: 0,
            memory_peak: None,
            anon_peak: None,
            events: None,
            cpu_seconds: None,
            emitted: Vec::new(),
            quiet: false,
        }
    }

    #[cfg(test)]
    pub fn sample(&mut self) {
        self.sample_at(Instant::now());
    }

    pub fn sample_at(&mut self, now: Instant) {
        if self.cgroup.is_none()
            && let Some(id) = self.container_id.as_deref().filter(|id| !id.is_empty())
        {
            self.cgroup = find_cgroup(id, &self.root, 6);
        }
        let mut current = None;
        if let Some(cgroup) = &self.cgroup {
            current = read_int(&cgroup.join("memory.current"));
            let peak = read_int(&cgroup.join("memory.peak"));
            let observed = [peak, current, Some(self.memory_peak.unwrap_or(0))]
                .into_iter()
                .flatten()
                .max();
            self.memory_peak = observed;
            if let Some((_, anon)) = keyed(&cgroup.join("memory.stat"), &["anon"]).first() {
                self.anon_peak = Some((*anon).max(self.anon_peak.unwrap_or(0)));
            }
            let events = keyed(
                &cgroup.join("memory.events"),
                &["high", "max", "oom", "oom_kill"],
            );
            if !events.is_empty() {
                self.events = Some(Value::Object(
                    events
                        .into_iter()
                        .map(|(k, v)| (k, Value::int(v)))
                        .collect(),
                ));
            }
            if let Some(cpu) = cpu_seconds(cgroup) {
                self.cpu_seconds = Some(cpu);
            }
            self.samples += 1;
        }
        if now.duration_since(self.last_heartbeat).as_secs_f64() >= HEARTBEAT_SECONDS {
            self.last_heartbeat = now;
            let optional = |v: Option<i128>| v.map_or(Value::Null, Value::int);
            let line = json::dumps(
                &object([(
                    "heartbeat",
                    object([
                        ("step", self.name.as_str().into()),
                        (
                            "elapsed_seconds",
                            sp::round_float(now.duration_since(self.started).as_secs_f64(), 1),
                        ),
                        ("memory_current_bytes", optional(current)),
                        ("memory_peak_bytes", optional(self.memory_peak)),
                        ("memory_anon_peak_bytes", optional(self.anon_peak)),
                        (
                            "cpu_seconds",
                            self.cpu_seconds.clone().unwrap_or(Value::Null),
                        ),
                    ]),
                )]),
                false,
            );
            if !self.quiet {
                println!("{line}");
            }
            self.emitted.push(line);
        }
    }

    pub fn summary(&self) -> Value {
        object([
            (
                "elapsed_seconds",
                sp::round_float(self.started.elapsed().as_secs_f64(), 3),
            ),
            ("cgroup_observed", self.cgroup.is_some().into()),
            ("samples", self.samples.into()),
            (
                "memory_peak_bytes",
                self.memory_peak.map_or(Value::Null, Value::int),
            ),
            (
                "memory_anon_peak_bytes",
                self.anon_peak.map_or(Value::Null, Value::int),
            ),
            ("memory_events", self.events.clone().unwrap_or(Value::Null)),
            (
                "cpu_seconds",
                self.cpu_seconds.clone().unwrap_or(Value::Null),
            ),
            ("sample_seconds", SAMPLE_SECONDS.into()),
        ])
    }
}

/// `wait_observed(process, timeout, observer)`: `process.wait(timeout)` with
/// periodic sampling. Raises `TimeoutExpired` with the original timeout, or
/// the pending interruption, leaving the process for the caller to stop.
pub fn wait_observed(
    child: &mut Child,
    argv: &[String],
    timeout: u64,
    observer: &mut StepObserver,
) -> R<i32> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout);
    let mut next_sample = started + Duration::from_secs(SAMPLE_SECONDS);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| sp::os_error(&e, None))? {
            return Ok(sp::returncode(status));
        }
        let now = Instant::now();
        if now >= deadline {
            // The former bounded wait always ended its last interval with a sample.
            if timeout > 0 && now < next_sample {
                observer.sample_at(now);
            }
            return Err(sp::timeout_error(argv, &timeout.to_string()));
        }
        sp::poll_interrupt()?;
        if now >= next_sample {
            observer.sample_at(now);
            next_sample = now + Duration::from_secs(SAMPLE_SECONDS);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_peak_and_cpu_are_sampled_and_heartbeat_is_credential_free() {
        let root =
            sp::resolve(&std::env::temp_dir()).join(format!("busbar-ci-cgroup-{}", sp::uuid_hex()));
        let id = "0123456789abcdef0123";
        let cgroup = root.join("system.slice").join(format!("docker-{id}.scope"));
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("memory.current"), "100\n").unwrap();
        std::fs::write(cgroup.join("memory.peak"), "300\n").unwrap();
        std::fs::write(cgroup.join("cpu.stat"), "usage_usec 2500000\nuser_usec 1\n").unwrap();
        assert_eq!(find_cgroup(id, &root, 6), Some(cgroup.clone()));
        assert_eq!(find_cgroup(id, &root, 1), None);
        assert_eq!(find_cgroup("short", &root, 6), None);
        let mut observer = StepObserver::with_root("root-runtime", Some(id), &root);
        observer.quiet = true;
        observer.sample();
        std::fs::write(cgroup.join("memory.peak"), "max\n").unwrap();
        observer.sample_at(Instant::now() + Duration::from_secs(301));
        let summary = observer.summary();
        assert_eq!(summary.at("memory_peak_bytes").as_int(), Some(300));
        assert_eq!(json::dumps(summary.at("cpu_seconds"), false), "2.5");
        assert_eq!(summary.at("samples").as_int(), Some(2));
        assert_eq!(observer.emitted.len(), 1);
        assert!(
            observer.emitted[0].starts_with(
                "{\"heartbeat\": {\"step\": \"root-runtime\", \"elapsed_seconds\": 301."
            )
        );
        assert!(observer.emitted[0].ends_with(
            "\"memory_current_bytes\": 100, \"memory_peak_bytes\": 300, \"memory_anon_peak_bytes\": null, \"cpu_seconds\": 2.5}}"
        ));
        assert_eq!(summary.at("memory_anon_peak_bytes"), &Value::Null);
        assert_eq!(summary.at("memory_events"), &Value::Null);
        for anon in [100, 5000, 300] {
            std::fs::write(
                cgroup.join("memory.stat"),
                format!("anon {anon}\nfile 9999\n"),
            )
            .unwrap();
            std::fs::write(
                cgroup.join("memory.events"),
                "low 0\nhigh 0\nmax 7\noom 0\noom_kill 0\n",
            )
            .unwrap();
            observer.sample();
        }
        let summary = observer.summary();
        assert_eq!(summary.at("memory_anon_peak_bytes").as_int(), Some(5000));
        assert_eq!(
            json::dumps(summary.at("memory_events"), false),
            "{\"high\": 0, \"max\": 7, \"oom\": 0, \"oom_kill\": 0}"
        );
        std::fs::remove_dir_all(&root).unwrap();
        let unobserved = StepObserver::new("x", None).summary();
        assert_eq!(
            json::dumps(&unobserved, false).split_once(", ").unwrap().1,
            "\"cgroup_observed\": false, \"samples\": 0, \"memory_peak_bytes\": null, \"memory_anon_peak_bytes\": null, \"memory_events\": null, \"cpu_seconds\": null, \"sample_seconds\": 15}"
        );
    }

    #[test]
    fn timeout_is_raised_with_the_original_bound() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let mut observer = StepObserver::new("slow", None);
        let argv = sp::strings(&["docker", "start", "--attach", "x"]);
        let error = wait_observed(&mut child, &argv, 0, &mut observer).unwrap_err();
        assert_eq!(
            error.message,
            "Command '['docker', 'start', '--attach', 'x']' timed out after 0 seconds"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
