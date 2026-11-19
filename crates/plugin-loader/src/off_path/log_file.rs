// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::log_file`'s configuration and binding: `plugins.logs` is read once per config apply
//! (`PluginLogConfig::from_words`: root boot and config apply, the connector's doors), every live
//! sink re-levelled once per apply (`reconfigure`), and a sink, its file name and its writer lane
//! made once when an instance is bound (`sink`: boot `load_planes`, registry
//! `open_transport_entries`, export axis `load`, auth door `to_file`, the connector's egress
//! `row_bind`). A plugin's log lines (`PluginLogSink::line`) and the writer thread stay in
//! `dispatch::log_file`; none of this runs per request.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Weak};

use busbar_contract::kinds::codes::KindCode;

use crate::dispatch::log_file::{
    refusal, wall_secs, Admit, FileSlot, Lane, Live, LogLevel, Now, Over, PluginLogConfig,
    PluginLogSink, Tag, Words, Writer, DEFAULT_DIR, DEFAULT_KEEP, LOG_QUEUE_LINES,
};
use crate::dispatch::plugin::EnvelopeSink;

impl PluginLogConfig {
    pub fn from_words(
        dir: Option<&str>,
        level: Option<&str>,
        levels: &BTreeMap<String, String>,
        rotate_mb: Option<u64>,
        keep: Option<u32>,
    ) -> Result<Self, String> {
        let level = level.map_or(Ok(LogLevel::Info), |w| {
            LogLevel::parse(w).ok_or_else(|| crate::cold::dispatch::load::bad_log_level(w))
        })?;
        // plugins.logs is read once per config apply.
        let mut parsed = BTreeMap::new();
        for (k, w) in levels {
            let level = LogLevel::parse(w)
                .ok_or_else(|| crate::cold::dispatch::load::bad_instance_log_level(k, w))?;
            parsed.insert(crate::cold::dispatch::load::text(k), level);
        }
        if rotate_mb == Some(0) {
            return Err("plugins.logs.rotate_mb: must be at least 1".into());
        }
        let dir_path = crate::cold::dispatch::load::path(dir.unwrap_or(DEFAULT_DIR));
        Ok(Self {
            dir: dir_path,
            named_dir: dir.is_some(),
            level,
            levels: parsed,
            rotate_bytes: rotate_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            keep: keep.unwrap_or(DEFAULT_KEEP),
            live: Live::default(),
        })
    }

    pub fn level_for(&self, instance: &str) -> LogLevel {
        self.current().level_for(instance)
    }

    pub fn path_for(&self, instance: &str, kind: KindCode) -> PathBuf {
        self.current().dir.join(file_name(instance, kind))
    }

    fn words(&self) -> Words {
        Words {
            dir: crate::cold::dispatch::load::path_copy(&self.dir),
            level: self.level,
            levels: crate::cold::dispatch::load::map_copy(&self.levels),
            rotate_bytes: self.rotate_bytes,
            keep: self.keep,
            named_dir: self.named_dir,
        }
    }

    fn current(&self) -> Arc<Words> {
        self.live
            .0
            .now
            .words()
            .unwrap_or_else(|| Arc::new(self.words()))
    }

    pub fn reconfigure(&self, next: &PluginLogConfig) {
        let words = Arc::new(next.words());
        if *self.current() == *words {
            return;
        }
        if next.named_dir {
            if let Err(e) = crate::durable::create_dir_all(&words.dir) {
                tracing::warn!(
                    error = %format_args!("plugins.logs.dir {}: {e}", words.dir.display()),
                    "the applied plugin log directory cannot be used"
                );
            }
        }
        let cell = &self.live.0;
        let mut sinks = cell.sinks.lock().unwrap_or_else(|p| p.into_inner());
        *cell.now.words.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::clone(&words));
        cell.now.generation.fetch_add(1, Ordering::AcqRel);
        // A config apply re-levels every live sink once.
        crate::cold::dispatch::load::relevel(&mut *sinks, |s| {
            s.level
                .store(words.level_for(&s.instance) as u8, Ordering::Release);
        });
    }

    pub fn sink(
        &self,
        instance: &str,
        kind: KindCode,
        metrics: Arc<dyn EnvelopeSink>,
    ) -> Result<PluginLogSink, String> {
        let cell = &self.live.0;
        let (admit, words) = {
            let mut sinks = cell.sinks.lock().unwrap_or_else(|p| p.into_inner());
            let words = self.current();
            let admit = Arc::new(Admit {
                instance: crate::cold::dispatch::load::text(instance),
                level: AtomicU8::new(words.level_for(instance) as u8),
            });
            crate::cold::dispatch::load::prune_weak(&mut *sinks);
            sinks.push(Arc::downgrade(&admit));
            (admit, words)
        };
        let name = file_name(instance, kind);
        let path = words.dir.join(&name);
        let tag = Arc::new(Tag {
            instance: crate::cold::dispatch::load::text(instance),
            kind: crate::cold::dispatch::load::kind_tag(kind),
        });
        if words.named_dir {
            FileSlot::of(&path)
                .and_then(|slot| slot.open())
                .map_err(|e| refusal(&path, &e))?;
        }
        let lane = {
            let mut lanes = cell.lanes.lock().unwrap_or_else(|p| p.into_inner());
            match lanes.get(&name).and_then(Weak::upgrade) {
                Some(lane) => lane,
                None => {
                    let lane = Lane::start(&name, &cell.now, words, &tag)
                        .map_err(|e| crate::cold::dispatch::load::writer_refused(instance, &e))?;
                    crate::cold::dispatch::load::prune_weak_map(&mut *lanes);
                    lanes.insert(name, Arc::downgrade(&lane));
                    lane
                }
            }
        };
        Ok(PluginLogSink {
            tag,
            admit,
            #[cfg(test)]
            path,
            metrics,
            clock: wall_secs,
            lane,
        })
    }
}

fn file_name(instance: &str, kind: KindCode) -> String {
    // A log file is named once, when its sink is bound.
    crate::cold::dispatch::load::log_file_name(instance, kind)
}

impl Lane {
    fn start(
        name: &str,
        now: &Arc<Now>,
        words: Arc<Words>,
        first: &Arc<Tag>,
    ) -> std::io::Result<Arc<Self>> {
        let (queue, jobs) = sync_channel(LOG_QUEUE_LINES);
        let over = Arc::new(Over::default());
        let writer = Writer {
            name: crate::cold::dispatch::load::text(name),
            rendered: String::new(),
            now: Arc::clone(now),

            seen: u64::MAX,
            path: words.dir.join(name),
            words,
            slot: None,
            over: Arc::clone(&over),
            last: Arc::clone(first),
        };
        std::thread::Builder::new()
            .name("busbar-plugin-log".into())
            .spawn(move || writer.drain(&jobs))?;
        Ok(Arc::new(Self { queue, over }))
    }
}
