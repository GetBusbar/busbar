// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::dispatch::{in_head, out_head, ConnTable, Frame, NO_BLOB};
use busbar_contract::abi::export::{slot as export_slot, DeliverIn, StatusOut};
use busbar_contract::abi::mechanism::call::{Outcome, BLOB_JSON, BLOB_JSONL};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, CancelIn, CancelOut, RefreshIn};
use busbar_contract::abi::mechanism::ticket::Ticket;

fn loaded(dropped: bool, file: bool, d: &Dispatcher, far: Arc<Far>) -> Plugin<Export> {
    let (door, library) = if file {
        (FILE_DOOR, file_cdylib())
    } else {
        (WEBHOOK_DOOR, webhook_cdylib())
    };
    let mut binding = bind("export-refresh", Arc::new(Tape::default()), d);
    binding.conns = if file {
        ConnTable::NoNeeds
    } else {
        ConnTable::Host(far)
    };
    if dropped {
        load_dropped_bytes::<Export>(
            &cdylib_bytes(library),
            "export-refresh",
            &rendering_of(door).unwrap(),
            binding,
        )
        .unwrap()
    } else {
        load_linked::<Export>(&LinkedRow::of(door).unwrap(), binding).unwrap()
    }
}

fn refresh(plugin: &Plugin<Export>, settings: &serde_json::Value, generation: u64) -> Outcome {
    let bytes = settings.to_string();
    let mut frame = Frame::new(
        RefreshIn {
            head: in_head(),
            generation,
            settings: crate::dispatch::lifecycle::blob(bytes.as_bytes(), BLOB_JSON, 0),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    let called = plugin.call(life::REFRESH, &mut frame);
    crate::dispatch::lifecycle::release(plugin, called.lease);
    called.outcome
}

fn batch(bytes: &[u8], id: u8) -> Frame<DeliverIn, OutHead> {
    Frame::new(
        DeliverIn {
            head: in_head(),
            op_id: [id; 16],
            stream: ExportStream::Logs as u8,
            _reserved: [0; 7],
            batch: crate::dispatch::lifecycle::blob(bytes, BLOB_JSONL, 0),
        },
        out_head(),
    )
}

fn finish(plugin: &Plugin<Export>, ticket: Ticket, frame: &mut Frame<DeliverIn, OutHead>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let called = plugin.call_inline(ticket, true, export_slot::DELIVER, frame);
        crate::dispatch::lifecycle::release(plugin, called.lease);
        if called.outcome == Outcome::Ready {
            return;
        }
        assert_eq!(called.outcome, Outcome::Pending);
        assert!(
            Instant::now() < deadline,
            "export delivery never resumed to READY"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn cancel(plugin: &Plugin<Export>, ticket: Ticket) {
    let mut frame = Frame::new(
        CancelIn {
            head: in_head(),
            ticket,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    );
    assert_eq!(
        plugin.call(life::CANCEL, &mut frame).outcome,
        Outcome::Ready
    );
}

fn pending_refresh(bytes: &[u8], generation: u64) -> Frame<RefreshIn, OutHead> {
    Frame::new(
        RefreshIn {
            head: in_head(),
            generation,
            settings: crate::dispatch::lifecycle::blob(bytes, BLOB_JSON, 0),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    )
}

fn refresh_crossing(
    plugin: &Plugin<Export>,
    ticket: Ticket,
    resume: bool,
    frame: &mut Frame<RefreshIn, OutHead>,
) -> Outcome {
    let called = plugin.call_inline(ticket, resume, life::REFRESH, frame);
    crate::dispatch::lifecycle::release(plugin, called.lease);
    called.outcome
}

fn start_pending_refresh(
    plugin: &Plugin<Export>,
    ticket: Ticket,
    frame: &mut Frame<RefreshIn, OutHead>,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let answer = refresh_crossing(plugin, ticket, false, frame);
        if answer != Outcome::Refused || Instant::now() >= deadline {
            assert_eq!(answer, Outcome::Pending);
            return;
        }
        std::thread::yield_now();
    }
}

fn owner_of(far: &Far, target: &str) -> InstanceId {
    far.owners
        .lock()
        .unwrap()
        .iter()
        .find(|(_, value)| value.contains(target))
        .unwrap()
        .0
}

fn release_owner(far: &Far, owner: InstanceId) {
    let waiting = {
        let mut stalled = far.stalled.lock().unwrap();
        let connections: Vec<_> = stalled
            .iter()
            .filter(|(_, (caller, _))| *caller == owner)
            .map(|(id, _)| *id)
            .collect();
        connections
            .into_iter()
            .filter_map(|id| stalled.remove(&id))
            .collect::<Vec<_>>()
    };
    assert!(
        !waiting.is_empty(),
        "the fixture must release a real pending read"
    );
    for (caller, ticket) in waiting {
        far.waker.get().unwrap()(caller, ticket);
    }
}

fn wake_owner(far: &Far, owner: InstanceId) {
    let waiting = far
        .stalled
        .lock()
        .unwrap()
        .values()
        .find(|(caller, _)| *caller == owner)
        .copied()
        .unwrap();
    far.waker.get().unwrap()(waiting.0, waiting.1);
}

fn candidate_is_kept(far: &Far, owner: InstanceId) {
    assert_eq!(
        far.owners
            .lock()
            .unwrap()
            .iter()
            .filter(|(caller, _)| *caller == owner)
            .count(),
        1,
        "a pending REFRESH keeps one declared candidate owner across every crossing"
    );
    assert!(
        !far.forgotten.lock().unwrap().contains(&owner),
        "PENDING is not candidate retirement"
    );
    assert!(far
        .verdicts
        .lock()
        .unwrap()
        .keys()
        .any(|(caller, _)| *caller == owner));
}

#[test]
fn pending_refresh_keeps_one_candidate_and_barrier_while_full_old_capacity_resumes_or_cancels_both_doors(
) {
    for dropped in [false, true] {
        let d = dispatcher();
        let far = Arc::new(Far::default());
        assert!(far.waker.set(d.conn_waker()).is_ok());
        let plugin = loaded(dropped, false, &d, far.clone());
        let old = serde_json::json!({"url":"https://old-stall.example/old","max_inflight_deliveries":64,"delivery_timeout_secs":600});
        let new = serde_json::json!({"url":"https://refresh-stall.example/pending-refresh","max_inflight_deliveries":64,"delivery_timeout_secs":600});
        let sink = ExportInstance::open(plugin, d.clone(), old.to_string().as_bytes()).unwrap();
        let _answer = Released(far.clone());
        let abandoned = d.inline_ticket().unwrap();
        let mut abandoned_batch = batch(b"{\"n\":1}\n{\"n\":2}\n", 10);
        assert_eq!(
            sink.plugin()
                .call_inline(
                    abandoned.ticket(),
                    false,
                    export_slot::DELIVER,
                    &mut abandoned_batch
                )
                .outcome,
            Outcome::Pending
        );
        let completed = Arc::new(AtomicUsize::new(0));
        for n in 100..164 {
            assert!(matches!(
                sink.deliver(
                    ExportStream::Logs as u8,
                    serde_json::json!({"n":n}).to_string().into_bytes(),
                    Box::new(LineHeld(completed.clone()))
                ),
                Delivered::Queued
            ));
        }
        until(
            "64 flusher deliveries and the inline cancellation case are pending",
            || far.stalled() == 65,
        );
        let old_owner = owner_of(&far, "old-stall.example");
        let held = d.inline_ticket().unwrap();
        let settings = new.to_string();
        let mut frame = pending_refresh(settings.as_bytes(), 2);
        start_pending_refresh(sink.plugin(), held.ticket(), &mut frame);
        let candidate = owner_of(&far, "refresh-stall.example");
        assert_ne!(candidate, old_owner);
        candidate_is_kept(&far, candidate);
        for _ in 0..3 {
            wake_owner(&far, candidate);
            assert_eq!(
                refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
                Outcome::Pending
            );
            candidate_is_kept(&far, candidate);
        }
        assert!(matches!(
            sink.deliver(
                ExportStream::Logs as u8,
                b"{\"n\":200}".to_vec(),
                Box::new(LineHeld(completed.clone()))
            ),
            Delivered::Queued
        ));
        cancel(sink.plugin(), abandoned.ticket());
        drop(abandoned);
        release_owner(&far, old_owner);
        until("old deliveries resume while REFRESH is pending", || {
            completed.load(Ordering::SeqCst) == 64
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            far.carried().len(),
            66,
            "new delivery waits across all pending REFRESH crossings"
        );
        assert!(!far
            .carried()
            .iter()
            .any(|request| request["body"] == "{\"n\":2}"));

        release_owner(&far, candidate);
        assert_eq!(
            refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
            Outcome::Pending
        );
        candidate_is_kept(&far, candidate);
        assert_eq!(
            far.carried().len(),
            67,
            "the second candidate probe really pended"
        );
        release_owner(&far, candidate);
        assert_eq!(
            refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
            Outcome::Ready
        );
        drop(held);
        until("fresh delivery enters the accepted candidate", || {
            far.carried().len() == 68
        });
        let request = far
            .carried()
            .into_iter()
            .find(|request| request["body"] == "{\"n\":200}")
            .unwrap();
        assert!(request["target"]
            .as_str()
            .unwrap()
            .contains("refresh-stall.example"));
        release_owner(&far, candidate);
        until("fresh delivery completes", || {
            completed.load(Ordering::SeqCst) == 65
        });
        drop(sink);
        assert_eq!(
            far.forgotten
                .lock()
                .unwrap()
                .iter()
                .filter(|owner| **owner == candidate)
                .count(),
            1
        );
    }
}

#[test]
fn pending_refresh_refusal_and_cancel_retire_candidate_once_and_unblock_prior_generation_both_doors(
) {
    for dropped in [false, true] {
        for cancelled in [false, true] {
            let d = dispatcher();
            let far = Arc::new(Far::default());
            assert!(far.waker.set(d.conn_waker()).is_ok());
            let plugin = loaded(dropped, false, &d, far.clone());
            let old = serde_json::json!({"url":"https://old-stall.example/old","delivery_timeout_secs":600});
            let new = serde_json::json!({"url":"https://refresh-stall.example/pending-refresh-refuse","delivery_timeout_secs":600});
            let sink = ExportInstance::open(plugin, d.clone(), old.to_string().as_bytes()).unwrap();
            let _answer = Released(far.clone());
            let old_owner = owner_of(&far, "old-stall.example");
            let held = d.inline_ticket().unwrap();
            let settings = new.to_string();
            let mut frame = pending_refresh(settings.as_bytes(), 2);
            start_pending_refresh(sink.plugin(), held.ticket(), &mut frame);
            let candidate = owner_of(&far, "refresh-stall.example");
            candidate_is_kept(&far, candidate);
            wake_owner(&far, candidate);
            assert_eq!(
                refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
                Outcome::Pending
            );
            candidate_is_kept(&far, candidate);
            let late = *far.stalled.lock().unwrap().values().next().unwrap();
            let completed = Arc::new(AtomicUsize::new(0));
            assert!(matches!(
                sink.deliver(
                    ExportStream::Logs as u8,
                    b"{\"n\":300}".to_vec(),
                    Box::new(LineHeld(completed.clone()))
                ),
                Delivered::Queued
            ));
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(far.carried().len(), 1);
            if cancelled {
                cancel(sink.plugin(), held.ticket());
                cancel(sink.plugin(), held.ticket());
            } else {
                release_owner(&far, candidate);
                assert_eq!(
                    refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
                    Outcome::Pending
                );
                candidate_is_kept(&far, candidate);
                release_owner(&far, candidate);
                assert_eq!(
                    refresh_crossing(sink.plugin(), held.ticket(), true, &mut frame),
                    Outcome::Refused
                );
            }
            drop(held);
            assert_eq!(
                far.forgotten
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|owner| **owner == candidate)
                    .count(),
                1
            );
            far.waker.get().unwrap()(late.0, late.1);
            until(
                "prior generation is unblocked after terminal REFRESH",
                || {
                    far.carried()
                        .iter()
                        .any(|request| request["body"] == "{\"n\":300}")
                },
            );
            let request = far
                .carried()
                .into_iter()
                .find(|request| request["body"] == "{\"n\":300}")
                .unwrap();
            assert!(request["target"]
                .as_str()
                .unwrap()
                .contains("old-stall.example"));
            release_owner(&far, old_owner);
            until("unblocked delivery completes", || {
                completed.load(Ordering::SeqCst) == 1
            });
            drop(sink);
            assert_eq!(
                far.forgotten
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|owner| **owner == candidate)
                    .count(),
                1
            );
        }
    }
}

#[test]
fn pending_export_batch_keeps_its_target_and_credentials_after_same_instance_refresh_both_doors() {
    for dropped in [false, true] {
        let d = dispatcher();
        let far = Arc::new(Far::default());
        assert!(far.waker.set(d.conn_waker()).is_ok());
        let plugin = loaded(dropped, false, &d, far.clone());
        let old = serde_json::json!({"url":format!("https://alice:old@{STALL_TARGET}/old"),
            "auth_header":{"name":"x-generation","value":"credential-A"},"delivery_timeout_secs":600});
        let new = serde_json::json!({"url":"https://bob:new@collector-b.example/new",
            "auth_header":{"name":"x-generation","value":"credential-B"},"delivery_timeout_secs":600});
        let sink = ExportInstance::open(plugin, d.clone(), old.to_string().as_bytes()).unwrap();
        let first = d.inline_ticket().unwrap();
        let mut old_batch = batch(b"{\"n\":1}\n{\"n\":2}\n", 1);
        assert_eq!(
            sink.plugin()
                .call_inline(first.ticket(), false, export_slot::DELIVER, &mut old_batch)
                .outcome,
            Outcome::Pending
        );
        assert_eq!(far.stalled(), 1);
        assert_eq!(far.carried().len(), 1);
        assert_eq!(refresh(sink.plugin(), &new, 2), Outcome::Ready);

        let fresh = d.inline_ticket().unwrap();
        let mut fresh_batch = batch(b"{\"n\":3}\n", 2);
        let initial = sink.plugin().call_inline(
            fresh.ticket(),
            false,
            export_slot::DELIVER,
            &mut fresh_batch,
        );
        if initial.outcome == Outcome::Pending {
            finish(sink.plugin(), fresh.ticket(), &mut fresh_batch);
        } else {
            assert_eq!(initial.outcome, Outcome::Ready);
        }
        drop(fresh);
        far.release();
        finish(sink.plugin(), first.ticket(), &mut old_batch);

        let carried = far.carried();
        for n in [1, 2, 3] {
            let request = carried
                .iter()
                .find(|request| request["body"] == format!("{{\"n\":{n}}}"))
                .unwrap();
            let (target, path, credential, basic) = if n == 3 {
                (
                    "collector-b.example",
                    "/new",
                    "credential-B",
                    "Basic Ym9iOm5ldw==",
                )
            } else {
                (STALL_TARGET, "/old", "credential-A", "Basic YWxpY2U6b2xk")
            };
            assert!(
                request["target"].as_str().unwrap().contains(target),
                "{request}"
            );
            assert_eq!(request["head_target"], path);
            let fields = request["fields"].as_array().unwrap();
            assert!(fields
                .iter()
                .any(|field| field == &serde_json::json!(["x-generation", credential])));
            assert!(fields
                .iter()
                .any(|field| field == &serde_json::json!(["authorization", basic])));
        }

        // Retiring the old ticket releases its declaration without holding a host guard across
        // the table's callback into the same plugin's STATUS slot.
        let reentered = Arc::new(AtomicUsize::new(0));
        let calls = reentered.clone();
        let plugin = sink.plugin().clone();
        *far.on_forget.lock().unwrap() = Some(Arc::new(move |_| {
            let mut status = Frame::new(
                in_head(),
                StatusOut {
                    head: out_head(),
                    status: NO_BLOB,
                },
            );
            assert_eq!(
                plugin.call(export_slot::STATUS, &mut status).outcome,
                Outcome::Ready
            );
            calls.fetch_add(1, Ordering::SeqCst);
        }));
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(first);
            let _ = send.send(());
        });
        recv.recv_timeout(Duration::from_secs(5))
            .expect("old generation cleanup re-enters without a host guard");
        *far.on_forget.lock().unwrap() = None;
        assert_eq!(reentered.load(Ordering::SeqCst), 1);

        let rejected = serde_json::json!({"url":"https://collector-c.example/rejected","bogus":1});
        assert_ne!(refresh(sink.plugin(), &rejected, 3), Outcome::Ready);
        let fresh = d.inline_ticket().unwrap();
        let mut after_refusal = batch(b"{\"n\":4}\n", 3);
        let initial = sink.plugin().call_inline(
            fresh.ticket(),
            false,
            export_slot::DELIVER,
            &mut after_refusal,
        );
        if initial.outcome == Outcome::Pending {
            finish(sink.plugin(), fresh.ticket(), &mut after_refusal);
        } else {
            assert_eq!(initial.outcome, Outcome::Ready);
        }
        let last = far.carried().pop().unwrap();
        assert!(last["target"]
            .as_str()
            .unwrap()
            .contains("collector-b.example"));
        assert_eq!(last["head_target"], "/new");
        drop(fresh);
        drop(sink);
    }
}

#[test]
fn cancelled_export_connector_batch_does_not_resume_on_a_reused_ticket_after_refresh_both_doors() {
    for dropped in [false, true] {
        let d = dispatcher();
        let far = Arc::new(Far::default());
        assert!(far.waker.set(d.conn_waker()).is_ok());
        let plugin = loaded(dropped, false, &d, far.clone());
        let old = serde_json::json!({"url":format!("https://{STALL_TARGET}/cancelled"),"delivery_timeout_secs":600});
        let new = serde_json::json!({"url":"https://collector-b.example/current"});
        let sink = ExportInstance::open(plugin, d.clone(), old.to_string().as_bytes()).unwrap();
        let cancelled = d.inline_ticket().unwrap();
        let old_ticket = cancelled.ticket();
        let mut old_batch = batch(b"{\"n\":10}\n{\"n\":11}\n", 8);
        assert_eq!(
            sink.plugin()
                .call_inline(old_ticket, false, export_slot::DELIVER, &mut old_batch)
                .outcome,
            Outcome::Pending
        );
        let late = *far.stalled.lock().unwrap().values().next().unwrap();
        assert_eq!(refresh(sink.plugin(), &new, 2), Outcome::Ready);
        cancel(sink.plugin(), old_ticket);
        drop(cancelled);
        assert_eq!(far.stalled(), 0);

        let reused = d.inline_ticket().unwrap();
        assert_eq!(reused.ticket().slot, old_ticket.slot);
        assert_ne!(reused.ticket().generation, old_ticket.generation);
        // The far end had captured its wake before cancellation. It may still deliver it after
        // this slot serves a different generation; the host must discard that completion.
        far.waker.get().unwrap()(late.0, late.1);
        let mut current = batch(b"{\"n\":12}\n", 9);
        let initial =
            sink.plugin()
                .call_inline(reused.ticket(), false, export_slot::DELIVER, &mut current);
        if initial.outcome == Outcome::Pending {
            finish(sink.plugin(), reused.ticket(), &mut current);
        } else {
            assert_eq!(initial.outcome, Outcome::Ready);
        }
        far.waker.get().unwrap()(late.0, late.1);
        drop(reused);
        let carried = far.carried();
        assert_eq!(
            carried.len(),
            2,
            "cancelled batch's second line must never open"
        );
        assert_eq!(carried[0]["body"], "{\"n\":10}");
        assert_eq!(carried[1]["body"], "{\"n\":12}");
        assert!(carried[1]["target"]
            .as_str()
            .unwrap()
            .contains("collector-b.example"));
        assert_eq!(carried[1]["head_target"], "/current");
        assert_eq!(far.stalled(), 0);
        drop(sink);
        assert!(far.verdicts.lock().unwrap().is_empty());
    }
}

struct Unblock(Option<std::sync::mpsc::Sender<()>>);

impl Drop for Unblock {
    fn drop(&mut self) {
        if let Some(send) = self.0.take() {
            let _ = send.send(());
        }
    }
}

struct LineHeld(Arc<AtomicUsize>);

impl Drop for LineHeld {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn refresh_enters_at_full_export_capacity_old_batches_resume_and_new_batches_wait_both_doors() {
    for dropped in [false, true] {
        let mut config = DispatchConfig::default();
        config.budgets.lifecycle = Duration::from_secs(60);
        let d = Arc::new(Dispatcher::new(config));
        let far = Arc::new(Far::default());
        assert!(far.waker.set(d.conn_waker()).is_ok());
        let plugin = loaded(dropped, false, &d, far.clone());
        let old = serde_json::json!({"url":format!("https://{STALL_TARGET}/old"),
            "max_inflight_deliveries":64,"delivery_timeout_secs":600});
        let new = serde_json::json!({"url":"https://collector-b.example/new",
            "max_inflight_deliveries":64,"delivery_timeout_secs":600});
        let sink = ExportInstance::open(plugin, d.clone(), old.to_string().as_bytes()).unwrap();
        let _answer = Released(far.clone());
        let done = Arc::new(AtomicUsize::new(0));
        for n in 0..64 {
            assert!(matches!(
                sink.deliver(
                    ExportStream::Logs as u8,
                    serde_json::json!({"n":n}).to_string().into_bytes(),
                    Box::new(LineHeld(done.clone()))
                ),
                Delivered::Queued
            ));
        }
        until("all 64 export tickets pending", || far.stalled() == 64);
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = Mutex::new(wait);
        *far.on_declare.lock().unwrap() = Some(Arc::new(move |target| {
            if target.contains("collector-b.example") {
                entered.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .expect("release staged REFRESH");
            }
        }));
        let mut unblock = Unblock(Some(release));
        let plugin = sink.plugin().clone();
        let (result, ready) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let answer = refresh(&plugin, &new, 2);
                if answer != Outcome::Refused || Instant::now() >= deadline {
                    let _ = result.send(answer);
                    break;
                }
                // Far records the last stalled read before that crossing has returned. Let
                // its first-entry guard leave before asking REFRESH to take the admission.
                std::thread::yield_now();
            }
        });
        observed
            .recv_timeout(Duration::from_secs(5))
            .expect("REFRESH enters even with all 64 delivery tickets held");
        assert!(matches!(
            sink.deliver(
                ExportStream::Logs as u8,
                b"{\"n\":64}".to_vec(),
                Box::new(LineHeld(done.clone()))
            ),
            Delivered::Queued
        ));
        far.release();
        until("old export batches resume during REFRESH", || {
            done.load(Ordering::SeqCst) == 64
        });
        assert_eq!(
            far.carried().len(),
            64,
            "new batch waits for REFRESH publication"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            far.carried().len(),
            64,
            "new batch cannot enter while REFRESH is staged"
        );
        unblock.0.take().unwrap().send(()).unwrap();
        assert_eq!(
            ready.recv_timeout(Duration::from_secs(5)).unwrap(),
            Outcome::Ready
        );
        *far.on_declare.lock().unwrap() = None;
        until("new batch enters the published generation", || {
            done.load(Ordering::SeqCst) == 65
        });
        let carried = far.carried();
        assert_eq!(carried.len(), 65);
        let current = carried
            .iter()
            .find(|request| request["body"] == "{\"n\":64}")
            .unwrap();
        assert!(current["target"]
            .as_str()
            .unwrap()
            .contains("collector-b.example"));
        assert_eq!(current["head_target"], "/new");
        drop(sink);
    }
}

type DiskAppend = (DiskDest, Vec<u8>, Later);

#[derive(Default)]
struct HeldDisk(Mutex<VecDeque<DiskAppend>>);

impl crate::services_double::ServicesDouble for Arc<HeldDisk> {
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        self.0
            .lock()
            .unwrap()
            .push_back((dest.clone(), bytes, later));
        Ran::Later
    }
}

impl HeldDisk {
    fn complete(&self) -> String {
        let (dest, bytes, later) = self.0.lock().unwrap().pop_front().unwrap();
        later(DiskHost::append(&dest, &bytes).stored());
        dest.path
    }
}

#[test]
fn pending_export_disk_append_keeps_old_path_and_cancelled_late_reply_cannot_reach_reused_ticket_both_doors(
) {
    for dropped in [false, true] {
        let dir = scratch(if dropped {
            "refresh-disk-dropped"
        } else {
            "refresh-disk-linked"
        });
        let a = dir.join("a.jsonl");
        let b = dir.join("b.jsonl");
        let c = dir.join("c.jsonl");
        let disk = Arc::new(HeldDisk::default());
        let d = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(crate::services_double::Double(disk.clone())),
        ));
        let plugin = loaded(dropped, true, &d, Arc::new(Far::default()));
        let sink = opened(plugin, d.clone(), &file_settings(&a));
        let old = d.inline_ticket().unwrap();
        let mut old_batch = batch(b"{\"n\":1}\n", 4);
        assert_eq!(
            sink.plugin()
                .call_inline(old.ticket(), false, export_slot::DELIVER, &mut old_batch)
                .outcome,
            Outcome::Pending
        );
        until("the old disk append is held", || {
            disk.0.lock().unwrap().len() == 1
        });
        assert_eq!(
            refresh(sink.plugin(), &file_settings(&b), 2),
            Outcome::Ready
        );
        let fresh = d.inline_ticket().unwrap();
        let mut new_batch = batch(b"{\"n\":2}\n", 5);
        assert_eq!(
            sink.plugin()
                .call_inline(fresh.ticket(), false, export_slot::DELIVER, &mut new_batch)
                .outcome,
            Outcome::Pending
        );
        until("both disk appends are held", || {
            disk.0.lock().unwrap().len() == 2
        });
        assert_eq!(disk.complete(), a.display().to_string());
        finish(sink.plugin(), old.ticket(), &mut old_batch);
        assert_eq!(disk.complete(), b.display().to_string());
        finish(sink.plugin(), fresh.ticket(), &mut new_batch);
        drop(old);
        drop(fresh);
        assert_eq!(ns(&a), Some(vec![1]));
        assert_eq!(ns(&b), Some(vec![2]));
        let rejected = serde_json::json!({"path":c,"bogus":1});
        assert_ne!(refresh(sink.plugin(), &rejected, 3), Outcome::Ready);

        let cancelled = d.inline_ticket().unwrap();
        let old_ticket = cancelled.ticket();
        let mut cancelled_batch = batch(b"{\"n\":3}\n", 6);
        assert_eq!(
            sink.plugin()
                .call_inline(
                    old_ticket,
                    false,
                    export_slot::DELIVER,
                    &mut cancelled_batch
                )
                .outcome,
            Outcome::Pending
        );
        until("the cancelled disk append is held", || {
            disk.0.lock().unwrap().len() == 1
        });
        cancel(sink.plugin(), old_ticket);
        drop(cancelled);
        let reused = d.inline_ticket().unwrap();
        assert_eq!(reused.ticket().slot, old_ticket.slot);
        assert_ne!(reused.ticket().generation, old_ticket.generation);
        let mut later_batch = batch(b"{\"n\":4}\n", 7);
        assert_eq!(
            sink.plugin()
                .call_inline(
                    reused.ticket(),
                    false,
                    export_slot::DELIVER,
                    &mut later_batch
                )
                .outcome,
            Outcome::Pending
        );
        until("the reused ticket disk append is held", || {
            disk.0.lock().unwrap().len() == 2
        });
        // An already issued disk write may finish after CANCEL. Its completion belongs to the
        // old ticket and cannot settle or replay the new generation's append.
        assert_eq!(disk.complete(), b.display().to_string());
        assert_eq!(
            sink.plugin()
                .call_inline(
                    reused.ticket(),
                    true,
                    export_slot::DELIVER,
                    &mut later_batch
                )
                .outcome,
            Outcome::Pending
        );
        assert_eq!(disk.0.lock().unwrap().len(), 1);
        assert_eq!(disk.complete(), b.display().to_string());
        finish(sink.plugin(), reused.ticket(), &mut later_batch);
        drop(reused);
        assert_eq!(ns(&a), Some(vec![1]));
        assert_eq!(ns(&b), Some(vec![2, 3, 4]));
        assert!(!c.exists());
        assert!(disk.0.lock().unwrap().is_empty());
        drop(sink);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn forgotten_pending_refresh_wakes_after_the_callers_state_lock_is_released() {
    use crate::dispatch::ticket::{InstanceWake, WakeRoute};
    use std::sync::atomic::{AtomicBool, Ordering};

    const REFRESH_TICKET: Ticket = Ticket {
        slot: 0,
        generation: 1,
    };
    const WAITING_DELIVERY: Ticket = Ticket {
        slot: 1,
        generation: 1,
    };

    struct ProbeRoute {
        state: std::sync::Mutex<()>,
        woke_without_state_lock: AtomicBool,
        woken: std::sync::Mutex<Vec<Ticket>>,
    }

    impl WakeRoute for ProbeRoute {
        fn wake(&self, ticket: Ticket, _: Option<&'static InstanceWake>) {
            self.woke_without_state_lock
                .store(self.state.try_lock().is_ok(), Ordering::SeqCst);
            self.woken.lock().unwrap().push(ticket);
        }
    }

    let route = Arc::new(ProbeRoute {
        state: std::sync::Mutex::new(()),
        woke_without_state_lock: AtomicBool::new(false),
        woken: std::sync::Mutex::new(Vec::new()),
    });
    let routed: Arc<dyn WakeRoute> = route.clone();
    let wake: &'static InstanceWake = Box::leak(Box::new(InstanceWake::default()));
    assert!(wake.route.set(Arc::downgrade(&routed)).is_ok());

    let admission = wake
        .exports
        .admit(wake, life::REFRESH, REFRESH_TICKET)
        .expect("refresh admitted");
    wake.exports.pending_refresh(REFRESH_TICKET);
    drop(admission);
    assert!(wake
        .exports
        .admit(wake, export_slot::DELIVER, WAITING_DELIVERY)
        .is_none());

    // Ticket retirement is called with a worker state guard held. Its returned cleanup may drop
    // after that guard; the routed wake is a caller callback and must observe the unlocked state.
    let state = route.state.lock().unwrap();
    let forgotten = wake.exports.forget(wake, REFRESH_TICKET);
    drop(state);
    drop(forgotten);
    assert_eq!(&*route.woken.lock().unwrap(), &[WAITING_DELIVERY]);
    assert!(route.woke_without_state_lock.load(Ordering::SeqCst));
}

#[test]
fn worker_delivery_releases_inline_refresh_waiter_after_unlock_both_doors() {
    use std::sync::atomic::AtomicBool;
    use std::task::Wake;

    const LOCK_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
    const CROSSING_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
    const CROSSING_WATCHDOG_BUDGET: Duration = Duration::from_secs(20);
    const PROBE_WORKER_INDEX: u32 = 0;
    const NEXT_SETTINGS_GENERATION: u64 = 2;

    struct WorkerLockProbe {
        dispatcher: Arc<Dispatcher>,
        worker_ticket: Ticket,
        result: std::sync::mpsc::Sender<bool>,
    }

    impl Wake for WorkerLockProbe {
        fn wake(self: Arc<Self>) {
            let (done, observed) = std::sync::mpsc::channel();
            let dispatcher = Arc::clone(&self.dispatcher);
            let ticket = self.worker_ticket;
            std::thread::spawn(move || {
                let _ = dispatcher.slot_state(ticket);
                let _ = done.send(());
            });
            let _ = self
                .result
                .send(observed.recv_timeout(LOCK_PROBE_TIMEOUT).is_ok());
        }
    }

    for dropped in [false, true] {
        let mut config = DispatchConfig::default();
        config.budgets.write_behind = CROSSING_WATCHDOG_BUDGET;
        let dispatcher = Arc::new(Dispatcher::new(config));
        let worker_ticket = dispatcher
            .mint(PROBE_WORKER_INDEX)
            .expect("probe worker slot");
        let far = Arc::new(Far::default());
        assert!(far.waker.set(dispatcher.conn_waker()).is_ok());
        let plugin = loaded(dropped, false, &dispatcher, Arc::clone(&far));
        let settings = serde_json::json!({"url":"https://collector.example/worker-wake"});
        let sink = ExportInstance::open(
            plugin,
            Arc::clone(&dispatcher),
            settings.to_string().as_bytes(),
        )
        .expect("open export sink");
        let (entered, entering) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let first_open = AtomicBool::new(false);
        *far.on_open.lock().unwrap() = Some(Arc::new(move |_| {
            if !first_open.swap(true, Ordering::SeqCst) {
                let _ = entered.send(());
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(CROSSING_CONTROL_TIMEOUT)
                    .expect("release export connector crossing");
            }
        }));
        let mut unblock = Unblock(Some(release));
        let (result, woke) = std::sync::mpsc::channel();
        let inline = dispatcher.inline_ticket().expect("inline refresh ticket");
        inline.register(&std::task::Waker::from(Arc::new(WorkerLockProbe {
            dispatcher: Arc::clone(&dispatcher),
            worker_ticket,
            result,
        })));
        let finished = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            sink.deliver(
                ExportStream::Logs as u8,
                b"{\"event\":\"worker-wake\"}".to_vec(),
                Box::new(LineHeld(Arc::clone(&finished))),
            ),
            Delivered::Queued
        ));
        entering
            .recv_timeout(CROSSING_CONTROL_TIMEOUT)
            .expect("delivery enters the real connector crossing");
        let next = serde_json::json!({"url":"https://collector.example/next"});
        let next_bytes = next.to_string();
        let mut frame = pending_refresh(next_bytes.as_bytes(), NEXT_SETTINGS_GENERATION);
        assert_eq!(
            refresh_crossing(sink.plugin(), inline.ticket(), false, &mut frame),
            Outcome::Refused,
            "an entering delivery holds the inline refresh barrier"
        );
        unblock.0.take().unwrap().send(()).unwrap();
        assert!(
            woke.recv_timeout(CROSSING_CONTROL_TIMEOUT)
                .expect("the inline refresh waiter is woken"),
            "the user waker must observe the worker state lock released"
        );
        until("the queued delivery finishes", || {
            finished.load(Ordering::SeqCst) == 1
        });
        *far.on_open.lock().unwrap() = None;
        drop(inline);
        drop(sink);
    }
}
