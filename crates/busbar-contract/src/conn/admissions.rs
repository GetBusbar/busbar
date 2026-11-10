// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Metadata-directed settings admission into a kernel-issued connection table.
//! Target material never leaves this operation as a readable result or caller callback.

use std::sync::Arc;

use super::{ConnError, DeclaredConns, InstanceId, NeedId, Program};
use crate::abi::mechanism::rendering::ReadNeed;
use crate::plugin_settings::Settings;

/// Authority to bind settings admission to the actual host enforcement table.
/// Issuance is privileged kernel composition, subject to the host source-direction boundary.
/// It does not claim to protect values from malicious privileged kernel code.
///
/// An ordinary host grant cannot construct this authority:
/// ```compile_fail,E0308
/// use busbar_contract::{conn::{DeclaredConns, admissions::AdmissionAuthority}, plugin::KernelSeal};
/// fn forge(seal: &dyn KernelSeal, table: std::sync::Arc<dyn DeclaredConns>) {
///     let _ = AdmissionAuthority::issue(seal, table);
/// }
/// ```
/// Nor can a caller install its own callback through a field literal:
/// ```compile_fail
/// use busbar_contract::conn::{DeclaredConns, admissions::AdmissionAuthority};
/// fn forge(table: std::sync::Arc<dyn DeclaredConns>) {
///     let _ = AdmissionAuthority { table };
/// }
/// ```
#[derive(Clone)]
pub struct AdmissionAuthority {
    table: Arc<dyn DeclaredConns>,
}

impl AdmissionAuthority {
    /// Issue only while holding the kernel's concrete root minter, never a generic seal/grant.
    pub fn issue(_: &crate::caps::KernelSeal, table: Arc<dyn DeclaredConns>) -> Self {
        Self { table }
    }

    /// Bind the validated instance identity and its admitted declaration once.
    pub fn bind(&self, owner: InstanceId, needs: &[ReadNeed]) -> EnforcedAdmissions {
        EnforcedAdmissions {
            table: Arc::clone(&self.table),
            owner,
            needs: Arc::from(needs),
            lineage: Arc::new(()),
        }
    }

    /// The already issued table used by the host's ordinary connection operations.
    pub fn table(&self) -> &Arc<dyn DeclaredConns> {
        &self.table
    }
}
impl std::fmt::Debug for AdmissionAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmissionAuthority(<host table>)")
    }
}

/// One immutable instance/declaration binding. Refresh successors retain its lineage and table.
#[derive(Clone)]
pub struct EnforcedAdmissions {
    table: Arc<dyn DeclaredConns>,
    owner: InstanceId,
    needs: Arc<[ReadNeed]>,
    lineage: Arc<()>,
}
impl std::fmt::Debug for EnforcedAdmissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnforcedAdmissions")
            .field("owner", &self.owner)
            .field("needs", &self.needs.len())
            .finish_non_exhaustive()
    }
}

/// A refusal contains only fixed kind vocabulary and existing connection error classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefused {
    /// A required target was absent from the admitted settings position.
    TargetUnresolved,
    /// The common program grammar could not be read.
    ProgramMalformed,
    /// The actual host table refused the operation.
    Connection(ConnError),
}

/// One need's admission result. No settings value is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedNeed {
    /// Position in the instance's admitted declaration.
    pub need: NeedId,
    /// Result from the real host enforcement table.
    pub result: Result<(), AdmissionRefused>,
    /// Whether this result is reported immediately (an unwritten optional trust source is deferred).
    pub report: bool,
    /// A declared trust position was supplied but refused; carries the metadata path only.
    pub trust_refused_at: Option<String>,
}

impl EnforcedAdmissions {
    /// Preserve this loaded instance's declaration/authority for a new refresh generation.
    pub fn successor(&self, owner: InstanceId) -> Self {
        Self {
            owner,
            ..self.clone()
        }
    }

    /// Admit the guarded settings only on this instance's already issued enforcement table.
    /// A foreign predecessor is rejected before any settings position is read or table called.
    pub fn apply(
        &self,
        settings: Option<&Settings>,
        owned: Option<&Settings>,
        predecessor: Option<&Self>,
    ) -> Result<Vec<AdmittedNeed>, ConnError> {
        if predecessor.is_some_and(|previous| {
            previous.owner == self.owner
                || !Arc::ptr_eq(&previous.table, &self.table)
                || !Arc::ptr_eq(&previous.lineage, &self.lineage)
        }) {
            return Err(ConnError::NotOwner);
        }
        let document = settings.map(|settings| &settings.0 .0);
        let owned = owned.map(|settings| &settings.0 .0);
        let mut results = Vec::new();
        for (index, need) in self.needs.iter().enumerate() {
            if need.target_from.is_empty() && need.trust_from.is_empty() {
                continue;
            }
            let id = NeedId(u32::try_from(index).unwrap_or(u32::MAX));
            if crate::section::member_program(&need.target_from) {
                let programs: Vec<_> = document
                    .and_then(serde_json::Value::as_object)
                    .into_iter()
                    .flatten()
                    .filter_map(|(name, value)| {
                        Some((name.clone(), Program::of_member(value)?.ok()?))
                    })
                    .collect();
                let answer = match predecessor {
                    Some(previous) => self.table.declare_member_programs_from(
                        previous.owner,
                        self.owner,
                        id,
                        need,
                        &programs,
                    ),
                    None => self
                        .table
                        .declare_member_programs(self.owner, id, need, &programs),
                };
                results.push(AdmittedNeed {
                    need: id,
                    result: answer.map_err(AdmissionRefused::Connection),
                    report: true,
                    trust_refused_at: None,
                });
                continue;
            }
            let value = document.and_then(|doc| setting(doc, &need.target_from));
            if let Some(value) = value.filter(|value| value.is_object()) {
                let answer = match Program::from_settings(value) {
                    Ok(program) => self
                        .table
                        .declare_program(self.owner, id, need, &program)
                        .map_err(AdmissionRefused::Connection),
                    Err(_) => self
                        .table
                        .declare(self.owner, id, need, None, None)
                        .map_err(|_| AdmissionRefused::ProgramMalformed),
                };
                results.push(AdmittedNeed {
                    need: id,
                    result: answer,
                    report: true,
                    trust_refused_at: None,
                });
                continue;
            }
            let target = value.and_then(text);
            let trust = match crate::section::owned_path(&need.trust_from) {
                Some(path) => owned.and_then(|doc| at(doc, path)).and_then(text),
                None => document
                    .and_then(|doc| setting(doc, &need.trust_from))
                    .and_then(text),
            };
            let unresolved = target.is_none()
                && !need.target_from.is_empty()
                && crate::section::member_target(&need.target_from).is_none();
            let trust_unwritten = trust.is_none()
                && !need.trust_from.is_empty()
                && crate::section::owned_path(&need.trust_from).is_none()
                && crate::section::member_target(&need.target_from).is_none();
            let answer = self
                .table
                .declare(self.owner, id, need, target, trust)
                .map_err(|error| {
                    if unresolved {
                        AdmissionRefused::TargetUnresolved
                    } else {
                        AdmissionRefused::Connection(error)
                    }
                });
            let trust_refused_at = (answer.is_err() && trust.is_some() && !unresolved)
                .then(|| need.trust_from.clone());
            results.push(AdmittedNeed {
                need: id,
                result: answer,
                report: unresolved || !trust_unwritten,
                trust_refused_at,
            });
        }
        Ok(results)
    }
}

fn text(value: &serde_json::Value) -> Option<&str> {
    value.as_str().filter(|value| !value.is_empty())
}
fn at<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(value, |value, key| value.get(key))
}
fn setting<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    at(value, path.strip_prefix("settings.")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{ConnId, Conns, OpenDesc, Piece, Ticket};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Table(AtomicUsize);
    impl Conns for Table {
        fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
            Err(ConnError::Refused)
        }
        fn write(
            &self,
            _: InstanceId,
            _: ConnId,
            _: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            Err(ConnError::Refused)
        }
        fn read(
            &self,
            _: InstanceId,
            _: ConnId,
            _: Ticket,
            _: &mut [u8],
        ) -> Result<Piece, ConnError> {
            Err(ConnError::Refused)
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
            Err(ConnError::Refused)
        }
        fn facts(
            &self,
            _: InstanceId,
            _: ConnId,
        ) -> Result<crate::transport::ConnFacts, ConnError> {
            Err(ConnError::Refused)
        }
        fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
            Err(ConnError::Refused)
        }
    }
    impl DeclaredConns for Table {
        fn serves_scheme(&self, _: &str) -> bool {
            true
        }
        fn declare(
            &self,
            _: InstanceId,
            _: NeedId,
            _: &ReadNeed,
            target: Option<&str>,
            _: Option<&str>,
        ) -> Result<(), ConnError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if target == Some("admitted-target-canary") {
                Ok(())
            } else {
                Err(ConnError::Refused)
            }
        }
        fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
            None
        }
    }

    fn need() -> ReadNeed {
        ReadNeed {
            direction: crate::abi::host::conn::connector::DIRECTION_OUTBOUND,
            egress_class: 0,
            transport: "byte-stream".into(),
            auth: String::new(),
            target_from: "settings.destination".into(),
            trust_from: String::new(),
            details: crate::abi::mechanism::rendering::ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            keep_response_headers: Vec::new(),
            timeout_ms: 0,
            keep_mode: 0,
            deny_response_headers: Vec::new(),
        }
    }

    #[test]
    fn foreign_predecessor_is_refused_before_target_use() {
        let table = Arc::new(Table::default());
        // The unit witness is inside the issuer module; external construction is compile-fail.
        let authority = AdmissionAuthority {
            table: table.clone(),
        };
        let first = authority.bind(InstanceId(1), &[need()]);
        let second = first.successor(InstanceId(2));
        let foreign = authority.bind(InstanceId(3), &[need()]);
        let settings: Settings =
            serde_json::from_value(serde_json::json!({"destination":"admitted-target-canary"}))
                .unwrap();
        assert_eq!(
            second.apply(Some(&settings), None, Some(&foreign)),
            Err(ConnError::NotOwner)
        );
        assert_eq!(
            table.0.load(Ordering::SeqCst),
            0,
            "no target reaches the table before lineage admission"
        );
        assert_eq!(
            first.apply(Some(&settings), None, Some(&first)),
            Err(ConnError::NotOwner)
        );
        assert_eq!(table.0.load(Ordering::SeqCst), 0);
        let results = second.apply(Some(&settings), None, Some(&first)).unwrap();
        assert_eq!(results[0].result, Ok(()));
        assert_eq!(table.0.load(Ordering::SeqCst), 1);
        let missing = Settings::default();
        let results = second.apply(Some(&missing), None, Some(&first)).unwrap();
        assert_eq!(results[0].result, Err(AdmissionRefused::TargetUnresolved));
        assert!(results[0].report);
        assert!(!format!("{first:?} {results:?}").contains("admitted-target-canary"));
    }
}
