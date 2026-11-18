// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook facts the native driver and its walk share: the unit's hook record and its journal,
//! the caller key a hook granted `user` is shown, the candidates the walk reports to the hooks and
//! the constraint the hooks put back on it. The hook calls themselves are the native bindings'
//! ([`super::native_hook_bindings`], [`super::port_hooks`]).

use std::sync::Arc;

use busbar_contract::signal::SignalBag;
use busbar_kernel_audit::record::HookApplied;

use crate::config::PolicyOnError;

/// ONE UNIT'S HOOK FACTS, as its hook stage reports them: every hook that ran for it, in the order
/// it ran, by the key the deployment configured it under (never the instance serving it), with its
/// decision head and whether it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HooksRan<'a> {
    /// The unit the hooks ran for: the record is sealed under that unit's facts.
    pub unit: busbar_contract::UnitKey,
    /// The hooks, in the order they ran: lent by the stage that ran them, which keeps them.
    pub hooks: &'a [HookApplied],
}

pub trait HookJournal: Send + Sync {
    fn hooks_ran(&self, record: &HooksRan<'_>);

    /// Whether the node keeps the end user on its unit records (`records.user`, ADMIN-API-1.6
    /// §3.5). `false` (the default) leaves the driver no work for it.
    fn keeps_end_user(&self) -> bool {
        false
    }

    /// The end user the plane projected for `unit`, once, from the unit's first projection.
    fn end_user(&self, _unit: busbar_contract::UnitKey, _user: &str) {}

    /// The unit's request header fields at Decode, for the record's allow-listed labels
    /// (`records.labels`, ADMIN-API-1.6 §3.5). A node keeping none returns at once.
    fn decoded_fields(&self, _unit: busbar_contract::UnitKey, _fields: &[(Vec<u8>, Vec<u8>)]) {}
}

/// The caller's governance key, as a hook granted `user` is shown it (never its secret).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerKey {
    /// The key's id.
    pub id: String,
    /// The key's display name.
    pub name: String,
}

pub type HookRead = Arc<
    dyn for<'a> Fn(
            &'a [&'a str],
            Option<&'a str>,
            &'a str,
            bool,
        ) -> crate::audit::amend::ReadConfirmation<'a>
        + Send
        + Sync,
>;

/// ONE CANDIDATE, as the walk reports it to the hooks: its configuration and its live signals.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CandidateFacts {
    /// The member's stable index in the pool (what an order names).
    pub idx: usize,
    /// The member's model.
    pub model: String,
    /// The member's provider.
    pub provider: String,
    /// The member's weight.
    pub weight: u32,
    /// The member's context ceiling.
    pub context_max: Option<usize>,
    /// The member's tier.
    pub tier: Option<String>,
    /// The member's cost per million tokens.
    pub cost_per_mtok: Option<f64>,
    /// The host's plane-declared cost terms, already priced for this lane and generation.
    pub route_cost: SignalBag,
    /// The member's tags.
    pub tags: Vec<String>,
    /// The member's latency average, in milliseconds.
    pub latency_ms: Option<f64>,
    /// The member's free concurrency.
    pub available_concurrency: usize,
    /// The member's lifetime budget left.
    pub budget_remaining: Option<i64>,
    /// The member's breaker state (`closed`, `open`, `half_open`).
    pub breaker_state: Option<&'static str>,
    /// The member's error rate.
    pub error_rate: Option<f64>,
    /// The member's p95 latency, in milliseconds.
    pub latency_p95_ms: Option<u64>,
}

/// The candidates of the pool the walk routes a unit over.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Candidates {
    /// The pool.
    pub pool: String,
    /// Its live members, in pool order.
    pub members: Vec<CandidateFacts>,
}

/// A restrict a hook decided: only members carrying one of `tags_any`; `on_empty` when none does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restrict {
    /// The tags, any of which admits a member: the deciding hook's own, moved out of its answer.
    pub tags_any: Vec<Box<str>>,
    /// What an empty intersection does.
    pub on_empty: PolicyOnError,
    /// The deciding hook.
    pub name: std::sync::Arc<str>,
}

/// Whether a member carrying `tags` is admitted by `r`: it carries one of the restrict's tags.
fn admits(r: &Restrict, tags: &[String]) -> bool {
    tags.iter()
        .any(|tag| r.tags_any.iter().any(|wanted| **wanted == **tag))
}

/// THE CONSTRAINT THE HOOKS PUT ON THE WALK.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraint {
    /// The members of the routed pool the walk may pick from (`None` = every one).
    pub keep: Option<Vec<usize>>,
    /// The order the walk tries them in (`None` = the walk's own pick).
    pub order: Option<Vec<usize>>,
    /// An unordered preferred set; all other kept members remain fallback. Ordinary ranking,
    /// configured tiers and weighted rotation apply inside each group; affinity keeps precedence.
    pub prioritize: Option<Vec<usize>>,
    /// The deciding name of the installed order or preferred set: the strategy word of a bound
    /// strategy, else the hook name.
    pub policy: Option<std::sync::Arc<str>>,
    /// Every restrict the hooks decided, re-applied to a fallback pool's members.
    pub restricts: Vec<Restrict>,
}

impl Constraint {
    pub fn enforce<'m>(
        &self,
        members: impl IntoIterator<Item = (usize, &'m [String])> + Clone,
    ) -> Result<Vec<usize>, &Restrict> {
        // The restricts that narrow the members, in the order they were decided: a member is
        // kept when every one of them admits it. A restrict that would leave no member either
        // fails the walk or (`Weighted`) is passed over. No narrowed list is built on the way:
        // only the kept indices, which the caller keeps.
        let mut narrowing = smallvec::SmallVec::<[&Restrict; 4]>::new();
        for r in &self.restricts {
            let leaves_one = members.clone().into_iter().any(|(_, tags)| {
                admits(r, tags) && narrowing.iter().all(|held| admits(held, tags))
            });
            if leaves_one {
                narrowing.push(r);
            } else if !matches!(r.on_empty, PolicyOnError::Weighted) {
                return Err(r);
            }
        }
        Ok(members
            .into_iter()
            .filter(|(_, tags)| narrowing.iter().all(|held| admits(held, tags)))
            .map(|(idx, _)| idx)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reconcile as it was written when it built one list of members per restrict: the model
    /// the listless form is checked against.
    fn listed<'c>(
        constraint: &'c Constraint,
        members: &[(usize, &[String])],
    ) -> Result<Vec<usize>, &'c Restrict> {
        let mut kept: Vec<(usize, &[String])> = members.to_vec();
        for r in &constraint.restricts {
            let narrowed: Vec<(usize, &[String])> = kept
                .iter()
                .copied()
                .filter(|(_, tags)| tags.iter().any(|t| r.tags_any.iter().any(|w| **w == **t)))
                .collect();
            if narrowed.is_empty() {
                if matches!(r.on_empty, PolicyOnError::Weighted) {
                    continue;
                }
                return Err(r);
            }
            kept = narrowed;
        }
        Ok(kept.into_iter().map(|(idx, _)| idx).collect())
    }

    fn restrict(tags: &[&str], on_empty: PolicyOnError) -> Restrict {
        Restrict {
            tags_any: tags.iter().map(|tag| (*tag).into()).collect(),
            on_empty,
            name: "hook".into(),
        }
    }

    fn members(tag_sets: &[&[&str]]) -> Vec<Vec<String>> {
        tag_sets
            .iter()
            .map(|tags| tags.iter().map(|tag| (*tag).to_owned()).collect())
            .collect()
    }

    #[test]
    fn restricts_narrow_in_order_and_an_empty_one_fails_or_is_passed_over() {
        let held = members(&[&["a"], &["b"], &["a", "b"], &["c"]]);
        let lent: Vec<(usize, &[String])> = held
            .iter()
            .enumerate()
            .map(|(at, tags)| (at + 10, tags.as_slice()))
            .collect();
        let kept = |restricts: Vec<Restrict>| {
            Constraint {
                restricts,
                ..Constraint::default()
            }
            .enforce(lent.iter().copied())
            .map_err(|refusing| refusing.tags_any.clone())
        };
        assert_eq!(kept(Vec::new()), Ok(vec![10, 11, 12, 13]));
        assert_eq!(
            kept(vec![restrict(&["a"], PolicyOnError::Reject)]),
            Ok(vec![10, 12])
        );
        assert_eq!(
            kept(vec![
                restrict(&["a"], PolicyOnError::Reject),
                restrict(&["b"], PolicyOnError::Reject)
            ]),
            Ok(vec![12])
        );
        // Nothing carries `z`: a rejecting restrict fails the walk and names itself, a weighted
        // one is passed over and the next still narrows.
        assert_eq!(
            kept(vec![
                restrict(&["a"], PolicyOnError::Reject),
                restrict(&["z"], PolicyOnError::Reject),
            ]),
            Err(vec![Box::<str>::from("z")])
        );
        assert_eq!(
            kept(vec![
                restrict(&["z"], PolicyOnError::Weighted),
                restrict(&["b", "c"], PolicyOnError::Reject),
            ]),
            Ok(vec![11, 12, 13])
        );
        // `a` then `c` leaves no member, though each alone leaves some.
        assert_eq!(
            kept(vec![
                restrict(&["a"], PolicyOnError::Reject),
                restrict(&["c"], PolicyOnError::Reject),
            ]),
            Err(vec![Box::<str>::from("c")])
        );
    }

    #[test]
    fn enforce_keeps_exactly_what_narrowing_one_list_per_restrict_kept() {
        let held = members(&[&[], &["a"], &["b"], &["a", "b"], &["c"]]);
        let lent: Vec<(usize, &[String])> = held
            .iter()
            .enumerate()
            .map(|(at, tags)| (at * 3, tags.as_slice()))
            .collect();
        let wanted: [&[&str]; 5] = [&["a"], &["b"], &["c"], &["a", "c"], &["z"]];
        let one: Vec<Restrict> = wanted
            .iter()
            .flat_map(|tags| {
                [PolicyOnError::Weighted, PolicyOnError::Reject]
                    .into_iter()
                    .map(move |on_empty| restrict(tags, on_empty))
            })
            .collect();
        // Every sequence of up to three of the ten restricts (a position past the end is none).
        let mut cases = 0;
        for first in 0..=one.len() {
            for second in 0..=one.len() {
                for third in 0..=one.len() {
                    let constraint = Constraint {
                        restricts: [first, second, third]
                            .iter()
                            .filter_map(|at| one.get(*at).cloned())
                            .collect(),
                        ..Constraint::default()
                    };
                    assert_eq!(
                        constraint.enforce(lent.iter().copied()),
                        listed(&constraint, &lent),
                        "{:?}",
                        constraint.restricts
                    );
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 11 * 11 * 11);
    }
}
