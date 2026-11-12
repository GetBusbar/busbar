//! `busbar-ci native-qualify`: the trusted native admission step runner
//! (former `scripts/architecture/native.py` and the `native_*` modules it
//! imported). Full suites run only inside a GitLab job.
//!
//! The project setting chooses this binary's immutable checkout. Candidate
//! code supplies the product, never the policy, compiler witnesses, command
//! list or merge credential. The step list, argv, `receipt.json` bytes,
//! evidence layout and refusal messages are those of the former runner; the
//! only Python left on this path is named in [`pysteps`].
pub mod confine;
pub mod junit;
pub mod product;
pub mod pysteps;
pub mod resources;
pub mod sp;
