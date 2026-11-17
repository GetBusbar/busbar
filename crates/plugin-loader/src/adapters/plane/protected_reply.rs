// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Whole-answer classification for protected native channel staging. This parser performs no
//! host effects and grants no exchange authority; the live session must check its held lease.

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::plane::{self as p, tag, ExMsg};
use busbar_plugin_abi::records::Records;

use super::{decode_answer, fault, Call};

pub enum Classification<'a> {
    Empty,
    Reply {
        exchange: u32,
        flags: u32,
        payload: &'a [u8],
    },
    /// Valid native output, but it needs whole-answer general admission before any effect.
    General,
}

/// Apply the existing complete native callback validator before classifying any output. No
/// partially valid prefix can escape; the second bounded read reuses the shared record codec.
pub fn classify(
    from: u32,
    has_demux: bool,
    answer: &[u8],
    max_message: usize,
) -> Result<Classification<'_>, FaultReason> {
    decode_answer(
        Call::Piece(from),
        has_demux,
        Records::new(answer),
        &mut |_| {},
    )?;
    let mut records = Records::new(answer);
    let Some(first) = records.next() else {
        return Ok(Classification::Empty);
    };
    let first = first.map_err(fault)?;
    if records.next().is_some() || first.tag != tag::EX_MSG {
        return Ok(Classification::General);
    }
    let (message, payload) = first.pod_tail::<ExMsg>().map_err(fault)?;
    if message.flags & p::MSG_ASK != 0 || message.stream != 0 || payload.len() > max_message {
        return Ok(Classification::General);
    }
    Ok(Classification::Reply {
        exchange: message.exchange,
        flags: message.flags,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, Writer};

    fn message(out: &mut Reply, flags: u32) {
        out.put_pod_tail(
            tag::EX_MSG,
            &ExMsg {
                exchange: 1,
                flags,
                stream: 0,
            },
            b"reply",
        )
        .unwrap();
    }

    #[test]
    fn a_complete_single_nonask_reply_is_eligible() {
        let mut out = Reply::new();
        message(&mut out, p::MSG_TEXT);
        match classify(p::FROM_CORE, true, out.as_bytes(), 4096).unwrap() {
            Classification::Reply {
                exchange, payload, ..
            } => {
                assert_eq!(exchange, 1);
                assert_eq!(payload, b"reply");
            }
            _ => panic!("one native reply"),
        }
    }

    #[test]
    fn ask_compound_and_malformed_suffix_cannot_spend_reply_reserve() {
        let mut out = Reply::new();
        message(&mut out, p::MSG_ASK);
        assert!(matches!(
            classify(p::FROM_CORE, true, out.as_bytes(), 4096).unwrap(),
            Classification::General
        ));
        out = Reply::new();
        message(&mut out, p::MSG_TEXT);
        message(&mut out, p::MSG_TEXT);
        assert!(matches!(
            classify(p::FROM_CORE, true, out.as_bytes(), 4096).unwrap(),
            Classification::General
        ));
        let mut truncated = out.as_bytes().to_vec();
        truncated.push(0);
        assert!(classify(p::FROM_CORE, true, &truncated, 4096).is_err());
    }
}
