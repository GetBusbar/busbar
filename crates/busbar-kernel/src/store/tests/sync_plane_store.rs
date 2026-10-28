// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane-store double written as plain synchronous methods. Each verb runs when it is called and
//! its future answers at once, so a cell can park, fail or re-enter inside a store crossing exactly
//! where the crossing happens.

use super::{PlaneCall, PlaneStore};
use busbar_contract::records::{PlaneRecordRef, PlaneSelector, RecordStoreResult};

/// [`PlaneStore`]'s verbs, synchronous (see the module doc).
pub(crate) trait SyncPlaneStore: Send + Sync + 'static {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>>;
    fn append_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()>;
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>>;
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>>;
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64>;
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()>;
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool>;
}

impl<S: SyncPlaneStore> PlaneStore for S {
    fn upsert_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::upsert_plane_record(
            self, record,
        )))
    }
    fn get_plane_record<'a>(
        &'a self,
        kind: &'a str,
        id: &'a str,
    ) -> PlaneCall<'a, Option<Vec<u8>>> {
        Box::pin(std::future::ready(SyncPlaneStore::get_plane_record(
            self, kind, id,
        )))
    }
    fn append_plane_record<'a>(&'a self, record: PlaneRecordRef<'a>) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::append_plane_record(
            self, record,
        )))
    }
    fn list_plane_records<'a>(
        &'a self,
        kind: &'a str,
        selector: &'a PlaneSelector<'a>,
    ) -> PlaneCall<'a, Vec<Vec<u8>>> {
        Box::pin(std::future::ready(SyncPlaneStore::list_plane_records(
            self, kind, selector,
        )))
    }
    fn list_plane_record_parents<'a>(&'a self, kind: &'a str) -> PlaneCall<'a, Vec<String>> {
        Box::pin(std::future::ready(
            SyncPlaneStore::list_plane_record_parents(self, kind),
        ))
    }
    fn purge_plane_records_before<'a>(&'a self, kind: &'a str, before: u64) -> PlaneCall<'a, u64> {
        Box::pin(std::future::ready(
            SyncPlaneStore::purge_plane_records_before(self, kind, before),
        ))
    }
    fn delete_plane_record<'a>(&'a self, kind: &'a str, id: &'a str) -> PlaneCall<'a, ()> {
        Box::pin(std::future::ready(SyncPlaneStore::delete_plane_record(
            self, kind, id,
        )))
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(std::future::ready(SyncPlaneStore::redeem_plane_token(
            self, kind, token, expires_at, now,
        )))
    }
    fn plane_token_live<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> PlaneCall<'a, bool> {
        Box::pin(std::future::ready(SyncPlaneStore::plane_token_live(
            self, kind, token, expires_at, now,
        )))
    }
}
