// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Qualified exporter images; each descriptor loan retains its actual product image.
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::sdk::door::RawDoorFn;
use std::path::PathBuf;
use std::sync::OnceLock;

macro_rules! image {
    ($module:ident, $variable:literal, $name:literal) => {
        pub(crate) mod $module {
            use super::*;
            pub(crate) const NAME: &str = $name;
            pub(crate) fn path() -> PathBuf {
                let path = std::env::var_os($variable)
                    .map(PathBuf::from)
                    .expect(concat!(
                        $variable,
                        " names the qualified actual exporter image"
                    ));
                assert!(
                    path.is_absolute() && path.is_file(),
                    "actual exporter: {}",
                    path.display()
                );
                path
            }
            pub(crate) extern "C" fn door() -> &'static Door {
                static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
                let image = IMAGE.get_or_init(|| {
                    let lib = crate::dlopen_on_worker(path().as_os_str())
                        .expect("load the actual exporter image");
                    // SAFETY: the qualified product exports its typed ABI symbol; IMAGE retains it.
                    let entry = unsafe {
                        *lib.get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                            .expect("actual exporter door")
                    };
                    (lib, entry)
                });
                let raw = crate::dispatch::load::enter_door(image.1);
                crate::dispatch::load::validate_door::<crate::dispatch::kinds::export::Export>(raw)
                    .expect("actual exporter descriptor validates");
                // SAFETY: the validated immutable descriptor lives in the retained IMAGE.
                let door = unsafe { &*raw };
                // SAFETY: validated descriptor names a live immutable Statement in IMAGE.
                let rendered = unsafe {
                    busbar_contract::abi::mechanism::rendering::render(&*door.statement())
                }
                .expect("actual exporter statement");
                let stated = busbar_contract::abi::mechanism::rendering::read(&rendered)
                    .expect("actual exporter rendering reads");
                assert_eq!(
                    stated.name, NAME,
                    "require the named actual exporter product"
                );
                door
            }
        }
    };
}
image!(
    prometheus,
    "BUSBAR_TEST_PROMETHEUS_CDYLIB",
    "busbar-export-prometheus"
);
image!(otlp, "BUSBAR_TEST_OTLP_CDYLIB", "busbar-export-otlp");
image!(
    webhook,
    "BUSBAR_TEST_EXPORT_WEBHOOK_CDYLIB",
    "busbar-export-webhook"
);

// The actual Prometheus product serves pull requests without connector I/O.
// Match its declared inbound need while refusing unexpected table operations.
pub(crate) mod prometheus_inbound {
    use std::sync::Arc;

    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    use busbar_contract::abi::mechanism::rendering::ReadNeed;
    use busbar_contract::conn::Ticket;
    use busbar_contract::conn::{
        ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    };
    use busbar_contract::transport::ConnFacts;

    /// This pull sink uses no connector I/O; the host still admits its declared HTTP listener.
    pub(crate) struct Inbound;

    impl Conns for Inbound {
        fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
            panic!("the scrape sink must not open an outbound connection")
        }
        fn write(
            &self,
            _: InstanceId,
            _: ConnId,
            _: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            panic!("the scrape sink must not write to a connector")
        }
        fn read(
            &self,
            _: InstanceId,
            _: ConnId,
            _: Ticket,
            _: &mut [u8],
        ) -> Result<Piece, ConnError> {
            panic!("the scrape sink must not read from a connector")
        }
        fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
            panic!("the scrape sink must not wait on a connector")
        }
        fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
            panic!("the scrape sink has no connector facts")
        }
        fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
            panic!("the scrape sink must not close a connector")
        }
    }

    impl DeclaredConns for Inbound {
        fn declare(
            &self,
            _: InstanceId,
            need: NeedId,
            spec: &ReadNeed,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(), ConnError> {
            assert_eq!(need, NeedId(0));
            assert_eq!(spec.direction, DIRECTION_INBOUND);
            assert_eq!(spec.transport, "http");
            assert_eq!(spec.target_from, "listen");
            assert!(
                spec.auth.is_empty(),
                "the operator's data auth chain supplies auth"
            );
            Ok(())
        }
        fn declared(&self, _: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            (need == NeedId(0)).then_some(Ok(()))
        }
        fn serves_scheme(&self, scheme: &str) -> bool {
            scheme == "http"
        }
    }

    pub(crate) fn table() -> Arc<dyn DeclaredConns> {
        Arc::new(Inbound)
    }
}
