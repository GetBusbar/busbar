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
