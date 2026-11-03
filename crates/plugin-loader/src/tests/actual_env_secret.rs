// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual environment-secret product image, held for the lifetime of its descriptor loans.

use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::sdk::door::RawDoorFn;
use std::path::PathBuf;
use std::sync::OnceLock;

pub(crate) fn cdylib() -> PathBuf {
    let path = std::env::var_os("BUSBAR_TEST_SECRET_ENV_CDYLIB")
        .map(PathBuf::from)
        .expect("BUSBAR_TEST_SECRET_ENV_CDYLIB names the actual qualified MCP product image");
    assert!(
        path.is_absolute() && path.is_file(),
        "actual environment-secret image: {}",
        path.display()
    );
    path
}

pub(crate) extern "C" fn door() -> &'static Door {
    static IMAGE: OnceLock<(libloading::Library, RawDoorFn)> = OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let library = crate::dlopen_on_worker(cdylib().as_os_str())
            .expect("load actual environment-secret image on the plugin thread");
        // SAFETY: the actual product exports the typed mechanism symbol, and IMAGE
        // retains its mapping through every crossing and descriptor loan.
        let entry = unsafe {
            *library
                .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("actual environment-secret door export")
        };
        (library, entry)
    });
    let door = crate::dispatch::load::enter_door(image.1);
    crate::dispatch::load::validate_door::<crate::dispatch::kinds::secret::Secret>(door)
        .expect("actual environment-secret plane descriptor validates");
    // SAFETY: the immutable descriptor validated above lives in IMAGE's retained mapping.
    let door = unsafe { &*door };
    // SAFETY: descriptor validation established this live immutable Statement.
    let stated = unsafe { busbar_contract::abi::mechanism::rendering::render(&*door.statement()) }
        .expect("actual environment-secret statement renders");
    let name = busbar_contract::abi::mechanism::rendering::read(&stated)
        .unwrap()
        .name;
    assert_eq!(
        name, "busbar-secret-env",
        "require the actual environment-secret product"
    );
    door
}

pub(crate) const NAME: &str = "busbar-secret-env";
