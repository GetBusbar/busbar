// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[allow(unsafe_code)]
fn actual_ranking_door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::sdk::door::RawDoorFn;
    static IMAGE: std::sync::OnceLock<(libloading::Library, RawDoorFn)> =
        std::sync::OnceLock::new();
    let image = IMAGE.get_or_init(|| {
        let path = std::env::var_os("BUSBAR_TEST_RANKING_CDYLIB")
            .expect("the qualified actual Ranking image is required");
        // SAFETY: this is the same explicitly qualified product image used by Ranking's
        // ordinary host controls. The retained handle keeps every forwarded pointer live.
        let library = unsafe { libloading::Library::new(path) }.expect("actual Ranking loads");
        // SAFETY: the actual product exports the contract's raw door function.
        let entry = unsafe {
            *library
                .get::<RawDoorFn>(busbar_contract::abi::mechanism::DOOR_SYMBOL)
                .expect("actual Ranking exports its door")
        };
        (library, entry)
    });
    let pointer = (image.1)();
    assert!(!pointer.is_null(), "actual Ranking door is nonnull");
    // SAFETY: the qualified product exports its immutable full Door. The outer loader
    // still validates the restated descriptor before admitting either origin.
    let door: &Door = unsafe { &*pointer };
    assert_eq!(door.magic(), busbar_contract::abi::mechanism::DOOR_MAGIC);
    assert_eq!(door.size() as usize, std::mem::size_of::<Door>());
    assert_eq!(
        door.kind(),
        busbar_contract::abi::mechanism::KindCode::Hook as u32
    );
    door
}

// Metadata-only adversarial boundary: retain Ranking's actual image and every operation,
// changing only the declared route list. This is not a product SERVE implementation.
#[allow(unsafe_code)]
pub extern "C" fn door() -> &'static busbar_contract::abi::mechanism::door::Door {
    use busbar_contract::abi::hook::{Route as AbiRoute, Tail, ROUTE_AUTH_KEY};
    use busbar_contract::abi::mechanism::door::{Door, Statement};
    use busbar_contract::abi::sdk::door::abi_str;
    static DOOR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let address = *DOOR.get_or_init(|| {
        let actual = actual_ranking_door();
        // SAFETY: the qualified actual image is retained for the process lifetime.
        let statement = unsafe { &*actual.statement() };
        // SAFETY: the validated Hook descriptor has a full, aligned Hook tail.
        assert!(!statement.kind_tail.is_null());
        // SAFETY: the qualified product states a live Hook kind tail.
        assert!(unsafe { (*statement.kind_tail).size } as usize >= std::mem::size_of::<Tail>());
        // SAFETY: the nonnull actual Hook tail states at least the full shape copied here.
        let mut tail = unsafe { *(statement.kind_tail.cast::<Tail>()) };
        let route = Box::leak(Box::new(AbiRoute {
            path: abi_str("/hooks/ranking/metadata-boundary"),
            method: abi_str("POST"),
            auth: ROUTE_AUTH_KEY,
            _reserved: 0,
        }));
        tail.routes = route;
        tail.routes_len = 1;
        let tail = Box::leak(Box::new(tail));
        let stated = Box::leak(Box::new(Statement {
            kind_tail: std::ptr::from_ref(tail).cast(),
            ..*statement
        }));
        let mut parts = actual.parts();
        parts.statement = stated;
        // SAFETY: only the route metadata points at new static allocations. All operation
        // pointers and their original static metadata remain in the retained actual image.
        let restated = unsafe { Door::__from_parts(parts).__with_migrate(actual.migrate()) };
        Box::into_raw(Box::new(restated)) as usize
    });
    // SAFETY: the immutable descriptor is allocated once and retained permanently above.
    unsafe { &*(address as *const Door) }
}

#[cfg(not(test))]
busbar_contract::export_door!(door);
