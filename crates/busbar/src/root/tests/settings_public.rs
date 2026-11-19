// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::config::settings_public::PublicSettings as _;

#[test]
fn a_plugins_public_settings_are_found_under_its_words_alone() {
    let t = Table::default();
    let _ = t.native.set(vec![Row {
        words: vec!["stub-alias".into(), "stub-public".into()],
        public: ["url".to_string()].into_iter().collect(),
    }]);
    assert_eq!(
        t.public("stub-alias").into_iter().collect::<Vec<_>>(),
        ["url"]
    );
    assert_eq!(
        t.public("stub-public").into_iter().collect::<Vec<_>>(),
        ["url"]
    );
    assert!(
        t.public("elsewhere").is_empty(),
        "undeclared: every setting sensitive"
    );
}

/// A native MIN-3 plane for the public-settings table: its describe's D_SCHEMA marks `listen` public.
mod native_plane {
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::ChainBytes;
    use busbar_plugin_abi::plane::{PlaneReq, Target};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::Out;
    use busbar_plugin_abi::types::Bytes;
    use busbar_plugin_abi::Plane;

    pub const SCHEMA: &str = r#"{"type":"object","properties":{"listen":{"type":"string","x-busbar-public":true},"token":{"type":"string"}}}"#;

    pub struct Session;
    pub struct Fx;

    impl Plane for Fx {
        type Session = Session;
        fn request(
            &self,
            _h: &Host,
            _req: &PlaneReq<'_>,
            _body: Bytes<'_>,
            _out: &mut Out<'_>,
        ) -> Result<Session, Fail> {
            Err(Fail::unsupported())
        }
        fn upstream(
            &self,
            _h: &Host,
            _s: &mut Session,
            _target: &Target<'_>,
            _out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
        fn piece(
            &self,
            _h: &Host,
            _s: &mut Session,
            _from: u32,
            _exchange: u32,
            _flags: u32,
            _bytes: Bytes<'_>,
            _out: &mut Out<'_>,
        ) -> Result<(), Fail> {
            Ok(())
        }
        fn end(&self, _h: &Host, _s: Session, _out: &mut Out<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn probe(
            &self,
            _h: &Host,
            _target: &Target<'_>,
            _out: &mut Out<'_>,
        ) -> Result<Session, Fail> {
            Err(Fail::unsupported())
        }
    }

    impl Open for Fx {
        async fn open(_h: &'static Host, _config: ChainBytes) -> Result<Self, Fail> {
            Ok(Fx)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.schema(SCHEMA);
        }
    }

    busbar_plugin_abi::plugin!(Plane, Fx, former_names: "public-plane", name: "native-public-plane");
}

/// A native plane's `x-busbar-public` setting is public (its describe's D_SCHEMA, not a door Statement), under
/// its identity and its former names; an unmarked setting stays sensitive.
#[test]
fn a_native_planes_x_busbar_public_setting_is_public() {
    use busbar_plugin_loader::instance::{Ceilings, ImagesBuilder};
    let process = crate::root::min3_boot::fixture::resources().expect("test process resources");
    let mut builder = ImagesBuilder::new(
        &busbar_plugin_abi::host_side::host_vt::HOST,
        std::sync::Arc::clone(process.slots()),
        Ceilings::DEFAULT,
    );
    builder
        .admit(busbar_plugin_loader::admit::admit_linked(&native_plane::PLUGIN).expect("admitted"))
        .expect("described");
    let images = builder.finish();
    let t = Table::default();
    let _ = t.native.set(native_rows(&images).expect("the native rows"));
    for word in ["native-public-plane", "public-plane"] {
        assert_eq!(
            t.public(word).into_iter().collect::<Vec<_>>(),
            ["listen"],
            "{word}"
        );
    }
}
