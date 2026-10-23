use super::{exempt_hit, mask_loader, CONNECTOR_PACKAGE, LOADER_PACKAGE};

const LOADER_DIR: &str = "crates/plugin-loader";
const CONNECTOR_DIR: &str = "crates/busbar-core-connector";

#[test]
fn a_bare_carrier_is_exempt_in_the_connector_and_the_loaders_need_service_files() {
    for word in ["tcp", "stdio"] {
        assert!(exempt_hit(
            CONNECTOR_PACKAGE,
            CONNECTOR_DIR,
            "crates/busbar-core-connector/src/socket.rs",
            "transport",
            word
        ));
        for file in ["src/tcp_conns.rs", "src/dispatch/conn_services.rs"] {
            assert!(exempt_hit(
                LOADER_PACKAGE,
                LOADER_DIR,
                &format!("{LOADER_DIR}/{file}"),
                "transport",
                word
            ));
        }
    }
}

#[test]
fn a_package_name_a_framer_another_file_or_another_crate_still_counts() {
    let socket = "crates/busbar-core-connector/src/socket.rs";
    for word in [
        "busbar-transport-tcp",
        "transport-stdio",
        "http",
        "ws",
        "grpc",
    ] {
        assert!(!exempt_hit(
            CONNECTOR_PACKAGE,
            CONNECTOR_DIR,
            socket,
            "transport",
            word
        ));
    }
    assert!(!exempt_hit(
        CONNECTOR_PACKAGE,
        CONNECTOR_DIR,
        socket,
        "plane",
        "tcp"
    ));
    assert!(!exempt_hit(
        LOADER_PACKAGE,
        LOADER_DIR,
        "crates/plugin-loader/src/registry.rs",
        "transport",
        "tcp"
    ));
    assert!(!exempt_hit(
        LOADER_PACKAGE,
        LOADER_DIR,
        "crates/plugin-loader/src/tests/tcp_conns.rs",
        "transport",
        "tcp"
    ));
    assert!(!exempt_hit(
        "busbar-kernel",
        "crates/busbar-kernel",
        "crates/busbar-kernel/src/tcp_conns.rs",
        "transport",
        "tcp"
    ));
}

#[test]
fn the_loader_masks_the_need_service_name_and_a_needs_carrier_literal_only() {
    let text =
        "use crate::tcp_conns::TcpConns;\nconst TCP: [Need; 1] = [need(abi_str(\"tcp\"))];\n\
                \"transport\": \"stdio\",\nstatic T: TCP_CONNS = 0;\n";
    let masked = mask_loader(text).expect("the loader-wide positions are masked");
    assert_eq!(masked.len(), text.len());
    assert_eq!(
        masked,
        "use crate::xxx_conns::xxxConns;\nconst TCP: [Need; 1] = [need(abi_str(\"xxx\"))];\n\
         \"transport\": \"xxxxx\",\nstatic T: xxx_CONNS = 0;\n"
    );
}

#[test]
fn every_other_carrier_word_in_the_loader_still_counts() {
    for text in [
        "pub fn tcp_route() {}",
        "// dials over tcp.",
        "const TCP_DOOR: u8 = 0;",
        "fn connects_over_tcp() {}",
        "let s = \"tcp://host\";",
        "let s = \"a tcp need\";",
        "struct MyTcpConns;",
        "mod tcpconns;",
        "use busbar_transport_tcp::Dial;",
    ] {
        assert_eq!(
            mask_loader(text),
            None,
            "`{text}` is left as written, so it counts"
        );
    }
}
