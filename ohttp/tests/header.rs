#![cfg(all(feature = "client", feature = "server"))]

use std::sync::Once;

use ohttp::{
    ClientRequest, Error, KeyConfig, Server, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};

const REQUEST: &[u8] = b"buffered staged request";
const RESPONSE: &[u8] = b"buffered staged response";
const KDF: Kdf = Kdf::HkdfSha256;
const AEAD: Aead = Aead::Aes128Gcm;

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(ohttp::init);
}

fn suites() -> Vec<SymmetricSuite> {
    vec![SymmetricSuite::new(KDF, AEAD)]
}

fn make_server(key_id: u8, kem: Kem) -> Server {
    init();
    Server::new(KeyConfig::new(key_id, kem, suites()).expect("supported test configuration"))
        .expect("server configuration")
}

fn make_client(server: &Server) -> ClientRequest {
    let config = server
        .config()
        .encode()
        .expect("encoded server configuration");
    ClientRequest::from_encoded_config(&config).expect("client configuration")
}

fn raw_header(key_id: u8, kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 7] {
    let mut header = [0; 7];
    header[0] = key_id;
    header[1..3].copy_from_slice(&kem_id.to_be_bytes());
    header[3..5].copy_from_slice(&kdf_id.to_be_bytes());
    header[5..7].copy_from_slice(&aead_id.to_be_bytes());
    header
}

fn supported_header(key_id: u8) -> [u8; 7] {
    raw_header(
        key_id,
        u16::from(Kem::X25519Sha256),
        u16::from(KDF),
        u16::from(AEAD),
    )
}

#[test]
fn request_header_preserves_unknown_raw_identifiers() {
    let mut raw = raw_header(0xa5, 0xfffe, 0xfffd, 0xfffc);
    let staged = Server::decode_header(&raw).expect("complete fixed-size header");
    let copied_header = *staged.header();

    raw.fill(0);
    assert_eq!(copied_header.key_id(), 0xa5);
    assert_eq!(copied_header.kem_id(), 0xfffe);
    assert_eq!(copied_header.kdf_id(), 0xfffd);
    assert_eq!(copied_header.aead_id(), 0xfffc);

    let unknown_raw = raw_header(0xa5, 0xfffe, 0xfffd, 0xfffc);
    let staged = Server::decode_header(&unknown_raw).expect("complete fixed-size header");
    assert!(matches!(staged.enc(), Err(Error::Unsupported)));
}

#[test]
fn header_enc_lengths_do_not_require_backend_setup() {
    for (kem, expected_len) in [
        (Kem::X25519Sha256, 32),
        (Kem::P256Sha256, 65),
        (Kem::XWing, 1120),
    ] {
        let mut wire = raw_header(1, u16::from(kem), u16::from(KDF), u16::from(AEAD)).to_vec();
        wire.resize(wire.len() + expected_len, 0);
        let staged = Server::decode_header(&wire).expect("recognized fixed-size header");
        assert_eq!(
            staged.enc().expect("recognized KEM enc length").len(),
            expected_len
        );
    }
}

#[test]
fn decode_header_and_enc_require_complete_boundaries() {
    let header = supported_header(1);

    assert!(matches!(
        Server::decode_header(&header[..6]),
        Err(Error::Truncated)
    ));

    let staged = Server::decode_header(&header).expect("exact header is sufficient for inspection");
    assert_eq!(staged.header().key_id(), 1);
    assert!(matches!(staged.enc(), Err(Error::Truncated)));

    let mut one_byte_short = header.to_vec();
    one_byte_short.resize(header.len() + 31, 0);
    let staged =
        Server::decode_header(&one_byte_short).expect("complete header remains inspectable");
    assert!(matches!(staged.enc(), Err(Error::Truncated)));
    assert_eq!(staged.header().kem_id(), u16::from(Kem::X25519Sha256));

    one_byte_short.push(0);
    let staged =
        Server::decode_header(&one_byte_short).expect("complete header remains inspectable");
    assert_eq!(
        staged.enc().expect("complete encapsulated key"),
        &one_byte_short[7..]
    );
}

#[test]
fn header_selects_between_configurations_before_decapsulation() {
    let first_server = make_server(1, Kem::X25519Sha256);
    let second_server = make_server(2, Kem::X25519Sha256);
    let client = make_client(&second_server);
    let (wire, client_response) = client.encapsulate(REQUEST).expect("encapsulated request");

    let staged = Server::decode_header(&wire).expect("the dispatcher only needs the fixed header");
    let selected_server = match staged.header().key_id() {
        1 => &first_server,
        2 => &second_server,
        unexpected => panic!("unexpected key token: {unexpected}"),
    };
    let (request, server_response) = staged
        .decapsulate(selected_server)
        .expect("selected configuration decapsulates request");
    assert_eq!(request, REQUEST);

    let wire_response = server_response
        .encapsulate(RESPONSE)
        .expect("encapsulated response");
    assert_eq!(
        client_response
            .decapsulate(&wire_response)
            .expect("decapsulated response"),
        RESPONSE
    );
}

#[test]
fn staged_request_retains_header_and_enc_after_key_or_suite_failure() {
    let sender = make_server(1, Kem::X25519Sha256);
    let other_server = make_server(2, Kem::X25519Sha256);
    let client = make_client(&sender);
    let (wire, _) = client.encapsulate(REQUEST).expect("encapsulated request");

    let staged = Server::decode_header(&wire).expect("header inspection before key validation");
    let enc_len = staged.enc().expect("complete encapsulated key").len();
    assert!(matches!(
        staged.decapsulate(&other_server),
        Err(Error::KeyId)
    ));
    assert_eq!(staged.header().key_id(), 1);
    assert_eq!(
        staged.enc().expect("encapsulated key retained"),
        &wire[7..7 + enc_len]
    );

    let mut wrong_suite_wire = wire;
    wrong_suite_wire[3..5].copy_from_slice(&u16::from(Kdf::HkdfSha384).to_be_bytes());
    let staged = Server::decode_header(&wrong_suite_wire)
        .expect("recognized-but-unconfigured suite remains inspectable");
    assert!(matches!(
        staged.decapsulate(&sender),
        Err(Error::Unsupported)
    ));
    assert_eq!(staged.header().kdf_id(), u16::from(Kdf::HkdfSha384));
    assert_eq!(
        staged.enc().expect("encapsulated key retained"),
        &wrong_suite_wire[7..7 + enc_len]
    );
}

#[test]
fn selected_key_must_match_the_request_kem() {
    let server = make_server(1, Kem::X25519Sha256);
    let mut wire = raw_header(
        1,
        u16::from(Kem::P256Sha256),
        u16::from(KDF),
        u16::from(AEAD),
    )
    .to_vec();
    wire.resize(7 + 65, 0);
    let staged = Server::decode_header(&wire).expect("complete fixed header");
    assert_eq!(staged.enc().expect("complete P-256 enc").len(), 65);
    assert!(matches!(
        staged.decapsulate(&server),
        Err(Error::InvalidKem)
    ));
    assert_eq!(staged.header().kem_id(), u16::from(Kem::P256Sha256));
}

#[test]
fn staged_request_retains_header_and_enc_after_authentication_failure() {
    let server = make_server(1, Kem::X25519Sha256);
    let client = make_client(&server);
    let (mut wire, _) = client.encapsulate(REQUEST).expect("encapsulated request");
    let last = wire.len() - 1;
    wire[last] ^= 1;

    let staged = Server::decode_header(&wire).expect("complete header remains inspectable");
    let enc_len = staged.enc().expect("complete encapsulated key").len();
    assert!(staged.decapsulate(&server).is_err());
    assert_eq!(staged.header().key_id(), 1);
    assert_eq!(
        staged.enc().expect("encapsulated key retained"),
        &wire[7..7 + enc_len]
    );
}

#[cfg(feature = "rust-hpke")]
#[test]
fn staged_buffered_round_trips_supported_representative_kems() {
    for (key_id, kem, enc_len) in [(3, Kem::P256Sha256, 65), (4, Kem::XWing, 1120)] {
        let server = make_server(key_id, kem);
        let client = make_client(&server);
        let (wire, client_response) = client.encapsulate(REQUEST).expect("encapsulated request");

        let staged = Server::decode_header(&wire).expect("staged header");
        assert_eq!(
            staged.enc().expect("recognized KEM enc length").len(),
            enc_len
        );
        let (request, server_response) = staged.decapsulate(&server).expect("decapsulated request");
        assert_eq!(request, REQUEST);
        let wire_response = server_response
            .encapsulate(RESPONSE)
            .expect("encapsulated response");
        assert_eq!(
            client_response
                .decapsulate(&wire_response)
                .expect("decapsulated response"),
            RESPONSE
        );
    }
}
