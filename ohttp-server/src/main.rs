use bhttp::{Message, Mode};
use ohttp::{AeadId, KdfId, KemId, KeyConfig, Server as OhttpServer, SymmetricSuite};
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use warp::Filter;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt)]
#[structopt(name = "ohttp-server", about = "Server oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[structopt(default_value = "127.0.0.1:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indefinite-length form.
    #[structopt(long, short = "n")]
    indefinite: bool,

    /// Certificate to use for serving.
    #[structopt(long, short = "c", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.crt"))]
    certificate: PathBuf,

    /// Key for the certificate to use for serving.
    #[structopt(long, short = "k", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.key"))]
    key: PathBuf,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indefinite {
            Mode::IndefiniteLength
        } else {
            Mode::KnownLength
        }
    }
}

fn generate_reply(
    ohttp_ref: Arc<Mutex<OhttpServer>>,
    enc_request: &[u8],
    mode: Mode,
) -> Res<Vec<u8>> {
    let mut ohttp = ohttp_ref.lock().unwrap();
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let brequest = Message::read_bhttp(&mut BufReader::new(&request[..]))?;

    let mut bresponse = Message::response(200);
    bresponse.write_content(b"Received:\r\n---8<---\r\n");
    let mut tmp = Vec::new();
    brequest.write_http(&mut tmp)?;
    bresponse.write_content(&tmp);
    bresponse.write_content(b"--->8---\r\n");

    let mut response = Vec::new();
    bresponse.write_bhttp(mode, &mut response)?;
    let enc_response = server_response.encapsulate(&response)?;
    Ok(enc_response)
}

async fn serve(
    body: warp::hyper::body::Bytes,
    ohttp: Arc<Mutex<OhttpServer>>,
    mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    match generate_reply(ohttp, &body[..], mode) {
        Ok(resp) => Ok(warp::http::Response::builder().body(resp)),
        Err(e) => {
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                Ok(warp::http::Response::builder()
                    .status(422)
                    .body(Vec::from(format!("Error: {:?}", oe).as_bytes())))
            } else {
                Ok(warp::http::Response::builder()
                    .status(400)
                    .body(Vec::from(&b"Request error"[..])))
            }
        }
    }
}

fn with_ohttp(
    ohttp: Arc<Mutex<OhttpServer>>,
) -> impl Filter<Extract = (Arc<Mutex<OhttpServer>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&ohttp))
}

#[tokio::main]
async fn main() -> Res<()> {
    let args = Args::from_args();
    ::ohttp::init();

    let config = KeyConfig::new(
        0,
        KemId::HpkeDhKemX25519Sha256,
        vec![
            SymmetricSuite::new(KdfId::HpkeKdfHkdfSha256, AeadId::HpkeAeadAes128Gcm),
            SymmetricSuite::new(KdfId::HpkeKdfHkdfSha256, AeadId::HpkeAeadChaCha20Poly1305),
        ],
    )?;
    let ohttp = OhttpServer::new(config)?;
    println!("Config: {}", hex::encode(ohttp.config().encode()?));
    let mode = args.mode();

    let filter = warp::post()
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(with_ohttp(Arc::new(Mutex::new(ohttp))))
        .and(warp::any().map(move || mode))
        .and_then(serve);
    warp::serve(filter)
        .tls()
        .cert_path(args.certificate)
        .key_path(args.key)
        .run(args.address)
        .await;

    Ok(())
}
