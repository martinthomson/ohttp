#![deny(warnings, clippy::pedantic)]

use std::{
    io::Cursor, net::SocketAddr, path::PathBuf, sync::Arc
};

use tokio::sync::Mutex;

use bhttp::{Message, Mode, StatusCode};
use ohttp::{
    hpke::{Aead, Kdf, Kem},
    KeyConfig, Server as OhttpServer, SymmetricSuite,
};
use structopt::StructOpt;
use warp::Filter;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, StructOpt)]
#[structopt(name = "ohttp-server", about = "Serve oblivious HTTP requests.")]
struct Args {
    /// The address to bind to.
    #[structopt(default_value = "127.0.0.1:9443")]
    address: SocketAddr,

    /// When creating message/bhttp, use the indeterminate-length form.
    #[structopt(long, short = "n", alias = "indefinite")]
    indeterminate: bool,

    /// Certificate to use for serving.
    #[structopt(long, short = "c", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.crt"))]
    certificate: PathBuf,

    /// Key for the certificate to use for serving.
    #[structopt(long, short = "k", default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/server.key"))]
    key: PathBuf,

    /// Target server 
    #[structopt(default_value = "142.250.180.14:80")]
    target: SocketAddr,
}

impl Args {
    fn mode(&self) -> Mode {
        if self.indeterminate {
            Mode::IndeterminateLength
        } else {
            Mode::KnownLength
        }
    }
}

async fn generate_reply(
    ohttp_ref: &Arc<Mutex<OhttpServer>>,
    enc_request: &[u8],
    target: SocketAddr,
    mode: Mode,
) -> Res<Vec<u8>> {
    let ohttp = ohttp_ref.lock().await;
    let (request, server_response) = ohttp.decapsulate(enc_request)?;
    let _bin_request = Message::read_bhttp(&mut Cursor::new(&request[..]))?;

    let client = reqwest::ClientBuilder::new().build()?;
    let body: Vec<u8> = _bin_request.content().to_vec();

    let response = client
        .get(target.to_string())
        .body(body)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let mut bin_response = Message::response(StatusCode::OK);
    bin_response.write_content(response);

    let mut response = Vec::new();
    bin_response.write_bhttp(mode, &mut response)?;
    let enc_response = server_response.encapsulate(&response)?;
    Ok(enc_response)
}

#[allow(clippy::unused_async)]
async fn score(
    body: warp::hyper::body::Bytes,
    ohttp: Arc<Mutex<OhttpServer>>,
    target: SocketAddr,
    mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    match generate_reply(&ohttp, &body[..], target, mode).await {
        Ok(resp) => Ok(warp::http::Response::builder()
            .header("Content-Type", "message/ohttp-res")
            .body(resp)),
        Err(e) => {
            println!("400 {}", e.to_string());
            if let Ok(oe) = e.downcast::<::ohttp::Error>() {
                Ok(warp::http::Response::builder()
                    .status(422)
                    .body(Vec::from(format!("Error: {oe:?}").as_bytes())))
            } else {
                Ok(warp::http::Response::builder()
                    .status(400)
                    .body(Vec::from(&b"Request error"[..])))
            }
        }
    }
}

#[allow(clippy::unused_async)]
async fn discover(
    config: String,
    _mode: Mode,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    Ok(warp::http::Response::builder()
        .status(200)
        .body(Vec::from(config)))
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
    env_logger::try_init().unwrap();

    let config = KeyConfig::new(
        0,
        Kem::X25519Sha256,
        vec![
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
            SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
        ],
    )?;
    let ohttp = OhttpServer::new(config)?;
    let config = hex::encode(KeyConfig::encode_list(&[ohttp.config()])?);

    println!("Config: {}", config);
    let mode = args.mode();
    let target = args.target;

    let score = warp::post()
        .and(warp::path::path("score"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(with_ohttp(Arc::new(Mutex::new(ohttp))))
        .and(warp::any().map(move || target))
        .and(warp::any().map(move || mode))
        .and_then(score);

    let discover = warp::get()
        .and(warp::path("discover"))
        .and(warp::path::end())
        .and(warp::any().map(move || config.clone()))
        .and(warp::any().map(move || mode))
        .and_then(discover);

    let routes = score.or(discover);

    warp::serve(routes)
        .tls()
        .cert_path(args.certificate)
        .key_path(args.key)
        .run(args.address)
        .await;

    Ok(())
}
