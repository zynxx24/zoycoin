//! Zoycoin — backend transaksi modern: UTXO + secp256k1 + PoW + SQLite,
//! dengan fee market (prioritas fee-rate), blok berbatas, dan estimasi fee
//! ala Solana/BNB (cepat, gas murah).
//!
//! Jalankan: `cargo run --release`
//!
//! Env:
//! - `PORT`               port HTTP (default 8080)
//! - `DB_PATH`            path SQLite (default `zoycoin.db`)
//! - `DIFFICULTY`         difficulty awal, leading zero bit (default 8)
//! - `API_TOKEN`          bila diisi: semua non-GET + endpoint admin
//!                        wajib `Authorization: Bearer <token>`
//! - `RATE_LIMIT_PER_MIN` batas request per menit per IP (default 120)
//! - `AUTO_MINE`          `1` = miner otomatis tiap 5 detik (default mati)
//! - `DEMO_WALLET`        `1` = cetak wallet demo di log (default mati)
//! - `BIND_ALL`           `1` = bind ke 0.0.0.0 (default 127.0.0.1).
//!                        WAJIB disertai `API_TOKEN`, kalau tidak proses
//!                        menolak start (fail-closed).
//! - `TRUST_PROXY`        `1` = percayai `X-Forwarded-For` (hanya di
//!                        belakang reverse proxy tepercaya)

mod api;
mod block;
mod chain;
mod crypto;
mod market;
mod mempool;
mod security;
mod stats;
mod store;
mod transaction;
mod web3;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use chain::Chain;
use security::SecurityConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let difficulty: u32 = std::env::var("DIFFICULTY")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(8);

    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "zoycoin.db".to_string());
    let store = store::Store::open(&db_path)
        .map_err(|e| format!("gagal membuka database {db_path}: {e}"))?;

    let mut chain = match store
        .load()
        .map_err(|e| format!("gagal load chain dari {db_path}: {e}"))?
    {
        Some((blocks, utxos, mempool)) => {
            info!(blocks = blocks.len(), "chain dimuat dari SQLite");
            Chain::from_parts(blocks, utxos, mempool, difficulty)
        }
        None => {
            info!("database kosong — chain baru dibuat");
            Chain::new(difficulty)
        }
    };
    chain.attach_store(store);

    let chain = Arc::new(Mutex::new(chain));

    // --- konfigurasi keamanan ---
    let api_token = std::env::var("API_TOKEN").ok();
    let rate_limit: u32 = std::env::var("RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(security::DEFAULT_RATE_LIMIT_PER_MIN);

    let mut sec = SecurityConfig::new(api_token, rate_limit);

    // Percayai X-Forwarded-For hanya bila operator menyatakannya eksplisit.
    sec.trust_proxy = std::env::var("TRUST_PROXY").ok().as_deref() == Some("1");

    // Disimpan terpisah: `sec` dipindah ke router, tapi status ini masih
    // dibutuhkan saat memutuskan alamat bind (fail-closed).
    let auth_enabled = sec.auth_enabled();

    if auth_enabled {
        info!("auth token AKTIF — non-GET & endpoint admin butuh Bearer token");
    } else {
        warn!(
            "API_TOKEN tidak diset — endpoint admin (mine, wallets, verify, stats) TERBUKA. \
             Server hanya bind ke loopback; set API_TOKEN sebelum BIND_ALL=1."
        );
    }
    if sec.trust_proxy {
        info!("TRUST_PROXY aktif — X-Forwarded-For dipakai sebagai IP klien");
    }
    info!(
        rate_limit_per_min = rate_limit,
        max_body_kb = security::MAX_BODY_BYTES / 1024,
        min_relay_fee_rate = market::MIN_FEE_RATE,
        max_block_txs = market::MAX_BLOCK_TXS,
        min_fee_rate = market::MIN_FEE_RATE,
        "kebijakan keamanan & fee market aktif"
    );

    // --- miner otomatis (opsional) ---
    if std::env::var("AUTO_MINE").ok().as_deref() == Some("1") {
        let miner = crypto::KeyPair::random();
        let address = miner.address();
        info!(miner = %address, "auto-miner aktif (blok tiap 5 detik)");

        let state = Arc::clone(&chain);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let mut guard = state.lock().await;
                match guard.mine_block(&address) {
                    Ok(block) => info!(
                        height = guard.height() - 1,
                        txs = block.transactions.len(),
                        hash = %block.hash,
                        "blok baru ditambang"
                    ),
                    Err(e) => warn!(error = %e, "auto-mine gagal"),
                }
            }
        });
    }

    // Bootstrap wallet demo: default mati agar secret tidak bocor ke log.
    if std::env::var("DEMO_WALLET").ok().as_deref() == Some("1") {
        let demo = crypto::KeyPair::random();
        info!(address = %demo.address(), "wallet demo dibuat");
        warn!(secret = %demo.secret_hex(), "secret demo (JANGAN dipakai di produksi)");
    }
    // --- penentuan alamat bind (fail-closed) ---
    // Default loopback: node tidak sengaja terekspos ke LAN/publik.
    // `sec` sudah dipindah ke router, jadi status auth diambil lebih awal.
    let bind_all = std::env::var("BIND_ALL").ok().as_deref() == Some("1");
    let host = if bind_all { "0.0.0.0" } else { "127.0.0.1" };

    if bind_all && !auth_enabled {
        return Err(
            "menolak bind ke 0.0.0.0 tanpa API_TOKEN: endpoint admin \
             (mine, wallets, verify, stats) akan terbuka untuk siapa pun. \
             Set API_TOKEN, atau jalankan tanpa BIND_ALL untuk mode lokal."
                .into(),
        );
    }

    // Web3 auth: nonce sekali-pakai + sesi bearer ber-TTL.
    let web3_auth = web3::Web3Auth::new();
    info!(
        nonce_ttl_secs = web3::NONCE_TTL.as_secs(),
        session_ttl_secs = web3::SESSION_TTL.as_secs(),
        "web3 auth aktif (signature login)"
    );

    let app = api::router(Arc::clone(&chain), sec, web3_auth);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    if bind_all {
        info!("server berjalan di http://{addr} (TEREKSPOS ke jaringan, auth AKTIF)");
    } else {
        info!("server berjalan di http://{addr} (loopback saja)");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("mematikan server...");
}
