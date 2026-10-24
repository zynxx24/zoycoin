//! Handler HTTP. State dibungkus `Arc<Mutex<Chain>>` agar aman antar task.
//!
//! Setiap request melewati lapisan keamanan (`security::guard`):
//! rate limit -> auth token -> validasi input -> konsensus.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::chain::{build_transfer, Chain, ChainError};
use crate::crypto::{self, KeyPair};
use crate::market;
use crate::security::{self, SecurityConfig};
use crate::transaction::{validate_transaction, OutPoint, Transaction};
use crate::web3::{self, Web3Auth};

pub type AppState = Arc<Mutex<Chain>>;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.into())
    }

    fn unprocessable(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
    }

    fn not_found(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::NOT_FOUND, msg.into())
    }
}

impl From<ChainError> for ApiError {
    fn from(err: ChainError) -> Self {
        // Detail internal (path SQLite, pesan driver) hanya masuk log server.
        // Klien menerima pesan generik agar struktur sistem tidak bocor.
        match err {
            ChainError::InvalidAddress(msg) => ApiError(StatusCode::BAD_REQUEST, msg),
            ChainError::Validation(msg) => ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg),
            ChainError::Internal(detail) => {
                tracing::error!(error = %detail, "kesalahan internal chain");
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "kesalahan internal server".to_string(),
                )
            }
        }
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ---------------------------------------------------------------------------
// DTO
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WalletCreateReq {
    /// Opsional: turunkan wallet dari secret hex 32 byte.
    #[serde(default)]
    pub secret_hex: Option<String>,
    /// Opsional: label bebas untuk wallet (disanitasi sebelum disimpan).
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct WalletResp {
    pub address: String,
    pub public_key: String,
    pub secret_hex: String,
}

#[derive(Deserialize)]
pub struct TransferReq {
    pub secret_hex: String,
    pub to: String,
    pub amount: u64,
    /// 0 = pakai estimasi fee otomatis dari mempool.
    #[serde(default)]
    pub fee: u64,
}

#[derive(Serialize)]
pub struct TransferResp {
    pub txid: String,
    pub fee: u64,
    pub fee_rate: u64,
    pub raw: Transaction,
}

#[derive(Deserialize)]
pub struct MineReq {
    pub miner_address: String,
}

#[derive(Serialize)]
pub struct MineResp {
    pub height: u64,
    pub hash: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub tx_count: usize,
}

#[derive(Deserialize)]
pub struct BatchTxReq {
    pub txs: Vec<Transaction>,
}

#[derive(Deserialize)]
pub struct LimitQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

impl LimitQuery {
    fn resolve(&self, default: usize, max: usize) -> usize {
        self.limit.unwrap_or(default).clamp(1, max)
    }
}

#[derive(Deserialize)]
pub struct FeeQuery {
    #[serde(default)]
    pub target_blocks: Option<u64>,
}

// ---------------------------------------------------------------------------
// Web3 DTO
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeReq {
    pub address: String,
}

#[derive(Serialize)]
pub struct ChallengeResp {
    pub address: String,
    pub nonce: String,
    /// Pesan persis yang harus ditandatangani klien.
    pub message: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub address: String,
    pub signature: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct VerifyResp {
    pub address: String,
    pub token: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct RevokeReq {
    pub token: String,
}

// ---------------------------------------------------------------------------
// Web3 handlers
// ---------------------------------------------------------------------------

fn web3_err(e: web3::Web3Error) -> ApiError {
    use web3::Web3Error::*;
    match e {
        InvalidAddress => ApiError(StatusCode::BAD_REQUEST, e.to_string()),
        NoChallenge | Expired | BadSignature => {
            // Pesan seragam: jangan bocorkan apakah nonce ada / signature salah.
            ApiError(StatusCode::UNAUTHORIZED, "autentikasi gagal".to_string())
        }
        Capacity => ApiError(StatusCode::TOO_MANY_REQUESTS, e.to_string()),
    }
}

/// Terbitkan challenge nonce untuk address.
async fn web3_challenge(
    State(auth): State<Web3Auth>,
    Json(req): Json<ChallengeReq>,
) -> ApiResult<ChallengeResp> {
    let (nonce, expires_in) = auth.issue_challenge(&req.address).map_err(web3_err)?;
    let message = web3::canonical_message(&req.address, &nonce);
    Ok(Json(ChallengeResp {
        address: req.address,
        nonce,
        message,
        expires_in,
    }))
}

/// Verifikasi signature atas challenge, terbitkan sesi bearer.
async fn web3_verify(
    State(auth): State<Web3Auth>,
    Json(req): Json<VerifyReq>,
) -> ApiResult<VerifyResp> {
    let (token, expires_in) = auth
        .verify_and_issue(&req.address, &req.signature, &req.public_key)
        .map_err(web3_err)?;
    Ok(Json(VerifyResp {
        address: req.address,
        token,
        expires_in,
    }))
}

/// Cek status sesi berdasarkan header `Authorization: Bearer <token>`.
async fn web3_session(
    State(auth): State<Web3Auth>,
    headers: axum::http::HeaderMap,
) -> ApiResult<Value> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();

    match auth.session_address(token) {
        Some(addr) => Ok(Json(json!({ "authenticated": true, "address": addr }))),
        None => Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "sesi tidak valid atau kedaluwarsa".to_string(),
        )),
    }
}

/// Cabut sesi (logout).
async fn web3_revoke(
    State(auth): State<Web3Auth>,
    Json(req): Json<RevokeReq>,
) -> ApiResult<Value> {
    let revoked = auth.revoke(&req.token);
    Ok(Json(json!({ "revoked": revoked })))
}

/// Observability: jumlah nonce & sesi aktif.
async fn web3_stats(State(auth): State<Web3Auth>) -> ApiResult<Value> {
    let (nonces, sessions) = auth.stats();
    Ok(Json(json!({
        "pending_nonces": nonces,
        "active_sessions": sessions,
        "nonce_ttl_secs": web3::NONCE_TTL.as_secs(),
        "session_ttl_secs": web3::SESSION_TTL.as_secs(),
    })))
}

/// Sub-router Web3 dengan state sendiri (Web3Auth), digabung ke router utama.
pub fn web3_router(auth: Web3Auth) -> Router {
    Router::new()
        .route("/web3/challenge", post(web3_challenge))
        .route("/web3/verify", post(web3_verify))
        .route("/web3/session", get(web3_session))
        .route("/web3/revoke", post(web3_revoke))
        .route("/web3/stats", get(web3_stats))
        .with_state(auth)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: AppState, sec: SecurityConfig, web3_auth: Web3Auth) -> Router {
    Router::new()
        // --- meta & statistik ---
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/stats", get(stats))
        .route("/supply", get(supply))
        .route("/richlist", get(rich_list))
        // --- fee market ---
        .route("/fee/estimate", get(fee_estimate))
        .route("/fee/histogram", get(fee_histogram))
        .route("/block/template", get(block_template))
        // --- wallet ---
        .route("/wallet", post(create_wallet))
        .route("/wallets", get(list_wallets))
        // --- address ---
        .route("/balance/:address", get(balance))
        .route("/utxos/:address", get(utxos))
        .route("/address/:address/history", get(address_history))
        // --- transaksi ---
        .route("/tx", post(submit_tx))
        .route("/tx/batch", post(submit_batch))
        .route("/tx/decode", post(decode_tx))
        .route("/tx/:txid", get(get_tx))
        .route("/transfer", post(transfer))
        // --- mempool ---
        .route("/mempool", get(mempool))
        .route("/mempool/:txid", get(mempool_tx))
        // --- mining & blok ---
        .route("/mine", post(mine))
        .route("/block/:height", get(get_block))
        .route("/block/hash/:hash", get(get_block_by_hash))
        .route("/blocks", get(list_blocks))
        .route("/verify", get(verify))
        // Batas ukuran body: menolak payload raksasa sebelum di-deserialize.
        .layer(DefaultBodyLimit::max(security::MAX_BODY_BYTES))
        // Rate limit + auth token + security header.
        .layer(middleware::from_fn_with_state(sec, security::guard))
        .with_state(state)
        // Web3 auth router punya state sendiri (Web3Auth) dan sudah
        // `with_state`-ed menjadi Router<()>, jadi digabung SETELAH
        // router utama di-`with_state`. Merge sebelum with_state akan
        // gagal: Router<()> tidak bisa jadi Router<AppState>.
        .merge(web3_router(web3_auth))
}

// ---------------------------------------------------------------------------
// Meta & statistik
// ---------------------------------------------------------------------------

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "block_time_target_secs": 5,
        "max_block_txs": market::MAX_BLOCK_TXS,
        "min_fee_rate": market::MIN_FEE_RATE,
    }))
}

async fn info(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    Ok(Json(json!(chain.info())))
}

/// Statistik agregat: supply, hashrate, waktu blok, saran fee, mempool.
async fn stats(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    let mut stats = chain.stats();
    if let Value::Object(ref mut map) = stats {
        map.insert("mempool".into(), chain.mempool_stats());
        map.insert("block_template".into(), chain.block_template());
        map.insert("fee_histogram".into(), chain.fee_histogram());
    }
    Ok(Json(stats))
}

/// Supply beredar + jadwal halving berikutnya.
async fn supply(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    let height = chain.height();
    let total = chain.total_supply();
    Ok(Json(json!({
        "height": height,
        "total_supply": total,
        "max_supply": security::MAX_MONEY,
        "supply_pct": (total as f64 / security::MAX_MONEY as f64) * 100.0,
        "block_reward": chain.block_reward(height),
        "next_halving_height": ((height / 210_000) + 1) * 210_000,
        "utxo_count": chain.utxos.len(),
    })))
}

/// Top holder (mirip "top accounts" di BNB Chain).
async fn rich_list(
    State(state): State<AppState>,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Value> {
    let limit = q.resolve(20, 200);
    let chain = state.lock().await;
    let list = chain.rich_list(limit);
    Ok(Json(json!({
        "count": list.len(),
        "total_supply": chain.total_supply(),
        "accounts": list,
    })))
}

// ---------------------------------------------------------------------------
// Fee market
// ---------------------------------------------------------------------------

/// Estimasi fee-rate (per 1000 byte) untuk target N blok.
async fn fee_estimate(
    State(state): State<AppState>,
    Query(q): Query<FeeQuery>,
) -> ApiResult<Value> {
    let target = q.target_blocks.unwrap_or(1).clamp(1, 100);
    let chain = state.lock().await;
    Ok(Json(json!({
        "target_blocks": target,
        "fee_rate": chain.estimate_fee(target),
        "min_fee_rate": market::MIN_FEE_RATE,
        "mempool": chain.mempool_stats(),
    })))
}

async fn fee_histogram(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    Ok(Json(chain.fee_histogram()))
}

/// Preview isi blok berikutnya (fee tertinggi lebih dulu).
async fn block_template(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    Ok(Json(chain.block_template()))
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

async fn create_wallet(
    State(state): State<AppState>,
    Json(req): Json<WalletCreateReq>,
) -> ApiResult<WalletResp> {
    let kp = match req.secret_hex {
        Some(secret) => {
            let secret = secret.trim().to_string();
            if secret.is_empty() || secret.len() > security::MAX_HEX_FIELD {
                return Err(ApiError::bad_request("secret_hex tidak valid"));
            }
            KeyPair::from_secret_hex(&secret).map_err(ApiError::bad_request)?
        }
        None => KeyPair::random(),
    };

    let label = req.label.as_deref().and_then(security::sanitize_label);
    {
        let chain = state.lock().await;
        chain.save_wallet(&kp.address(), &kp.secret_hex(), label.as_deref());
    }

    Ok(Json(WalletResp {
        address: kp.address(),
        public_key: kp.public_key_hex(),
        secret_hex: kp.secret_hex(),
    }))
}

/// Daftar wallet tersimpan di SQLite. Endpoint admin.
async fn list_wallets(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    let wallets = chain.list_wallets()?;
    Ok(Json(json!({ "count": wallets.len(), "wallets": wallets })))
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

async fn balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> ApiResult<Value> {
    if !crypto::is_valid_address(&address) {
        return Err(ApiError::bad_request("address tidak valid"));
    }
    let chain = state.lock().await;
    Ok(Json(json!({
        "address": address,
        "balance": chain.balance(&address),
        "utxo_count": chain.get_utxos_for_address(&address).len(),
    })))
}

async fn utxos(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> ApiResult<Value> {
    if !crypto::is_valid_address(&address) {
        return Err(ApiError::bad_request("address tidak valid"));
    }
    let chain = state.lock().await;
    let list: Vec<Value> = chain
        .get_utxos_for_address(&address)
        .into_iter()
        .map(|(op, u)| {
            json!({
                "txid": op.txid,
                "vout": op.vout,
                "value": u.value,
                "coinbase": u.coinbase,
                "height": u.height,
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

async fn address_history(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Value> {
    if !crypto::is_valid_address(&address) {
        return Err(ApiError::bad_request("address tidak valid"));
    }
    let limit = q.resolve(50, 200);
    let chain = state.lock().await;
    let history = chain.address_history(&address, limit);
    Ok(Json(json!({
        "address": address,
        "balance": chain.balance(&address),
        "count": history.len(),
        "history": history,
    })))
}

// ---------------------------------------------------------------------------
// Transaksi
// ---------------------------------------------------------------------------

async fn submit_tx(
    State(state): State<AppState>,
    Json(tx): Json<Transaction>,
) -> ApiResult<Value> {
    // 1. Validasi struktural (murah, tanpa state).
    security::validate_tx_shape(&tx).map_err(ApiError::unprocessable)?;

    let mut chain = state.lock().await;

    // 2. Policy node: batas mempool + minimum relay fee.
    let fee = security::relay_check(&chain, &tx).map_err(ApiError::unprocessable)?;
    let fee_rate = market::fee_rate(&chain.utxos, &tx);
    let txid = tx.txid();

    let size_bytes = market::tx_size(&tx);

    // 3. Konsensus penuh (signature, maturity, double-spend).
    chain.submit_transaction(tx)?;

    Ok(Json(json!({
        "txid": txid,
        "status": "accepted",
        "fee": fee,
        "fee_rate": fee_rate,
        "size_bytes": size_bytes,
    })))
}

/// Kirim banyak transaksi sekaligus. Tiap tx dievaluasi independen:
/// yang gagal tidak membatalkan yang lain (partial success).
async fn submit_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchTxReq>,
) -> ApiResult<Value> {
    if req.txs.is_empty() {
        return Err(ApiError::bad_request("tidak ada transaksi dalam batch"));
    }
    if req.txs.len() > security::MAX_BATCH_TXS {
        return Err(ApiError::bad_request(format!(
            "batch terlalu besar: {} (maks {})",
            req.txs.len(),
            security::MAX_BATCH_TXS
        )));
    }

    let mut chain = state.lock().await;
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<Value> = Vec::new();

    for (index, tx) in req.txs.into_iter().enumerate() {
        if let Err(err) = security::validate_tx_shape(&tx) {
            rejected.push(json!({ "index": index, "error": err }));
            continue;
        }
        if let Err(err) = security::relay_check(&chain, &tx) {
            rejected.push(json!({ "index": index, "error": err }));
            continue;
        }
        match chain.submit_transaction(tx) {
            Ok(txid) => accepted.push(txid),
            Err(err) => rejected.push(json!({ "index": index, "error": err.to_string() })),
        }
    }

    Ok(Json(json!({
        "accepted_count": accepted.len(),
        "rejected_count": rejected.len(),
        "accepted": accepted,
        "rejected": rejected,
    })))
}

/// Dry-run: periksa transaksi tanpa memasukkannya ke mempool.
/// Dipakai wallet sebelum broadcast supaya tidak membuang fee.
async fn decode_tx(
    State(state): State<AppState>,
    Json(tx): Json<Transaction>,
) -> ApiResult<Value> {
    let chain = state.lock().await;
    let txid = tx.txid();
    let shape_err = security::validate_tx_shape(&tx).err();

    // Double-spend terhadap mempool ikut dihitung, bukan hanya UTXO set.
    let mut spent: HashSet<OutPoint> = HashSet::new();
    for pending in chain.mempool.iter() {
        for input in &pending.inputs {
            spent.insert(OutPoint::new(&input.prev_txid, input.prev_vout));
        }
    }

    let verdict = validate_transaction(&tx, &chain.utxos, &spent, chain.height());

    let (valid, fee, error) = match (&shape_err, &verdict) {
        (Some(e), _) => (false, None, Some(e.clone())),
        (None, Err(e)) => (false, None, Some(e.to_string())),
        (None, Ok(f)) => (true, Some(*f), None),
    };

    // `valid` hanya berarti "lolos konsensus". Sebuah tx bisa valid secara
    // konsensus tapi tetap tidak akan pernah diterima `POST /tx` karena
    // kebijakan relay (mempool penuh, fee-rate di bawah minimum, bentuk
    // coinbase). Laporkan itu terpisah supaya wallet tidak membuang fee
    // pada tx yang dry-run-nya "valid" tapi pasti ditolak.
    let relay_verdict = if valid {
        security::relay_check(&chain, &tx).err()
    } else {
        Some("tx tidak valid secara konsensus".to_string())
    };

    let fee_rate = fee.map(|_| market::fee_rate(&chain.utxos, &tx));

    Ok(Json(json!({
        "txid": txid,
        "valid": valid,
        "relayable": valid && relay_verdict.is_none(),
        "relay_error": relay_verdict,
        "fee": fee,
        "fee_rate": fee_rate,
        "size_bytes": market::tx_size(&tx),
        "meets_min_fee_rate": fee_rate.map(|r| r >= market::MIN_FEE_RATE),
        "error": error,
        "input_count": tx.inputs.len(),
        "output_count": tx.outputs.len(),
        "total_output": tx.total_output().ok(),
        "is_coinbase": tx.is_coinbase(),
    })))
}

/// Bangun + tanda-tangani + kirim transfer dalam satu langkah.
/// `fee: 0` berarti pakai estimasi fee market saat ini.
async fn transfer(
    State(state): State<AppState>,
    Json(req): Json<TransferReq>,
) -> ApiResult<TransferResp> {
    // --- validasi input (fail fast, sebelum menyentuh state) ---
    if req.amount == 0 {
        return Err(ApiError::bad_request("amount harus lebih dari 0"));
    }
    if req.amount > security::MAX_MONEY {
        return Err(ApiError::bad_request("amount melebihi batas supply"));
    }
    if !crypto::is_valid_address(&req.to) {
        return Err(ApiError::bad_request("address tujuan tidak valid"));
    }
    if req.secret_hex.len() > security::MAX_HEX_FIELD {
        return Err(ApiError::bad_request("secret_hex tidak valid"));
    }

    let keypair =
        KeyPair::from_secret_hex(req.secret_hex.trim()).map_err(ApiError::bad_request)?;

    let mut chain = state.lock().await;

    if chain.mempool.len() >= security::MAX_MEMPOOL_TXS {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "mempool penuh, coba lagi nanti".into(),
        ));
    }

    // Fee otomatis: `estimate_fee()` mengembalikan FEE-RATE (per 1000 byte),
    // bukan fee absolut. Probe tx dulu untuk mengukur ukurannya, lalu konversi.
    let fee = if req.fee == 0 {
        let rate = chain.estimate_fee(1);
        let probe = build_transfer(&chain, &keypair, &req.to, req.amount, 0)?;
        market::fee_for_rate(rate, market::tx_size(&probe)).max(1)
    } else {
        req.fee
    };

    let tx = build_transfer(&chain, &keypair, &req.to, req.amount, fee)?;

    // Tolak lebih awal bila fee eksplisit user di bawah policy relay.
    let relay_rate = market::fee_rate(&chain.utxos, &tx);
    if relay_rate < market::MIN_FEE_RATE {
        return Err(ApiError::unprocessable(format!(
            "fee-rate {relay_rate} di bawah minimum relay fee-rate {}",
            market::MIN_FEE_RATE
        )));
    }
    let txid = tx.txid();
    let fee_rate = market::fee_rate(&chain.utxos, &tx);
    chain.submit_transaction(tx.clone())?;

    Ok(Json(TransferResp {
        txid,
        fee,
        fee_rate,
        raw: tx,
    }))
}

/// Detail transaksi berdasarkan txid (mempool atau sudah confirmed).
async fn get_tx(State(state): State<AppState>, Path(txid): Path<String>) -> ApiResult<Value> {
    if txid.len() != 64 {
        return Err(ApiError::bad_request("txid harus 64 karakter hex"));
    }
    let chain = state.lock().await;

    if let Some(tx) = chain.mempool.iter().find(|t| t.txid() == txid) {
        return Ok(Json(json!({
            "status": "mempool",
            "txid": txid,
            "fee": market::fee(&chain.utxos, tx),
            "fee_rate": market::fee_rate(&chain.utxos, tx),
            "tx": tx,
        })));
    }

    if let Some((height, tx)) = chain.find_transaction(&txid) {
        return Ok(Json(json!({
            "status": "confirmed",
            "txid": txid,
            "height": height,
            "confirmations": chain.height().saturating_sub(height),
            "tx": tx,
        })));
    }

    Err(ApiError::not_found(format!(
        "transaksi {txid} tidak ditemukan"
    )))
}

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

async fn mempool(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    Ok(Json(json!({
        "stats": chain.mempool_stats(),
        "txids": chain.mempool_txids(),
    })))
}

async fn mempool_tx(State(state): State<AppState>, Path(txid): Path<String>) -> ApiResult<Value> {
    let chain = state.lock().await;
    // Clone tx + hitung fee di dalam scope guard, supaya `chain` tidak perlu
    // hidup selama serialisasi JSON.
    let found = chain.mempool.iter().find(|t| t.txid() == txid).map(|tx| {
        let fee = market::fee(&chain.utxos, tx);
        let fee_rate = market::fee_rate(&chain.utxos, tx);
        (tx.clone(), fee, fee_rate)
    });
    drop(chain);

    match found {
        Some((tx, fee, fee_rate)) => Ok(Json(json!({
            "status": "mempool",
            "txid": txid,
            "fee": fee,
            "fee_rate": fee_rate,
            "tx": tx,
        }))),
        None => Err(ApiError::not_found(format!(
            "transaksi {txid} tidak ada di mempool"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Mining & blok
// ---------------------------------------------------------------------------

async fn mine(State(state): State<AppState>, Json(req): Json<MineReq>) -> ApiResult<MineResp> {
    let miner_address = req.miner_address.trim().to_string();
    if !crypto::is_valid_address(&miner_address) {
        return Err(ApiError::bad_request("miner_address tidak valid"));
    }

    // Mutex ditahan selama PoW agar tidak ada dua blok paralel
    // yang berebut tip yang sama di node ini.
    let mut chain = state.lock().await;
    let block = chain.mine_block(&miner_address)?;

    Ok(Json(MineResp {
        height: chain.height() - 1,
        hash: block.hash,
        nonce: block.header.nonce,
        difficulty: block.header.difficulty,
        tx_count: block.transactions.len(),
    }))
}

async fn get_block(State(state): State<AppState>, Path(height): Path<u64>) -> ApiResult<Value> {
    let chain = state.lock().await;
    let block = chain
        .blocks
        .get(height as usize)
        .ok_or_else(|| ApiError::not_found("blok tidak ditemukan"))?;

    Ok(Json(json!({
        "height": height,
        "hash": block.hash,
        "prev_hash": block.header.prev_hash,
        "merkle_root": block.header.merkle_root,
        "timestamp": block.header.timestamp,
        "difficulty": block.header.difficulty,
        "nonce": block.header.nonce,
        "tx_count": block.transactions.len(),
        "transactions": block.transactions,
    })))
}

/// Cari blok berdasarkan hash (explorer).
async fn get_block_by_hash(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> ApiResult<Value> {
    if hash.len() != 64 {
        return Err(ApiError::bad_request("hash harus 64 karakter hex"));
    }
    let chain = state.lock().await;
    let (height, block) = chain
        .block_by_hash(&hash)
        .ok_or_else(|| ApiError::not_found("blok tidak ditemukan"))?;

    Ok(Json(json!({
        "height": height,
        "hash": block.hash,
        "prev_hash": block.header.prev_hash,
        "merkle_root": block.header.merkle_root,
        "timestamp": block.header.timestamp,
        "difficulty": block.header.difficulty,
        "nonce": block.header.nonce,
        "tx_count": block.transactions.len(),
        "transactions": block.transactions,
    })))
}

/// Ringkasan N blok terakhir (terbaru dulu). `?limit=` default 10, maks 100.
async fn list_blocks(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Value> {
    let count: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
        .clamp(1, 100);

    let chain = state.lock().await;
    let list: Vec<Value> = chain
        .blocks
        .iter()
        .enumerate()
        .rev()
        .take(count)
        .map(|(height, b)| {
            json!({
                "height": height,
                "hash": b.hash,
                "prev_hash": b.header.prev_hash,
                "timestamp": b.header.timestamp,
                "difficulty": b.header.difficulty,
                "nonce": b.header.nonce,
                "tx_count": b.transactions.len(),
            })
        })
        .collect();

    Ok(Json(json!({ "count": list.len(), "blocks": list })))
}

// ---------------------------------------------------------------------------
// Verifikasi chain
// ---------------------------------------------------------------------------

/// Validasi ulang seluruh chain dari genesis (PoW, merkle, replay UTXO).
/// Endpoint admin: biayanya O(chain).
async fn verify(State(state): State<AppState>) -> ApiResult<Value> {
    let chain = state.lock().await;
    match chain.verify_chain() {
        Ok(()) => Ok(Json(json!({ "valid": true, "height": chain.height() }))),
        Err(e) => Ok(Json(json!({ "valid": false, "error": e.to_string() }))),
    }
}
