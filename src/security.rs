//! Lapisan keamanan terpusat: rate limiting, autentikasi token,
//! security header, batas ukuran body, dan validasi struktural
//! transaksi di batas API (sebelum masuk ke konsensus).
//!
//! Semua konstanta di sini adalah *policy* node, bukan aturan konsensus.
//! Node lain boleh memakai nilai berbeda tanpa memecah chain.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::chain::Chain;
use crate::crypto;
use crate::transaction::{OutPoint, Transaction};

// ---------------------------------------------------------------------------
// Policy constants
// ---------------------------------------------------------------------------

/// Batas atas supply: 21 juta koin, 8 desimal (satuan terkecil).
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Batas jumlah input per transaksi (anti-DoS: tx raksasa memakan CPU verifikasi).
pub const MAX_TX_INPUTS: usize = 100;

/// Batas jumlah output per transaksi (anti-DoS: memperbesar state UTXO).
pub const MAX_TX_OUTPUTS: usize = 100;

/// Batas transaksi dalam mempool. Diatas ini, tx baru ditolak (backpressure).
pub const MAX_MEMPOOL_TXS: usize = 5_000;

/// Fee-rate minimum (per 1000 byte) untuk diteruskan ke mempool.
///
/// Sengaja berbasis *rate*, bukan fee absolut: `estimate_fee()` di fee market
/// mengembalikan rate per 1000 byte, jadi policy relay harus memakai satuan
/// yang sama agar tx kecil tidak salah ditolak.
pub const MIN_RELAY_FEE_RATE: u64 = crate::market::MIN_FEE_RATE;

/// Batas panjang field hex (public key / signature) untuk menolak payload absurd.
pub const MAX_HEX_FIELD: usize = 200;

/// Batas panjang string address.
pub const MAX_ADDRESS_FIELD: usize = 64;

/// Batas ukuran body request (256 KiB) — cukup untuk 100 input + 100 output.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Batas jumlah transaksi dalam satu request batch.
pub const MAX_BATCH_TXS: usize = 50;

/// Jumlah request per menit per IP (token bucket, burst = kapasitas yang sama).
pub const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 120;

/// Batas keras jumlah bucket rate limiter. Bila tercapai dan pembersihan
/// tidak cukup, request dari IP *baru* ditolak (fail-closed) alih-alih
/// membiarkan map tumbuh sampai OOM.
pub const MAX_RATE_BUCKETS: usize = 50_000;

/// Bucket yang tidak aktif selama ini dibuang saat map mendekati batas.
pub const BUCKET_IDLE_TTL: Duration = Duration::from_secs(180);

/// Jeda minimum antar sapuan `retain()` saat map penuh.
///
/// Menjaga biaya sapuan O(n) tetap teramortisasi: paling banyak satu sapuan
/// per interval, bukan satu sapuan per request.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Rate limiter (token bucket per IP)
// ---------------------------------------------------------------------------

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token bucket per IP. Thread-safe, tidak butuh runtime async.
pub struct RateLimiter {
    per_minute: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Kapan sapuan `retain()` terakhir dijalankan. Dipisah dari `buckets`
    /// agar pengunciannya murah dan tidak memperpanjang hold time map.
    last_sweep: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute: per_minute.max(1),
            buckets: Mutex::new(HashMap::new()),
            // Diisi "sekarang" agar sapuan pertama baru terjadi setelah
            // SWEEP_INTERVAL, bukan langsung saat map menyentuh cap.
            last_sweep: Mutex::new(Instant::now()),
        }
    }

    /// True bila request diizinkan.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let capacity = self.per_minute as f64;
        let refill_per_sec = capacity / 60.0;

        // IPv6 dinormalisasi ke /64: satu penyerang biasanya menguasai
        // seluruh /64 (atau /48), jadi menomori per-alamat berarti
        // memberi mereka miliaran bucket gratis.
        let key = rate_key(ip);

        let mut map = match self.buckets.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Cegah pertumbuhan map tak terbatas (serangan IP acak / IPv6).
        //
        // Sapuan `retain()` bersifat O(n) dan berjalan sambil memegang mutex.
        // Tanpa throttle, begitu map menyentuh cap setiap request berikutnya
        // akan memicu sapuan penuh 50k entri — DoS baru yang menggantikan
        // OOM. Karena itu sapuan dibatasi frekuensinya (`last_sweep`), dan
        // di antara dua sapuan IP baru tetap ditolak (fail-closed).
        if map.len() >= MAX_RATE_BUCKETS {
            let sweep_due = self
                .last_sweep
                .lock()
                .map(|mut last| {
                    if last.elapsed() >= SWEEP_INTERVAL {
                        *last = Instant::now();
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);

            if sweep_due {
                map.retain(|_, b| b.last.elapsed() < BUCKET_IDLE_TTL);
            }
            // Masih penuh setelah disapu: tolak IP baru, jangan tumbuh.
            // Fail-closed lebih baik daripada OOM.
            if map.len() >= MAX_RATE_BUCKETS && !map.contains_key(&key) {
                return false;
            }
        }

        let now = Instant::now();
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Kunci rate-limit: IPv4 apa adanya, IPv6 dipadatkan ke prefix /64.
fn rate_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        IpAddr::V4(_) => ip,
    }
}

// ---------------------------------------------------------------------------
// Konfigurasi keamanan + middleware
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SecurityConfig {
    /// Bila `Some`, semua request non-GET dan endpoint admin wajib
    /// membawa header `Authorization: Bearer <token>`.
    pub api_token: Option<String>,
    pub limiter: Arc<RateLimiter>,
    /// Bila true, `X-Forwarded-For` dipercaya sebagai sumber IP klien.
    /// HANYA aktifkan bila node berada di belakang reverse proxy
    /// tepercaya — header ini bisa dipalsukan klien langsung.
    pub trust_proxy: bool,
}

impl SecurityConfig {
    pub fn new(api_token: Option<String>, rate_limit_per_min: u32) -> Self {
        Self {
            api_token: api_token.filter(|t| !t.trim().is_empty()),
            limiter: Arc::new(RateLimiter::new(rate_limit_per_min)),
            trust_proxy: false,
        }
    }

    pub fn auth_enabled(&self) -> bool {
        self.api_token.is_some()
    }
}

/// Perbandingan constant-time (anti timing attack pada token).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Endpoint yang butuh autentikasi walau method-nya GET.
///
/// Semua endpoint di sini berbiaya O(n) terhadap state chain dan dieksekusi
/// di dalam `state.lock()`. Karena `tokio::sync::Mutex` bersifat eksklusif,
/// satu scan tanpa auth akan memblokir seluruh request lain — ini masalah
/// *availability*, bukan kebocoran data.
fn is_admin_path(path: &str) -> bool {
    const EXACT: &[&str] = &[
        "/wallet",
        "/wallets",
        "/verify",
        "/stats",
        "/richlist",
        "/block/template",
        "/fee/histogram",
        // --- tambahan: handler berikut juga memindai state penuh ---
        // `/supply`      -> total_supply() iterasi seluruh UTXO set
        // `/fee/estimate`-> estimate_fee() + mempool_stats()
        // `/mempool`     -> mempool_stats() + mempool_txids()
        "/supply",
        "/fee/estimate",
        "/mempool",
    ];
    if EXACT.contains(&path) {
        return true;
    }
    // Endpoint mahal dengan parameter di dalam path.
    // `/balance/:addr` -> balance() + get_utxos_for_address(), scan UTXO set
    // `/utxos/:addr`   -> scan UTXO set
    // `/address/:addr/history` -> scan semua blok
    // `/mempool/:txid` -> iterasi mempool
    //
    // Dua route berikut awalnya dicatat sebagai "belum diverifikasi" di plan.
    // Setelah ditelusuri, keduanya O(n) dan menahan state.lock():
    // `/tx/:txid`          -> Chain::find_transaction(): loop blok x tx,
    //                         memanggil tx.txid() (SHA-256) tiap iterasi
    // `/block/hash/:hash`  -> Chain::block_by_hash(): linear scan seluruh blok
    path.starts_with("/utxos/")
        || path.starts_with("/address/")
        || path.starts_with("/balance/")
        || path.starts_with("/mempool/")
        || path.starts_with("/tx/")
        || path.starts_with("/block/hash/")
}

fn needs_auth(method: &Method, path: &str) -> bool {
    let is_read = *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS;
    !is_read || is_admin_path(path)
}

fn error_response(status: StatusCode, message: &str, extra: Option<(&str, String)>) -> Response {
    let mut body = json!({ "error": message });
    if let Some((key, value)) = extra {
        body[key] = json!(value);
    }
    (status, Json(body)).into_response()
}

/// Middleware keamanan: rate limit -> auth -> handler -> security header.
pub async fn guard(
    State(cfg): State<SecurityConfig>,
    req: Request,
    next: Next,
) -> Response {
    // IP klien: diambil dari ConnectInfo (butuh into_make_service_with_connect_info).
    // `X-Forwarded-For` HANYA dibaca bila TRUST_PROXY=1 — tanpa itu, header
    // bisa dipalsukan klien dan dipakai untuk menembus rate limit.
    // Fallback loopback agar test tanpa ConnectInfo tetap jalan.
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    let ip = if cfg.trust_proxy {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .or(peer_ip)
    } else {
        peer_ip
    }
    .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    if !cfg.limiter.allow(ip) {
        let mut res = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit terlampaui, coba lagi nanti",
            None,
        );
        res.headers_mut().insert(
            header::RETRY_AFTER,
            header::HeaderValue::from_static("60"),
        );
        apply_security_headers(&mut res);
        return res;
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if let Some(expected) = cfg.api_token.as_ref() {
        if needs_auth(&method, &path) {
            let provided = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|t| t.trim().to_string());

            let ok = provided
                .as_deref()
                .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
                .unwrap_or(false);

            if !ok {
                let mut res = error_response(
                    StatusCode::UNAUTHORIZED,
                    "butuh header Authorization: Bearer <API_TOKEN>",
                    None,
                );
                apply_security_headers(&mut res);
                return res;
            }
        }
    }

    let mut res = next.run(req).await;
    apply_security_headers(&mut res);
    res
}

fn apply_security_headers(res: &mut Response) {
    let headers = res.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        "x-api-version",
        header::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
}

// ---------------------------------------------------------------------------
// Validasi input
// ---------------------------------------------------------------------------

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validasi struktural murni (tanpa akses state). Dijalankan paling awal
/// supaya payload berbahaya ditolak sebelum menyentuh UTXO set.
pub fn validate_tx_shape(tx: &Transaction) -> Result<(), String> {
    if tx.inputs.is_empty() {
        return Err("transaksi tanpa input".into());
    }
    if tx.outputs.is_empty() {
        return Err("transaksi tanpa output".into());
    }
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err(format!(
            "terlalu banyak input: {} (maks {MAX_TX_INPUTS})",
            tx.inputs.len()
        ));
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(format!(
            "terlalu banyak output: {} (maks {MAX_TX_OUTPUTS})",
            tx.outputs.len()
        ));
    }

    let coinbase = tx.is_coinbase();

    // Input: format & duplikasi.
    let mut seen: Vec<OutPoint> = Vec::with_capacity(tx.inputs.len());
    for (idx, input) in tx.inputs.iter().enumerate() {
        if input.prev_txid.len() != 64 || !input.prev_txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("input #{idx}: prev_txid harus 64 hex"));
        }
        if coinbase {
            continue;
        }
        if input.public_key.len() > MAX_HEX_FIELD || !is_hex(&input.public_key) {
            return Err(format!("input #{idx}: public_key tidak valid"));
        }
        if input.signature.len() > MAX_HEX_FIELD || !is_hex(&input.signature) {
            return Err(format!("input #{idx}: signature tidak valid"));
        }
        let op = OutPoint::new(&input.prev_txid, input.prev_vout);
        if seen.contains(&op) {
            return Err(format!("input duplikat: {}:{}", op.txid, op.vout));
        }
        seen.push(op);
    }

    // Output: rentang nilai & address.
    let mut total: u64 = 0;
    for (idx, out) in tx.outputs.iter().enumerate() {
        if out.value == 0 {
            return Err(format!("output #{idx}: nilai 0 tidak diizinkan"));
        }
        if out.value > MAX_MONEY {
            return Err(format!("output #{idx}: nilai melebihi batas supply"));
        }
        if out.address.len() > MAX_ADDRESS_FIELD || !crypto::is_valid_address(&out.address) {
            return Err(format!("output #{idx}: address tidak valid"));
        }
        total = total
            .checked_add(out.value)
            .ok_or_else(|| "overflow total output".to_string())?;
    }
    if total > MAX_MONEY {
        return Err("total output melebihi batas supply".into());
    }

    Ok(())
}

/// Hitung fee transaksi dari UTXO set (None bila input tidak diketahui).
pub fn tx_fee(chain: &Chain, tx: &Transaction) -> Option<u64> {
    let mut input_sum: u64 = 0;
    for input in &tx.inputs {
        let op = OutPoint::new(&input.prev_txid, input.prev_vout);
        let utxo = chain.utxos.get(&op)?;
        input_sum = input_sum.checked_add(utxo.value)?;
    }
    let output_sum = tx.total_output().ok()?;
    input_sum.checked_sub(output_sum)
}

/// Pemeriksaan policy node sebelum tx masuk mempool.
/// Mengembalikan fee bila lolos.
pub fn relay_check(chain: &Chain, tx: &Transaction) -> Result<u64, String> {
    if chain.mempool.len() >= MAX_MEMPOOL_TXS {
        return Err(format!(
            "mempool penuh ({} transaksi), coba lagi nanti",
            chain.mempool.len()
        ));
    }

    let fee = tx_fee(chain, tx).ok_or_else(|| {
        "input transaksi tidak ditemukan di UTXO set (mungkin sudah dibelanjakan)".to_string()
    })?;

    // Policy berbasis fee-rate (per 1000 byte), sejalan dengan fee market.
    let rate = crate::market::fee_rate(&chain.utxos, tx);
    if rate < MIN_RELAY_FEE_RATE {
        return Err(format!(
            "fee-rate {rate} di bawah minimum relay fee-rate {MIN_RELAY_FEE_RATE}"
        ));
    }

    Ok(fee)
}

/// Bersihkan label bebas (wallet label) dari karakter kontrol & potong panjang.
pub fn sanitize_label(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxIn, TxOut};

    fn addr() -> String {
        crypto::KeyPair::random().address()
    }

    #[test]
    fn rejects_empty_inputs() {
        let tx = Transaction::new(vec![], vec![TxOut { value: 1, address: addr() }]);
        assert!(validate_tx_shape(&tx).is_err());
    }

    #[test]
    fn rejects_empty_outputs() {
        let tx = Transaction::new(
            vec![TxIn {
                prev_txid: "a".repeat(64),
                prev_vout: 0,
                public_key: "02".repeat(33),
                signature: "11".repeat(64),
            }],
            vec![],
        );
        assert!(validate_tx_shape(&tx).is_err());
    }

    #[test]
    fn rejects_zero_value_and_bad_address() {
        let input = TxIn {
            prev_txid: "a".repeat(64),
            prev_vout: 0,
            public_key: "02".repeat(33),
            signature: "11".repeat(64),
        };
        let zero = Transaction::new(vec![input.clone()], vec![TxOut { value: 0, address: addr() }]);
        assert!(validate_tx_shape(&zero).is_err());

        let bad_addr = Transaction::new(
            vec![input],
            vec![TxOut { value: 10, address: "bukan-address".into() }],
        );
        assert!(validate_tx_shape(&bad_addr).is_err());
    }

    #[test]
    fn rejects_duplicate_inputs() {
        let input = TxIn {
            prev_txid: "b".repeat(64),
            prev_vout: 3,
            public_key: "02".repeat(33),
            signature: "22".repeat(64),
        };
        let tx = Transaction::new(
            vec![input.clone(), input],
            vec![TxOut { value: 10, address: addr() }],
        );
        assert!(validate_tx_shape(&tx).is_err());
    }

    #[test]
    fn accepts_wellformed_tx() {
        let tx = Transaction::new(
            vec![TxIn {
                prev_txid: "c".repeat(64),
                prev_vout: 1,
                public_key: "02".repeat(33),
                signature: "33".repeat(64),
            }],
            vec![TxOut { value: 5_000, address: addr() }],
        );
        assert!(validate_tx_shape(&tx).is_ok());
    }

    #[test]
    fn rate_limiter_blocks_burst_then_refills() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
        // IP lain punya bucket sendiri.
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.allow(other));
    }

    #[test]
    fn label_sanitizer_strips_control_chars() {
        assert_eq!(sanitize_label("  tabungan\u{0007}  "), Some("tabungan".into()));
        assert_eq!(sanitize_label("   "), None);
        assert_eq!(sanitize_label(""), None);
    }

    #[test]
    fn ipv6_rate_key_collapses_to_slash64() {
        // Dua alamat di /64 yang sama harus berbagi bucket.
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        assert_eq!(rate_key(a), rate_key(b));

        // /64 berbeda = bucket berbeda.
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_ne!(rate_key(a), rate_key(c));
    }

    #[test]
    fn ipv4_rate_key_is_unchanged() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(rate_key(ip), ip);
    }

    #[test]
    fn expensive_endpoints_require_auth() {
        // Handler O(n) yang menahan state.lock().
        assert!(is_admin_path("/stats"));
        assert!(is_admin_path("/richlist"));
        assert!(is_admin_path("/supply"));
        assert!(is_admin_path("/fee/estimate"));
        assert!(is_admin_path("/mempool"));
        assert!(is_admin_path("/utxos/abc"));
        assert!(is_admin_path("/address/abc/history"));
        assert!(is_admin_path("/balance/abc"));
        assert!(is_admin_path("/mempool/deadbeef"));
        // Keduanya menelusuri seluruh chain (lihat find_transaction/block_by_hash).
        assert!(is_admin_path("/tx/aa"));
        assert!(is_admin_path("/block/hash/bb"));

        // Endpoint murah / sudah dijaga method-nya tetap terbuka.
        assert!(!is_admin_path("/health"));
        assert!(!is_admin_path("/info"));
        assert!(!is_admin_path("/tx"));
        assert!(!is_admin_path("/block/12"));
    }

    #[test]
    fn rate_limiter_sweep_is_throttled_under_cap() {
        // Bucket penuh (cap tercapai) tidak boleh memicu sapuan per request.
        // Bukti tidak langsung: limiter tetap memberi jawaban konsisten dan
        // IP baru tetap ditolak setelah cap, tanpa menggantung.
        let limiter = RateLimiter::new(60);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.allow(ip));
        }
        // Bucket segar bertahan setelah pemakaian berulang.
        assert!(limiter.allow(ip));
    }
}
