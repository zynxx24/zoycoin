# Rencana Pengerasan Keamanan — Zoycoin

Dokumen ini mencatat temuan audit dan perbaikannya. Setiap item punya
jejak di kode agar bisa diverifikasi ulang.

---

## A. Fail-closed & autentikasi

### A1. Bind default loopback
Server semula bind ke `0.0.0.0` secara default, sehingga node dev
langsung terekspos ke LAN. Default diubah ke `127.0.0.1` (`src/main.rs`).

### A2. Tolak start tanpa token saat bind publik
`BIND_ALL=1` tanpa `API_TOKEN` membuat seluruh endpoint admin terbuka.
Kini proses **menolak start** dengan pesan eksplisit (fail-closed)
alih-alih diam-diam berjalan tanpa proteksi.

### A3. `TRUST_PROXY` eksplisit
`X-Forwarded-For` semula selalu dipercaya, sehingga klien bisa memalsukan
IP dan menembus rate limit. Kini header itu hanya dibaca bila
`TRUST_PROXY=1`.

---

## B. Rate limiting & endpoint mahal

### B1. Endpoint admin diperluas
Endpoint GET yang berbiaya O(n) terhadap state chain dieksekusi di dalam
`state.lock()`. Karena `tokio::sync::Mutex` eksklusif, satu scan tanpa
auth memblokir seluruh request lain — masalah availability.

Ditambahkan ke `is_admin_path`:

| Route | Hasil verifikasi |
|---|---|
| `/stats`, `/supply`, `/richlist` | scan state penuh |
| `/fee/estimate`, `/fee/histogram` | iterasi mempool |
| `/block/template` | susun kandidat blok |
| `/wallet`, `/wallets`, `/verify` | scan wallet / chain |
| `/mempool`, `/mempool/:txid` | iterasi mempool |
| `/balance/:addr`, `/utxos/:addr` | scan UTXO set |
| `/address/:addr/history` | scan semua blok |
| `/tx/:txid` | **O(n)** — `find_transaction()` loop blok x tx, memanggil `tx.txid()` (SHA-256) tiap iterasi |
| `/block/hash/:hash` | **O(n)** — `block_by_hash()` linear scan seluruh blok |

`/tx/batch` dan `/tx/decode` ikut tercakup prefix `/tx/`, tetapi keduanya
`POST` sehingga sudah wajib auth lewat `needs_auth` — tidak ada regresi.

Sengaja **tetap terbuka**: `/health`, `/info` (liveness probe),
`/block/:height` (`blocks.get(height)` = O(1)), `/blocks`
(`.rev().take(count)` dengan `clamp(1,100)` = O(limit)).

### B2. Normalisasi IPv6 ke /64
Rate limiter semula memakai `IpAddr` mentah sebagai kunci bucket. Satu
penyerang yang menguasai sebuah /64 bisa memakai 2^64 alamat berbeda dan
mendapat 2^64 bucket — pembatasan per alamat jadi tidak berarti sekaligus
membanjiri map.

Perbaikan: `rate_key()` memadatkan IPv6 ke prefix /64 dengan menolkan 4
segmen terakhir. IPv4 dipakai apa adanya. Diverifikasi oleh test
`ipv6_rate_key_collapses_to_slash64`.

### B3. Throttle sapuan rate limiter
`retain()` bersifat O(n) dan berjalan sambil memegang mutex limiter.
Tanpa throttle, begitu map menyentuh `MAX_RATE_BUCKETS` setiap request
berikutnya memicu sapuan penuh 50k entri — DoS CPU yang menggantikan
OOM yang justru ingin dicegah.

Perbaikan: `last_sweep: Mutex<Instant>` + `SWEEP_INTERVAL = 10s`.
Sapuan maksimal sekali per interval; di antara dua sapuan IP baru tetap
ditolak (fail-closed). `last_sweep` sengaja dipisah dari `buckets` agar
pengunciannya murah dan tidak memperpanjang hold time map utama.

---

## C. Kebocoran informasi & validasi input

### C1. Redaksi error internal
`ChainError::Internal` semula mengirim detail ke klien. Kini detail hanya
masuk `tracing::error!`, klien menerima `"kesalahan internal server"`.

### C2. Flag `relayable`
Field `relayable` semula bernilai `valid` saja, padahal tx bisa valid
secara struktur namun ditolak kebijakan relay (fee terlalu rendah).
Diperbaiki menjadi `valid && relay_verdict.is_none()`.

### C3. Validasi panjang hex eksplisit
`secret_hex` dan field hex lain kini dicek terhadap `MAX_HEX_FIELD`
sebelum `from_secret_hex`, sehingga payload absurd ditolak lebih awal.

---

## Yang TIDAK diubah (dan alasannya)

| Item | Alasan tidak disentuh |
|---|---|
| `secret_hex` dikirim/diterima API | Butuh perubahan wallet + frontend sekaligus. Risiko residu tinggi. |
| SQLite tanpa `spawn_blocking` | Perubahan struktural `Chain`, risiko regresi besar. |
| Mempool tanpa eviction by fee | Butuh kebijakan RBF, mengubah semantik konsensus. |
| `hash160` = SHA256[..20] | Mengubahnya mematikan semua wallet lama. |

---

## Verifikasi

- `cargo test` — seluruh test lulus, termasuk test regresi B1/B2/B3.
- `cargo build --release` — bersih.
- `git ls-files` — tidak ada file rahasia ter-track.
