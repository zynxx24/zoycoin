# Zoycoin — Security Hardening Plan (A/B/C)

Status audit: **final**, setelah verifikasi ulang terhadap source.
Dua temuan awal audit dinyatakan **tidak valid** dan dicabut.

## Koreksi audit

### C3 — `sighash()` tidak mengikat outpoint → **TIDAK VALID**
`sighash()` di `src/transaction.rs` sudah meng-hash:
`version`, `jumlah input`, **semua `prev_txid` + `prev_vout`**,
`jumlah output`, **semua `value` + `address` output**.

Artinya signature sudah mengikat input mana yang dibelanjakan.
Serangan realokasi input (theft) **tidak mungkin**. Tidak ada perubahan kode.

Catatan desain (bukan bug): satu `sighash` untuk seluruh tx = model
"SIGHASH_ALL". Konsekuensinya semua input harus ditandatangani satu key.
Kode saat ini mengizinkan `public_key` berbeda per input, tetapi address
check per-input membuatnya tidak berguna. Ini kontrak yang perlu
didokumentasikan, bukan diperbaiki sekarang.

### H2 — rate limiter tanpa eviction → **SEBAGIAN TIDAK VALID**
`RateLimiter::allow()` sudah memanggil `retain()` saat `len() > 20_000`.
Namun masih ada dua lubang nyata:
1. **IPv6**: satu penyerang dengan blok `/48` punya ~10^19 alamat valid.
   Setiap alamat = bucket baru. `retain()` hanya membuang bucket *idle*;
   penyerang bisa terus mengisi dengan alamat baru sebelum TTL habis.
2. **Tidak ada hard cap**: kalau `retain()` tidak cukup membuang,
   map tetap tumbuh sampai OOM.

Perbaikan: normalisasi key IPv6 ke `/64` + hard cap fail-closed.

---

## FASE A — Fail-closed & autentikasi

### A1. Bind default loopback
`main.rs` sebelumnya: `format!("0.0.0.0:{port}")` → selalu terbuka.
Sekarang: default `127.0.0.1`, ekspos hanya bila `BIND_ALL=1`.

### A2. Tolak start tanpa token saat bind publik
Sebelumnya hanya `warn!` lalu proses jalan → siapa pun di jaringan bisa
`POST /mine` dan mencetak koin gratis.
Sekarang: proses **return Err** dan berhenti.

### A3. TRUST_PROXY eksplisit
`X-Forwarded-For` bisa dipalsukan klien. Header ini hanya dibaca bila
`TRUST_PROXY=1` diset operator. Default: abaikan header, pakai `ConnectInfo`.

---

## FASE B — Availability

### B1. Perluas daftar endpoint admin
Endpoint O(n) yang menahan `state.lock()` dan bisa dipicu tanpa auth:

Awalnya terdaftar hanya `/stats`, `/richlist`, `/block/template`,
`/fee/histogram`, `/utxos/*`, `/address/*`. Verifikasi terhadap
`router()` di `api.rs` menemukan **empat endpoint terlewat**:

| Route | Sumber biaya O(n) |
|---|---|
| `GET /supply` | `total_supply()` — iterasi seluruh UTXO set |
| `GET /balance/:address` | `balance()` + `get_utxos_for_address()` |
| `GET /fee/estimate` | `estimate_fee()` + `mempool_stats()` |
| `GET /mempool` | `mempool_stats()` + `mempool_txids()` |

Keempatnya kini masuk `is_admin_path`, termasuk prefix `/balance/`
dan `/mempool/` untuk varian berparameter.

Kandidat yang sempat ditandai "belum diverifikasi" sudah ditelusuri:

| Route | Hasil verifikasi |
|---|---|
| `GET /tx/:txid` | **O(n)** — `Chain::find_transaction()` loop blok × tx, memanggil `tx.txid()` (SHA-256) tiap iterasi → **ditambahkan** |
| `GET /block/hash/:hash` | **O(n)** — `Chain::block_by_hash()` linear scan seluruh blok → **ditambahkan** |
| `GET /blocks` | O(limit) — `.rev().take(count)` dengan `clamp(1,100)`, tidak scan penuh → tetap terbuka |

Prefix `/tx/` dan `/block/hash/` kini masuk `is_admin_path`.
`/tx/batch` dan `/tx/decode` ikut tercakup prefix `/tx/`, tetapi
keduanya `POST` sehingga sudah wajib auth lewat `needs_auth` —
tidak ada regresi.

Karena `tokio::sync::Mutex` eksklusif, satu scan memblokir **semua**
request lain termasuk `/tx` dan `/mine`. Ini availability bug, bukan
kebocoran data.

### B2. Normalisasi IPv6 ke /64
Rate limiter semula memakai `IpAddr` mentah sebagai kunci bucket. Satu
penyerang yang menguasai sebuah /64 (umumnya satu pelanggan ISP) bisa
memakai 2^64 alamat berbeda dan mendapat 2^64 bucket — pembatasan per
alamat jadi tidak berarti sekaligus membanjiri map.

Perbaikan: `rate_key()` memadatkan IPv6 ke prefix /64 dengan
menolkan 4 segmen terakhir (`Ipv6Addr::new(s[0..3], 0,0,0,0)`).
IPv4 dipakai apa adanya. Diverifikasi oleh test
`ipv6_rate_key_collapses_to_slash64` (src/security.rs:611).

### B3. Throttle sapuan rate limiter
`retain()` bersifat O(n) dan berjalan sambil memegang mutex limiter.
Tanpa throttle, begitu map menyentuh `MAX_RATE_BUCKETS` setiap request
berikutnya memicu sapuan penuh 50k entri — DoS CPU yang menggantikan
OOM yang justru ingin dicegah.

Perbaikan: `last_sweep: Mutex<Instant>` + `SWEEP_INTERVAL = 10s`.
Sapuan maksimal sekali per interval; di antara dua sapuan IP baru
tetap ditolak (fail-closed).

`last_sweep` sengaja dipisah dari `buckets` agar pengunciannya murah
dan tidak memperpanjang hold time map utama.

---

## FASE C — Pembersihan

### C1. Redaksi error internal
`ChainError::Internal(_)` sebelumnya mengirim `err.to_string()` mentah
ke klien (bisa memuat path file / pesan SQLite).
Sekarang: detail → log server, klien dapat pesan generik.

### C2. `decode_tx` melaporkan relayability
`decode_tx` memanggil `validate_transaction` langsung, melewati
`relay_check`. Tx bergaya-coinbase bisa tampil `valid: true` padahal
tidak akan pernah diterima `POST /tx`.
Sekarang: field `relayable` + `relay_error` terpisah dari `valid`.

### C3. Hex decode eksplisit
`hex::decode(&input.public_key).unwrap_or_default()` menghasilkan `&[]`,
lalu `address_from_pubkey_bytes(&[])` menghasilkan address acak yang
kebetulan gagal di `AddressMismatch`. Aman secara kebetulan, tapi
menyembunyikan input rusak. Diganti error eksplisit.

---

## Yang TIDAK diubah (dan alasannya)

| Item | Alasan |
|---|---|
| `secret_hex` di API | Perubahan arsitektur (klien menandatangani lokal). Di luar cakupan hardening ini; butuh perubahan wallet + frontend. Dicatat sebagai risiko residu. |
| SQLite `spawn_blocking` | Perubahan struktural pada `Chain`. Risiko regresi tinggi. Dicatat sebagai backlog. |
| Mempool eviction by fee | Butuh kebijakan RBF; mengubah semantik konsensus. Butuh desain terpisah. |
| `hash160` = SHA-256[..20] | Mengubahnya = mematikan semua wallet yang ada. Keputusan sadar. |

## Urutan deploy
1. Fase A → restart node, verifikasi `curl http://127.0.0.1:8080/health`
2. Fase B → uji `curl -H "Authorization: Bearer x" .../stats` → 401
3. Fase C → `cargo test`
