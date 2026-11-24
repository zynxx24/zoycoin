# Zoycoin

Backend transaksi ala Bitcoin, ditulis dalam Rust.

Model **UTXO** + signature **secp256k1 ECDSA** + **proof-of-work** SHA-256d,
dengan fee market berbasis fee-rate, blok berbatas, dan persistensi SQLite.

---

## 1. Prasyarat

| Kebutuhan | Versi |
|---|---|
| Rust toolchain | stable (edition 2021) |
| C compiler | `cc`/`gcc`, dibutuhkan `libsqlite3-sys` |
| SQLite | dibundel (`bundled` feature), tidak perlu install manual |

```bash
rustc --version   # pastikan cargo & rustc ada
```

---

## 2. Build & jalankan

```bash
# build release (disarankan)
cargo build --release

# jalankan node lokal (loopback saja, tanpa auth)
cargo run --release
```

Server default: **http://127.0.0.1:8080**

Cek hidup:

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/info
```

---

## 3. Environment variable

| Variabel | Default | Arti |
|---|---|---|
| `PORT` | `8080` | port HTTP |
| `DB_PATH` | `zoycoin.db` | path file SQLite |
| `DIFFICULTY` | `8` | difficulty awal (leading zero bit) |
| `API_TOKEN` | *(kosong)* | bila diisi: semua non-GET **dan** endpoint admin wajib `Authorization: Bearer <token>` |
| `RATE_LIMIT_PER_MIN` | `120` | batas request per menit per IP |
| `AUTO_MINE` | *(mati)* | `1` = miner otomatis tiap 5 detik |
| `DEMO_WALLET` | *(mati)* | `1` = cetak wallet demo ke log |
| `BIND_ALL` | *(mati)* | `1` = bind `0.0.0.0`. **Wajib** disertai `API_TOKEN` |
| `TRUST_PROXY` | *(mati)* | `1` = percayai `X-Forwarded-For`. Hanya di belakang reverse proxy tepercaya |

### Contoh: node publik

```bash
API_TOKEN="$(openssl rand -hex 32)" \
BIND_ALL=1 \
PORT=8080 \
DB_PATH=/var/lib/zoycoin/zoycoin.db \
cargo run --release
```

**Fail-closed:** `BIND_ALL=1` tanpa `API_TOKEN` -> proses **menolak start**
dengan pesan jelas. Ini disengaja; jangan diakali dengan mengosongkan token.

---

## 4. Autentikasi: kapan token diwajibkan

Aturannya ada di `src/security.rs` (`needs_auth` + `is_admin_path`).

**Selalu wajib token (semua method non-GET):**

```
POST /wallet   POST /tx   POST /tx/batch   POST /tx/decode
POST /transfer POST /mine
```

**Wajib token karena O(n) terhadap state chain (menahan `state.lock()`):**

```
GET /stats          GET /supply        GET /richlist
GET /fee/estimate   GET /fee/histogram GET /block/template
GET /wallet         GET /wallets       GET /verify
GET /mempool        GET /mempool/:txid
GET /balance/:addr  GET /utxos/:addr   GET /address/:addr/history
GET /tx/:txid       GET /block/hash/:hash
```

**Tetap terbuka (murah / liveness probe):**

```
GET /health   GET /info   GET /block/:height   GET /blocks
```

Contoh request terautentikasi:

```bash
curl -s -H "Authorization: Bearer $API_TOKEN" http://127.0.0.1:8080/stats
```

---

## 5. Ringkasan endpoint

| Method | Path | Keterangan |
|---|---|---|
| GET | `/health` | liveness probe |
| GET | `/info` | info node & chain |
| GET | `/stats` | statistik chain |
| GET | `/supply` | total supply beredar |
| GET | `/richlist` | peringkat saldo |
| GET | `/fee/estimate` | estimasi fee-rate |
| GET | `/fee/histogram` | histogram fee mempool |
| GET | `/block/template` | template blok untuk miner |
| POST | `/wallet` | buat keypair baru |
| GET | `/wallets` | daftar wallet tersimpan |
| GET | `/balance/:address` | saldo address |
| GET | `/utxos/:address` | UTXO milik address |
| GET | `/address/:address/history` | riwayat transaksi address |
| POST | `/tx` | submit satu transaksi |
| POST | `/tx/batch` | submit banyak transaksi (maks 50) |
| POST | `/tx/decode` | decode transaksi mentah |
| GET | `/tx/:txid` | cari transaksi |
| POST | `/transfer` | kirim dana (helper) |
| GET | `/mempool` | isi mempool |
| GET | `/mempool/:txid` | detail tx di mempool |
| POST | `/mine` | tambang satu blok |
| GET | `/block/:height` | blok berdasarkan tinggi |
| GET | `/block/hash/:hash` | blok berdasarkan hash |
| GET | `/blocks` | daftar blok terbaru (maks 100) |
| GET | `/verify` | verifikasi integritas chain |

---

## 6. Batas & policy node

Nilai di `src/security.rs` adalah **policy node**, bukan aturan konsensus.
Node lain boleh memakai angka berbeda tanpa memecah chain.

| Konstanta | Nilai | Fungsi |
|---|---|---|
| `MAX_MONEY` | 21.000.000 x 10^8 | batas atas supply |
| `MAX_TX_INPUTS` | 100 | batas input per tx |
| `MAX_TX_OUTPUTS` | 100 | batas output per tx |
| `MAX_MEMPOOL_TXS` | 5.000 | backpressure mempool |
| `MAX_BODY_BYTES` | 256 KiB | batas ukuran body request |
| `MAX_BATCH_TXS` | 50 | batas tx per `/tx/batch` |
| `MAX_HEX_FIELD` | 200 | batas panjang field hex |
| `MAX_RATE_BUCKETS` | 50.000 | cap bucket rate limiter |

Rate limiter menormalkan IPv6 ke prefix **/64**, dan sapuan bucket
dibatasi `SWEEP_INTERVAL = 10s` agar tidak menjadi O(n) per request.

---

## 7. Test

```bash
cargo test
```

Test mencakup: normalisasi IPv6 /64, throttle sapuan rate limiter,
daftar `is_admin_path`, validasi bentuk transaksi, dan batas hex.

---

## 8. Struktur proyek

```
src/
  main.rs         entrypoint, env, bind address (fail-closed)
  api.rs          router + handler HTTP
  security.rs     rate limit, auth, header, validasi input
  chain.rs        state chain, UTXO set, mempool
  block.rs        struktur blok & header
  transaction.rs  model transaksi UTXO
  crypto.rs       keypair, alamat, signature
  market.rs       fee market & estimasi
  stats.rs        statistik & indeks baca
  store.rs        persistensi SQLite
```

---

## 9. Keamanan: baca sebelum publish

1. **Jangan pernah commit private key.** File wallet berisi `secret_hex`
   plaintext. Seluruh `.local/` sudah masuk `.gitignore`; simpan kunci di
   sana atau di secret manager.
2. **`BIND_ALL=1` wajib `API_TOKEN`.** Proses menolak start tanpa itu.
3. **`TRUST_PROXY` hanya untuk reverse proxy tepercaya.** Tanpa proxy,
   header `X-Forwarded-For` bisa dipalsukan untuk menembus rate limit.
4. **`Cargo.lock` sengaja di-commit**: binary crate, build reproducible.
5. **Kebocoran kunci tidak bisa dibatalkan.** Kalau `secret_hex` pernah
   terkirim ke luar mesin ini, pindahkan dananya ke keypair baru.

---

## 10. Cara commit & publish

Repositori ini sudah ter-init. Alur standar:

```bash
# 1. pastikan tidak ada artefak runtime yang ikut ter-stage
git status --short

# 2. cek file rahasia benar-benar terabaikan
git check-ignore -v .local/keys/a.json
git check-ignore -v zoycoin.db

# 3. stage perubahan source saja
git add -A

# 4. review sebelum commit
git diff --cached --stat

# 5. commit
git commit -m "pesan yang menjelaskan perubahan"

# 6. publish
git remote add origin <url-repo-kamu>
git push -u origin main
```

### Sebelum push pertama, wajib dicek

```bash
# tidak boleh ada kunci / DB / log di daftar ini
git ls-files | grep -Ei '\.(json|db|log|pid|pem|key)$'

# .local/ harus benar-benar terabaikan
git check-ignore -v .local/keys/a.json .local/db/zoycoin.db
```

Kalau salah satu perintah di atas memunculkan file yang seharusnya
rahasia, **jangan push**. Hapus dari index dulu:

```bash
git rm --cached <file>
```

### Kalau kunci sudah terlanjur ter-push

`git rm --cached` **tidak** menghapus file dari riwayat. Kunci itu harus
dianggap bocor: pindahkan dananya ke keypair baru, lalu bersihkan riwayat
dengan `git filter-repo` bila repo sudah publik.

---

## 11. Lisensi

Belum ditetapkan. Tambahkan `LICENSE` sebelum publikasi terbuka.

---

## 12. Changelog & Report Pekerjaan

Lihat **[CHANGELOG.md](CHANGELOG.md)** untuk catatan perubahan per tanggal
beserta report pekerjaan lengkap (test, security, backup, pembersihan).
