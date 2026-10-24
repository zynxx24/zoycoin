# Changelog & Report — Zoycoin

Dokumen ini menggabungkan **catatan perubahan per tanggal** dan **report
pekerjaan** dalam satu tempat. Status proyek: **DEV** (belum produksi).

---

## Ringkasan Status Terakhir

| Item | Nilai |
|---|---|
| Tanggal snapshot | **2026-10-24** |
| Test suite | **39 passed, 0 failed, 0 ignored** |
| Waktu test | 0.22 s |
| Build release | OK — `target/release/zoycoin` (5.0 MB) |
| Kode sumber | 12 modul, **4.600 baris** |
| Warning build | **Ada** — 3 struct belum dipakai (lihat §4.3) |
| Backup terakhir | `backups/dev-20261024-211908/` |
| Branch git | belum ada commit baru; perubahan masih working tree |

---

## 1. Changelog 2026-10-24

### 1.1 Keamanan — `.gitignore` diperkuat

Ditambahkan blok **`1b. BACKUP DEV`** (15 baris) ke `.gitignore`:

```gitignore
/backups/
backups/
*.tar.gz
```

**Alasan:** folder `backups/` berisi `keys.tar.gz` yang memuat `a.json` dan
`b.json` **lengkap dengan `secret_hex`** (private key plaintext). Ini
sederajat dengan `.local/keys/` yang sudah di-ignore, sehingga wajib
diperlakukan sama.

**Verifikasi:**

```console
$ git check-ignore -v backups/dev-20261024-211908/db.tar.gz
.gitignore:47:backups/    backups/dev-20261024-211908/db.tar.gz
```

Backup **tetap ada di disk** untuk rollback — hanya tidak masuk repo.

### 1.2 Backup snapshot dev dibuat

```
backups/dev-20261024-211908/
├── db.tar.gz       509.755 B   SQLite (zoycoin.db + .local/db/*)
├── keys.tar.gz         517 B   .local/keys/ (a.json, b.json, addr_*.txt)
├── logs.tar.gz       2.023 B   log runtime
└── SECURITY_PLAN.md  6.304 B   snapshot dokumen security
```

Sesuai arahan: DB **tidak** dihapus, hanya di-backup dulu karena proyek
masih tahap dev.

### 1.3 Pembersihan artefak build

- `target/debug/incremental/` — puluhan ribu file objek sisa build dihapus.
- `target/release/zoycoin` (5.0 MB) **dipertahankan** — binary hasil build
  yang test-nya lulus.
- `Cargo.lock` dan seluruh `src/*.rs` **tidak disentuh**.

---

## 2. Perubahan Kode (working tree, belum commit)

```console
$ git diff --stat
 .gitignore    |  15 ++++++
 src/api.rs    | 162 +++++++++++++++++++++++++++++++++++++++++++++++---
 src/crypto.rs |  19 ++++++
 src/main.rs   |  12 ++++-
 src/market.rs |   4 +-
 5 files changed, 203 insertions(+), 9 deletions(-)
```

File baru yang belum ter-track:

| File | Baris | Isi |
|---|---|---|
| `src/mempool.rs` | 468 | Mempool: eviction, RBF, cascade remove, orphan prune |
| `src/web3.rs` | 351 | Auth challenge/verify, nonce single-use, sesi bearer |
| `.gitignore.bak` | — | Backup `.gitignore` sebelum edit (boleh dihapus) |

### 2.1 Detail per file

**`src/api.rs` (+162)** — handler HTTP baru: endpoint Web3 auth, batch tx,
decode, dan perluasan admin path.

**`src/crypto.rs` (+19)** — validasi bentuk address & helper base58.

**`src/main.rs` (+12)** — wiring modul `mempool` & `web3` ke router.

**`src/market.rs` (±4)** — perbaikan helper `tx()` pada test: transaksi
sebelumnya identik sehingga asersi "fee naik" tidak bermakna.

---

## 3. Struktur Kode Saat Ini

```
src/
  main.rs        196   entrypoint, env, bind address (fail-closed)
  api.rs         911   router + handler HTTP
  security.rs    664   rate limit, auth, header, validasi input
  chain.rs       677   state chain, UTXO set, mempool
  mempool.rs     468   eviction, RBF, orphan handling
  web3.rs        351   auth challenge/verify, sesi
  transaction.rs 271   model transaksi UTXO
  store.rs       258   persistensi SQLite
  crypto.rs      250   keypair, alamat, signature
  market.rs      216   fee market & estimasi
  stats.rs       205   statistik & indeks baca
  block.rs       133   struktur blok & header
  ────────────────────
  total         4600
```

---

## 4. Report Test

### 4.1 Hasil

```console
$ cargo test --quiet
running 39 tests
.......................................
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
finished in 0.22s
```

### 4.2 Cakupan per modul

| Modul | `#[test]` | Fokus |
|---|---:|---|
| `security` | 11 | rate limiter burst/refill, IPv6 /64 collapse, auth endpoint mahal, sanitizer, validasi shape tx |
| `mempool` | 9 | eviction, RBF, cascade remove, orphan prune, spent-lock |
| `market` | 4 | fee floor, target rate, miner rich-list |
| `web3` | 4 | nonce sekali-pakai, domain-bound message, wrong key, revoke sesi |
| `chain` | 3 | double-spend ditolak, reward + maturity |
| `crypto` | 3 | base58 roundtrip, validasi address, sign/verify |
| `stats` | 3 | keys, block lookup, history kosong |
| `block` | 2 | leading zeros |
| **Total** | **39** | |

### 4.3 ⚠️ Koreksi klaim sebelumnya

Report sesi lalu menyebut build **"warning-free"**. Itu **tidak akurat**.
`cargo test` saat ini mengeluarkan warning:

```
warning: struct `ChallengeResp` is never constructed   --> src/web3.rs:267
warning: struct `VerifyReq`     is never constructed   --> src/web3.rs:275
warning: struct `VerifyResp`    is never constructed   --> src/web3.rs:282
```

Ketiganya struct respons Web3 yang belum dipakai handler. **Tidak
menggagalkan build atau test**, tapi klaim "tanpa warning" salah dan
dicatat di sini supaya tidak menyesatkan.

---

## 5. Report Keamanan

Yang **terbukti aktif** dari uji end-to-end:

| Kontrol | Bukti |
|---|---|
| `/web3/session` tanpa challenge valid | **401** |
| Address sampah | ditolak di layer validasi |
| Nonce | single-use (tidak bisa dipakai ulang) |
| Sesi bearer | ber-TTL, bisa di-revoke |
| Rate limiter | per-IP, IPv6 di-collapse ke **/64** agar tidak bypass |
| `BIND_ALL=1` tanpa `API_TOKEN` | proses **menolak start** (fail-closed) |

### Policy node (bukan konsensus)

| Konstanta | Nilai |
|---|---|
| `MAX_MONEY` | 21.000.000 × 10^8 |
| `MAX_TX_INPUTS` / `MAX_TX_OUTPUTS` | 100 / 100 |
| `MAX_MEMPOOL_TXS` | 5.000 |
| `MAX_BODY_BYTES` | 256 KiB |
| `MAX_BATCH_TXS` | 50 |
| `MAX_HEX_FIELD` | 200 |
| `MAX_RATE_BUCKETS` | 50.000 |
| `SWEEP_INTERVAL` | 10 s |

---

## 6. Catatan Dev — Wajib Dibaca Sebelum Push

1. **`backups/` berisi private key dev.** Sudah di-ignore, tapi jangan
   pernah `git add -f`. Kalau perlu diarsipkan ke luar mesin, **enkripsi
   dulu** (age/gpg).
2. **`.gitignore.bak`** masih ada di working tree. Isinya `.gitignore`
   versi lama — aman, tapi sebaiknya dihapus atau di-ignore agar tidak
   ikut ter-commit.
3. **`src/mempool.rs` dan `src/web3.rs` belum ter-track git.** Kalau
   `git add -A` dijalankan, keduanya akan masuk — itu memang yang
   diinginkan, tapi pastikan tidak ada kunci yang ikut.
4. **Warning `web3.rs`** perlu dibereskan sebelum rilis: pakai struct
   tersebut atau beri `#[allow(dead_code)]` dengan alasan jelas.
5. **Kunci dev di `.local/keys/`** — kalau `secret_hex` pernah keluar dari
   mesin ini, anggap bocor: pindahkan dana ke keypair baru.

### Checklist sebelum push

```bash
git status --short
git check-ignore -v .local/keys/a.json backups/dev-20261024-211908/keys.tar.gz
git ls-files | grep -Ei '\.(json|db|log|pid|pem|key|gz)$'   # harus kosong
```

Kalau perintah terakhir memunculkan file rahasia, **jangan push**.

---

## 7. Rollback

Kalau perlu kembali ke state sebelum pembersihan:

```bash
cd /home/wira/Documents/agent/workspace/1
mkdir -p restore && tar -xzf backups/dev-20261024-211908/db.tar.gz -C restore
tar -xzf backups/dev-20261024-211908/keys.tar.gz -C restore
```

Binary lama: `target/release/zoycoin` (masih ada, tidak dihapus).

---

## 8. Ringkasan Jujur

**Selesai:**
- `.gitignore` diperkuat untuk `backups/` — terverifikasi dengan `git check-ignore`.
- Backup dev lengkap dibuat (DB, keys, logs, security plan).
- Artefak build basi dibersihkan; binary release dipertahankan.
- Test suite hijau: 39/39.
- README + CHANGELOG digabung jadi satu dokumen (file ini).

**Belum selesai / terbuka:**
- 3 warning `dead_code` di `src/web3.rs` (§4.3).
- `src/mempool.rs` & `src/web3.rs` belum di-commit.
- `.gitignore.bak` belum dibersihkan.
- `LICENSE` belum ditetapkan.
