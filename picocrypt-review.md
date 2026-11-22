# Picocrypt Code Review

> [!NOTE]
> This is a review of [Picocrypt.go](file:///run/media/shenouda/Data/Data/projects/Picocrypt/src/Picocrypt.go) — a ~2,900-line single-file Go application providing a GUI encryption tool. Version **v1.49**, released under GPL-3.0.

---

## Overall Impression

Picocrypt is a **well-intentioned and thoughtfully designed** personal encryption tool. The cryptographic architecture is solid in its *choices* — XChaCha20 + keyed BLAKE2b (or HMAC-SHA3), Argon2id for KDF, Serpent as a cascade cipher in paranoid mode, HKDF-SHA3 for subkey derivation, Reed-Solomon for error correction. These are excellent algorithm picks. The code is readable and the author clearly cares about getting the crypto right.

That said, there are real issues. I'll separate them into **cryptographic/security concerns**, **software engineering issues**, and **things done well**.

---

## 🔴 Cryptographic & Security Concerns

### 1. MAC-then-Encrypt ordering (Encrypt-then-MAC is correct, but verify the flow)

The code actually does **Encrypt-then-MAC** for encryption (line 2050-2053: encrypt, then `mac.Write(dst)`) and **MAC-then-Decrypt** for decryption (line 2142-2145: `mac.Write(src)` on ciphertext, then decrypt). This is the **correct** ordering ✅. The MAC covers the ciphertext, which is the right approach.

### 2. No AEAD — using unauthenticated ChaCha20 + separate MAC

The code uses `chacha20.NewUnauthenticatedCipher` (line 1974) with a hand-rolled MAC-then-decrypt scheme instead of XChaCha20-Poly1305 (AEAD). While the separate keyed-BLAKE2b/HMAC-SHA3 MAC achieves the same goal, this is a **fragile construction** that's harder to audit and easier to get wrong in future changes. The MAC is verified *after* the entire file is decrypted (line 2232), meaning:

- The **entire plaintext is written to disk before authentication is checked**
- If authentication fails, the corrupted/malicious plaintext file exists on disk temporarily (cleaned up in `broken()`, but a crash between write and cleanup leaks it)

> [!WARNING]
> This is the most significant architectural concern. An attacker who can modify ciphertext gets the decrypted (albeit corrupted) output written to disk before the MAC check runs. The `.incomplete` suffix mitigates this partially, but a crash or kill -9 leaves the file behind.

### 3. Deniability layer uses unauthenticated encryption with no MAC at all

The deniability feature (lines 2262-2365 for encrypt, 1419-1534 for decrypt) wraps the entire volume in an extra XChaCha20 layer with **zero authentication**. There's no MAC on this outer layer. An attacker can bit-flip the ciphertext, and the inner layer's MAC will catch it, but the deniability layer itself provides no integrity guarantee. The nonce rekeying at 60 GiB (line 2337) uses `sha3(nonce)` which is deterministic — if the same password encrypts the same file twice with deniability, and by cosmic coincidence the same salt is generated, the nonce sequence would repeat. (Extremely unlikely, but the main encryption path uses HKDF which is cleaner.)

### 4. Key hash stored in the header enables offline brute-force

The header stores `SHA3-512(encryption_key)` (line 2218, written back after encryption). During decryption, this is compared to verify the password (line 1905). This means an attacker with the file can:

1. Try a password
2. Run Argon2id to derive the key
3. Compare `SHA3-512(derived_key)` against the stored hash
4. **No need to actually decrypt the file**

This turns the full-file MAC check into a redundant verification. The key hash is essentially a **password verifier** stored in the header. This is a deliberate design choice (for UX — fast feedback on wrong password), but it **weakens** the security model vs. letting the MAC be the sole verifier. With deniability mode, this hash is not present, which is correct.

### 5. Nonce reuse risk in temporary zip encryption

Lines 1199-1217: The temporary zip file is encrypted with ChaCha20 using a random key/nonce, but `tempZipCipherW` and `tempZipCipherR` are created from the **same key and nonce**. This is correct for a write-then-read pattern (they maintain independent counters that traverse the same keystream). ✅

### 6. `panic()` as error handling in crypto code

Throughout the crypto path, errors trigger `panic()` (lines 1201-1216, 1328, 1641-1663, etc.). In a GUI application, an unrecovered panic kills the process and can leave temporary files (`.incomplete`, `.tmp`) on disk containing partial plaintext. These should be caught with deferred cleanup.

### 7. File deletion is not secure

The "Delete files" option (line 2548-2558) uses `os.Remove()` / `os.RemoveAll()`, which is a standard filesystem unlink — **not** a secure wipe. The original plaintext remains recoverable from disk with forensic tools. For a tool that offers "deniability" mode, this is a significant gap. No overwrite-before-delete is performed.

---

## 🟡 Software Engineering Issues

### 8. Everything is global mutable state

The entire application state lives in ~60 package-level `var` declarations (lines 62-156). The `work()` function reads and writes these globals, as does the UI code and the goroutines. There are **no mutexes** protecting concurrent access — the UI goroutine and the `work()` goroutine race on variables like `working`, `progress`, `popupStatus`, `mainStatus`, etc.

> [!IMPORTANT]
> This is a **data race**. `working` is read by the UI thread and written by worker goroutines without synchronization. Go's race detector would flag this. In practice it *mostly works* because of how the giu event loop serializes, but it's undefined behavior per the Go memory model.

### 9. Single 2,900-line file

The entire application — UI layout, crypto logic, file I/O, zip handling, Reed-Solomon encoding, progress tracking, state management — lives in one file. This makes the code extremely difficult to audit, test, or maintain. The cryptographic core should be a separate, independently testable package.

### 10. Zero tests

There are no test files anywhere in the repository. For a **cryptographic tool**, this is a serious gap. There should be:
- Round-trip encrypt/decrypt tests
- Known-answer tests for the crypto primitives
- Edge case tests (empty files, huge files, split/recombine, RS encoding/decoding)
- Fuzzing for the header parser

### 11. Nil pointer dereference risks in error helpers

`insufficientSpace()`, `broken()`, and `cancel()` all call `.Close()` on their `*os.File` arguments (lines 2603-2631) without nil checks. Several call sites pass `nil` for one or both arguments (e.g., line 1528: `broken(nil, nil, ...)`). Calling `.Close()` on a nil `*os.File` will panic.

### 12. `unpackArchive` defers Close inside a loop

Line 2860: `defer fileInArchive.Close()` is inside a `for` loop over archive entries. The defer won't execute until the function returns, so **all file handles accumulate** until the entire archive is extracted. For a large archive with many files, this leaks file descriptors.

### 13. Integer overflow potential in split calculations

Line 2390: `chunkSize *= TiB` where `TiB = 1 << 40` and `chunkSize` is an `int` (from `strconv.Atoi`). On 64-bit systems `int` is 64-bit so this is fine, but the code doesn't validate the multiplication won't overflow.

### 14. The `encryptedZipReader.Read` swallows short reads

Lines 194-205: If `_r.Read()` returns `n > 0` *and* a non-nil error (which is valid per `io.Reader` contract — e.g., `n > 0, io.EOF`), the error is discarded when `n > 0`. The `if err == nil && n > 0` check misses this case, meaning the last chunk of data before EOF could be silently dropped.

### 15. Hardcoded magic numbers everywhere

- `524351` for window flags (line 319)
- `6`, `70`, `16384` for popup/input flags
- `789` for header size (line 1550)
- `309` for seek offset (line 2215)

These should be named constants.

---

## 🟢 Things Done Well

1. **Excellent algorithm choices**: XChaCha20, Argon2id, BLAKE2b, SHA3, Serpent, HKDF — all modern, well-regarded primitives
2. **Reed-Solomon error correction** as an option is a genuinely useful feature for archival
3. **Paranoid mode cascade** (Serpent-CTR → XChaCha20) adds defense-in-depth without breaking anything
4. **Constant-time comparison** (`subtle.ConstantTimeCompare`) used for key/keyfile hash verification (line 1905-1906)
5. **CSPRNG validation** — checking that `rand.Read` didn't return all zeros (lines 1207, 1652-1663) is a nice belt-and-suspenders check
6. **Nonce rekeying** at 60 GiB boundaries prevents counter overflow for very large files
7. **Temporary file naming** (`.incomplete` suffix) prevents partially-processed files from being mistaken for complete ones
8. **Encrypted temporary zip** — the temp zip used when combining multiple files is encrypted with a random key, preventing plaintext from touching disk during multi-file encryption
9. **Zip path traversal protection** in `unpackArchive` (line 2825: checking for `..`)
10. **Clean UI** — the giu-based interface is straightforward and well-organized

---

## Summary

| Area | Grade | Notes |
|------|-------|-------|
| Algorithm selection | **A** | Best-in-class choices throughout |
| Cryptographic construction | **B-** | Correct Encrypt-then-MAC, but full plaintext hits disk before verification |
| Key management | **B** | Proper KDF, but stored key hash enables offline attacks |
| Error handling | **C** | `panic()` throughout crypto code; nil deref risks |
| Code structure | **C-** | Single file, all global state, no separation of concerns |
| Testing | **F** | Zero tests for a cryptographic application |
| Concurrency safety | **D** | Data races on shared state between UI and worker goroutines |

The tool is **usable and reasonably secure for personal use**. The crypto is fundamentally sound — the right algorithms in roughly the right order. But for a project that brands itself as a serious encryption tool, the lack of tests, the write-plaintext-then-verify pattern, and the data races are concerning. The biggest practical risk is the "decrypt entire file before checking MAC" pattern, which could leak plaintext on crash.
