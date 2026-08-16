# Template Temuan dan Writeup Keamanan

Gunakan file ini sebagai template untuk mencatat temuan pengujian keamanan. Dokumen ini diindeks ke dalam vector store RAG sebagai referensi analisis.

---

## Template: Bug Bounty Finding

### [Judul Temuan] - [Severity: Critical / High / Medium / Low / Info]

- Target: [Nama program / domain]
- Tanggal: [YYYY-MM-DD]
- Komponen: [Nama endpoint / file / parameter]

#### Deskripsi
[Jelaskan kerentanan yang ditemukan secara teknis]

#### Langkah Reproduksi
1. [Langkah 1]
2. [Langkah 2]
3. [Langkah 3]

#### Bukti Kode / PoC
```javascript
// Cuplikan kode atau payload di sini
```

#### Pola Deteksi / Signature
[Pola regex atau karakteristik kode untuk deteksi otomatis]

#### Referensi dan Catatan
[Catatan mitigasi atau referensi CWE/CVE terkait]

---

## Template: Custom Signature

### [Nama Signature]

- Severity: Critical / High / Medium / Low / Info
- Kategori: XSS / SQLi / SSRF / Secrets / IDOR / Deserialization

#### Pola Regex
```regex
[Pola regex di sini]
```

#### Contoh Kode Rentan
```javascript
[Contoh kode rentan]
```

#### Catatan False Positive
[Kondisi yang memicu false positive dan cara filternya]

---

## Struktur Folder Knowledge Base

```
knowledge/
├── owasp_top10.md
├── malware_js_patterns.md
├── secrets_patterns.md
├── cve/
├── writeups/
├── signatures/
└── targets/
```
