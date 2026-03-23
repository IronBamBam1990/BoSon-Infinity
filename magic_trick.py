#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MAGIC TRICK: Upload files (txt/pdf) -> AI-Compact (.dtcp) ~ "100MB -> 1MB" style
- UI: http://127.0.0.1:5005
- Output: dataset.dtcp (binary), commit.json (proof hashes)
- Works offline. Optional PDF extract via PyMuPDF (fitz) or pdfminer.six.

Install:
  pip install flask
Optional for PDF:
  pip install pymupdf
  # or:
  pip install pdfminer.six
Run:
  python magic_trick.py
"""

import os
import io
import re
import json
import time
import zlib
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from flask import Flask, request, send_file, Response

APP_HOST = "127.0.0.1"
APP_PORT = 5005

# -----------------------------
# "Magic" compression settings
# -----------------------------
FEATURE_DIM = 1024         # 256/512/1024/2048. Bigger = more info, bigger pack
TOKENS_PER_CHUNK = 900     # chunk size (approx)
TOPK_TOKENS = 500          # keep only top-K tokens per chunk (smaller pack)
INT8_CLIP = 127            # int8 clip for counts
ZLIB_LEVEL = 9             # compression level

# If you *really* want to chase ~1MB aggressively:
# FEATURE_DIM=512, TOPK_TOKENS=200, TOKENS_PER_CHUNK=1200
# (less info, smaller file)

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Boson Infinity — AI Data Magic Trick</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; max-width: 900px; }
    .box { border: 2px dashed #777; padding: 24px; border-radius: 14px; }
    .row { margin: 14px 0; }
    input[type=file] { width: 100%; }
    button { padding: 12px 18px; font-size: 16px; cursor:pointer; }
    .hint { color:#444; font-size: 14px; }
    code { background:#f2f2f2; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>AI-Compression (100MB → ~1MB vibe)</h1>
  <p class="hint">
    Upload TXT/PDF. We generate <b>AI-compact</b> dataset for fast training/RAG, plus hashes for blockchain proof.
    This is semantic packing (not lossless ZIP).
  </p>

  <div class="box">
    <form method="POST" action="/compress" enctype="multipart/form-data">
      <div class="row">
        <label><b>Files</b> (txt/pdf):</label><br/>
        <input type="file" name="files" multiple required />
      </div>

      <div class="row">
        <label><b>Target style</b>:</label><br/>
        <select name="profile">
          <option value="RAG_1MB">RAG Ultra-Fast (~1MB target)</option>
          <option value="TRAIN_BALANCED" selected>Training Balanced</option>
          <option value="MORE_INFO">More Info (bigger output)</option>
        </select>
      </div>

      <div class="row">
        <button type="submit">✨ Compress for AI</button>
      </div>

      <div class="row hint">
        After compression you will get:
        <ul>
          <li><code>dataset.dtcp</code> (binary compact)</li>
          <li><code>commit.json</code> (hash proof: original + compact)</li>
        </ul>
      </div>
    </form>
  </div>

  <p class="hint">
    Tip: If PDFs are scanned images, install OCR pipeline later — this MVP extracts text from real-text PDFs.
  </p>
</body>
</html>
"""

# -----------------------------
# Helpers
# -----------------------------

def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()

def norm_text(s: str) -> str:
    # aggressive normalize (shrinks + helps hashing)
    s = s.replace("\u00a0", " ")
    s = s.lower()
    s = re.sub(r"[^\w\s\-\.]+", " ", s, flags=re.UNICODE)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def tokenize(s: str) -> List[str]:
    # simple tokenizer: words + numbers
    return re.findall(r"[a-z0-9][a-z0-9\-\._]{1,}", s)

def stable_hash_token(tok: str) -> int:
    # stable 64-bit from sha256(token)
    h = hashlib.sha256(tok.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "little", signed=False)

def try_extract_pdf_text(data: bytes) -> str:
    # Prefer PyMuPDF (fitz). If not installed, try pdfminer.six.
    try:
        import fitz  # pymupdf
        doc = fitz.open(stream=data, filetype="pdf")
        out = []
        for page in doc:
            out.append(page.get_text("text") or "")
        return "\n".join(out)
    except Exception:
        pass

    try:
        from pdfminer.high_level import extract_text
        return extract_text(io.BytesIO(data)) or ""
    except Exception:
        # no PDF extractor available
        return ""

def extract_text_from_file(filename: str, data: bytes) -> str:
    ext = os.path.splitext(filename.lower())[1]
    if ext in [".txt", ".md", ".csv", ".json", ".log"]:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("latin-1", errors="ignore")

    if ext == ".pdf":
        return try_extract_pdf_text(data)

    # fallback: attempt decode as text
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""

@dataclass
class Profile:
    name: str
    feature_dim: int
    tokens_per_chunk: int
    topk_tokens: int

def profile_params(profile_name: str) -> Profile:
    if profile_name == "RAG_1MB":
        return Profile("RAG_1MB", feature_dim=512, tokens_per_chunk=1200, topk_tokens=200)
    if profile_name == "MORE_INFO":
        return Profile("MORE_INFO", feature_dim=2048, tokens_per_chunk=700, topk_tokens=1200)
    return Profile("TRAIN_BALANCED", feature_dim=1024, tokens_per_chunk=900, topk_tokens=500)

# -----------------------------
# AI-Compact pack format
# -----------------------------
# dtcp binary layout (simple):
# [magic 4 bytes] = b"DTCP"
# [version u16]   = 1
# [feature_dim u16]
# [chunks u32]
# [for each chunk]:
#   [token_count u16]  (# tokens kept)
#   [pairs ...]        repeated token_count times:
#       [index u16]    (feature index)
#       [value i8]     (int8 count)
# Then zlib compress whole body.

def build_compact(tokens: List[str], prof: Profile) -> Tuple[bytes, dict]:
    dim = prof.feature_dim
    tpc = prof.tokens_per_chunk
    topk = prof.topk_tokens

    # split into chunks
    chunks = []
    for i in range(0, len(tokens), tpc):
        chunks.append(tokens[i:i+tpc])

    body = io.BytesIO()
    # header
    body.write(b"DTCP")
    body.write((1).to_bytes(2, "little"))               # version u16
    body.write((dim).to_bytes(2, "little"))             # feature_dim u16
    body.write((len(chunks)).to_bytes(4, "little"))     # chunks u32

    total_kept = 0
    for ch in chunks:
        # count tokens -> feature bins
        counts = {}
        for tok in ch:
            idx = stable_hash_token(tok) % dim
            counts[idx] = counts.get(idx, 0) + 1

        # keep top-k by count
        items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:topk]
        total_kept += len(items)

        # write chunk
        body.write((len(items)).to_bytes(2, "little"))  # token_count u16
        for idx, val in items:
            if val > INT8_CLIP:
                val = INT8_CLIP
            body.write((idx & 0xFFFF).to_bytes(2, "little"))  # index u16
            body.write(int(val).to_bytes(1, "little", signed=True))  # value i8

    raw_body = body.getvalue()
    packed = zlib.compress(raw_body, level=ZLIB_LEVEL)

    meta = {
        "dtcp_version": 1,
        "profile": prof.name,
        "feature_dim": dim,
        "tokens_per_chunk": tpc,
        "topk_tokens": topk,
        "chunks": len(chunks),
        "tokens_total": len(tokens),
        "pairs_total": total_kept,
        "raw_bytes": len(raw_body),
        "packed_bytes": len(packed),
    }
    return packed, meta

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)

@app.get("/")
def home():
    return Response(HTML, mimetype="text/html")

@app.post("/compress")
def compress():
    files = request.files.getlist("files")
    if not files:
        return "no_files", 400

    prof = profile_params(request.form.get("profile", "TRAIN_BALANCED"))

    # read + concat text
    original_concat = io.BytesIO()
    texts = []
    for f in files:
        data = f.read()
        original_concat.write(data)
        txt = extract_text_from_file(f.filename or "file", data)
        if txt:
            texts.append(txt)

    all_original_bytes = original_concat.getvalue()
    original_sha = sha512_hex(all_original_bytes)

    merged_text = "\n".join(texts)
    merged_text_norm = norm_text(merged_text)
    toks = tokenize(merged_text_norm)

    packed, meta = build_compact(toks, prof)
    packed_sha = sha512_hex(packed)

    commit = {
        "created_at": int(time.time()),
        "original_sha512": original_sha,
        "packed_sha512": packed_sha,
        "original_bytes": len(all_original_bytes),
        "packed_bytes": len(packed),
        "meta": meta,
        "note": "Store packed blob off-chain (ipfs/s3/http). Put this commit on-chain as Tx.Data.",
    }

    # Build a zip-like multi file response: simplest = return a JSON with base64? (but big)
    # Better: return a small HTML with download links kept in memory for this run.
    # We'll store in temp directory.
    outdir = os.path.join(os.path.dirname(__file__), ".dtcp_out")
    os.makedirs(outdir, exist_ok=True)

    dtcp_path = os.path.join(outdir, "dataset.dtcp")
    commit_path = os.path.join(outdir, "commit.json")

    with open(dtcp_path, "wb") as w:
        w.write(packed)
    with open(commit_path, "w", encoding="utf-8") as w:
        json.dump(commit, w, indent=2)

    page = f"""
    <html><head><meta charset="utf-8"><title>Done</title></head><body style="font-family:Arial;margin:40px;max-width:900px;">
    <h2>✅ Done</h2>
    <p><b>Original:</b> {len(all_original_bytes):,} bytes<br/>
       <b>Compact:</b> {len(packed):,} bytes<br/>
       <b>Ratio:</b> {(len(all_original_bytes) / max(1,len(packed))):.2f}x
    </p>
    <p><b>original_sha512</b>: <code>{original_sha}</code><br/>
       <b>packed_sha512</b>: <code>{packed_sha}</code>
    </p>
    <h3>Downloads</h3>
    <ul>
      <li><a href="/download/dataset">dataset.dtcp</a></li>
      <li><a href="/download/commit">commit.json</a></li>
    </ul>

    <h3>How to put on blockchain (Boson)</h3>
    <p class="hint">
      Use a TX with <code>type="data_commit"</code> and <code>data</code> set to the JSON from commit.json (or its hash + CID).
      Keep the real <code>dataset.dtcp</code> off-chain (IPFS/S3/HTTP) and store a link/CID in the TX data.
    </p>
    <p><a href="/">← back</a></p>
    </body></html>
    """
    return Response(page, mimetype="text/html")

@app.get("/download/dataset")
def dl_dataset():
    outdir = os.path.join(os.path.dirname(__file__), ".dtcp_out")
    path = os.path.join(outdir, "dataset.dtcp")
    if not os.path.exists(path):
        return "not_ready", 404
    return send_file(path, as_attachment=True, download_name="dataset.dtcp", mimetype="application/octet-stream")

@app.get("/download/commit")
def dl_commit():
    outdir = os.path.join(os.path.dirname(__file__), ".dtcp_out")
    path = os.path.join(outdir, "commit.json")
    if not os.path.exists(path):
        return "not_ready", 404
    return send_file(path, as_attachment=True, download_name="commit.json", mimetype="application/json")

if __name__ == "__main__":
    print(f"[MAGIC] open http://{APP_HOST}:{APP_PORT}")
    app.run(host=APP_HOST, port=APP_PORT, debug=False)
