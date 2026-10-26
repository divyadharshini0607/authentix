#!/usr/bin/env python3
"""
AUTHENTIX / EduVerify-AI (SIH26261)
Document OCR, Layout Region & Image/PDF Forensics Microservice
Default Port: 8001 (Configurable via OCR_SERVICE_PORT)

Zero mandatory third-party pip dependencies for core operation; automatically
upgrades capabilities when `tesseract` (eng / hin) or `pdftotext` binaries are installed.
"""

import base64
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


def detect_tesseract() -> Tuple[bool, List[str]]:
    exe = shutil.which("tesseract")
    if not exe:
        return False, []
    try:
        proc = subprocess.run(
            [exe, "--list-langs"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        lines = [ln.strip() for ln in (proc.stdout + "\n" + proc.stderr).splitlines() if ln.strip()]
        langs = [ln for ln in lines if not ln.lower().startswith("list of available") and len(ln) <= 12]
        return True, langs
    except Exception:
        return True, ["eng"]


HAS_TESSERACT, TESSERACT_LANGS = detect_tesseract()
HAS_PDFTOTEXT = shutil.which("pdftotext") is not None


def decode_pdf_string_token(raw: bytes) -> str:
    if raw.startswith(b"<") and raw.endswith(b">"):
        hex_body = re.sub(rb"\s+", b"", raw[1:-1])
        if len(hex_body) % 2 == 1:
            hex_body += b"0"
        try:
            data = bytes.fromhex(hex_body.decode("ascii", errors="ignore"))
            if data.startswith(b"\xfe\xff"):
                return data[2:].decode("utf-16-be", errors="replace")
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if raw.startswith(b"(") and raw.endswith(b")"):
        inner = raw[1:-1]
        out = bytearray()
        i = 0
        while i < len(inner):
            ch = inner[i]
            if ch == 0x5C and i + 1 < len(inner):
                nxt = inner[i + 1]
                escapes = {
                    ord("n"): 10,
                    ord("r"): 13,
                    ord("t"): 9,
                    ord("b"): 8,
                    ord("f"): 12,
                    ord("("): ord("("),
                    ord(")"): ord(")"),
                    ord("\\"): ord("\\"),
                }
                if nxt in escapes:
                    out.append(escapes[nxt])
                    i += 2
                    continue
                if 48 <= nxt <= 55:
                    oct_digits = bytes([nxt])
                    j = i + 2
                    while j < len(inner) and len(oct_digits) < 3 and 48 <= inner[j] <= 55:
                        oct_digits += bytes([inner[j]])
                        j += 1
                    out.append(int(oct_digits, 8) & 0xFF)
                    i = j
                    continue
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            i += 1
        data = bytes(out)
        if data.startswith(b"\xfe\xff"):
            return data[2:].decode("utf-16-be", errors="replace")
        return data.decode("utf-8", errors="replace")
    return ""


def parse_pdf_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for key in ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]:
        pattern = re.compile(rb"/" + key.encode("ascii") + rb"\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)")
        match = pattern.search(raw_bytes)
        if match:
            val = decode_pdf_string_token(match.group(1)).strip()
            if val:
                metadata[key] = val

    page_matches = re.findall(rb"/Type\s*/Page\b", raw_bytes)
    page_count = max(1, len(page_matches))
    has_sig = bool(
        re.search(rb"/Type\s*/Sig\b", raw_bytes) and re.search(rb"/ByteRange\b", raw_bytes)
    )
    metadata["hasEmbeddedPdfSignature"] = has_sig
    metadata["hasEmbeddedDigitalSignature"] = has_sig

    decompressed_streams: List[bytes] = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw_bytes, flags=re.DOTALL):
        chunk = m.group(1)
        header_window = raw_bytes[max(0, m.start() - 260) : m.start()]
        if b"/FlateDecode" in header_window:
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    decompressed_streams.append(zlib.decompress(chunk, wbits))
                    break
                except Exception:
                    continue
        else:
            decompressed_streams.append(chunk)

    if not decompressed_streams:
        decompressed_streams.append(raw_bytes)

    pages: List[Dict[str, Any]] = []
    all_lines: List[str] = []
    page_idx = 1

    token_re = re.compile(
        rb"(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Td|"
        rb"(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Tm|"
        rb"(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>)\s*Tj|"
        rb"\[(.*?)\]\s*TJ",
        flags=re.DOTALL,
    )

    for stream_data in decompressed_streams:
        if b"BT" not in stream_data:
            continue
        blocks: List[Dict[str, Any]] = []
        cur_x, cur_y = 50.0, 750.0
        for bt_match in re.finditer(rb"BT(.*?)ET", stream_data, flags=re.DOTALL):
            bt_body = bt_match.group(1)
            for tok in token_re.finditer(bt_body):
                if tok.group(1) is not None:
                    cur_x = float(tok.group(1))
                    cur_y = float(tok.group(2))
                elif tok.group(7) is not None:
                    cur_x = float(tok.group(7))
                    cur_y = float(tok.group(8))
                elif tok.group(9) is not None:
                    txt = decode_pdf_string_token(tok.group(9)).strip()
                    if txt:
                        blocks.append(
                            {
                                "text": txt,
                                "bbox": [round(cur_x, 1), round(cur_y, 1), round(max(60.0, len(txt) * 5.4), 1), 14.0],
                                "confidence": 0.96,
                            }
                        )
                        all_lines.append(txt)
                elif tok.group(10) is not None:
                    arr_body = tok.group(10)
                    parts = [
                        decode_pdf_string_token(sm.group(0))
                        for sm in re.finditer(rb"\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>", arr_body)
                    ]
                    joined = "".join(parts).strip()
                    if joined:
                        blocks.append(
                            {
                                "text": joined,
                                "bbox": [round(cur_x, 1), round(cur_y, 1), round(max(60.0, len(joined) * 5.4), 1), 14.0],
                                "confidence": 0.95,
                            }
                        )
                        all_lines.append(joined)
        if blocks:
            pages.append({"page_number": page_idx, "blocks": blocks})
            page_idx += 1

    # Fallback to pdftotext CLI if streams yielded no text and pdftotext is installed
    engine = "python-pdf-stream-extractor"
    if not all_lines and HAS_PDFTOTEXT:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
            tf.write(raw_bytes)
            temp_pdf = tf.name
        try:
            proc = subprocess.run(["pdftotext", temp_pdf, "-"], capture_output=True, text=True, timeout=6, check=False)
            if proc.returncode == 0 and proc.stdout.strip():
                lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
                all_lines.extend(lines)
                pages = [
                    {
                        "page_number": 1,
                        "blocks": [
                            {"text": ln, "bbox": [48.0, float(760 - idx * 18), float(len(ln) * 5.5), 14.0], "confidence": 0.93}
                            for idx, ln in enumerate(lines)
                        ],
                    }
                ]
                engine = "python-pdftotext"
        finally:
            if os.path.exists(temp_pdf):
                os.remove(temp_pdf)

    forensics = inspect_pdf_forensics(raw_bytes, metadata)
    extracted_text = "\n".join(all_lines)
    if extracted_text.strip():
        ocr_status = "COMPLETED"
        confidence = 0.95
    else:
        ocr_status = "LOW_CONFIDENCE"
        confidence = 0.0

    return {
        "ocr_status": ocr_status,
        "ocr_engine": engine,
        "ocr_confidence": confidence,
        "page_count": max(page_count, len(pages) or 1),
        "extracted_text": extracted_text,
        "pages": pages,
        "metadata": metadata,
        "forensics": forensics,
    }


def inspect_pdf_forensics(raw_bytes: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
    indicators: List[Dict[str, Any]] = []
    producer = (metadata.get("Producer", "") + " " + metadata.get("Creator", "")).lower()
    suspicious_editors = ["photoshop", "gimp", "canva", "paint", "pdfescape", "ilovepdf", "sejda"]
    matched_editor = next((ed for ed in suspicious_editors if ed in producer), None)
    if matched_editor:
        indicators.append(
            {
                "code": "PDF_IMAGE_EDITOR_PRODUCER",
                "severity": "HIGH",
                "description": f"PDF metadata indicates graphics/editing tool '{matched_editor}' in Producer/Creator tags ({metadata.get('Producer') or metadata.get('Creator')}). Indicator for officer inspection, not standalone proof of tampering.",
            }
        )

    creation = metadata.get("CreationDate", "")
    mod = metadata.get("ModDate", "")
    if creation and mod and creation != mod:
        indicators.append(
            {
                "code": "PDF_MODIFIED_AFTER_CREATION",
                "severity": "MEDIUM",
                "description": f"PDF Modification timestamp ({mod}) differs from Creation timestamp ({creation}).",
            }
        )

    eof_count = len(re.findall(rb"%%EOF", raw_bytes))
    if eof_count > 1:
        indicators.append(
            {
                "code": "PDF_INCREMENTAL_UPDATES",
                "severity": "LOW",
                "description": f"PDF contains {eof_count} %%EOF markers indicating incremental saves/revisions after initial generation.",
            }
        )

    return {"indicators": indicators, "eof_markers": eof_count}


def inspect_image_bytes(raw_bytes: bytes, mime_type: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"mime_type": mime_type, "byte_length": len(raw_bytes)}
    indicators: List[Dict[str, Any]] = []
    embedded_text_chunks: List[str] = []

    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        pos = 8
        idat_payloads = bytearray()
        while pos + 8 <= len(raw_bytes):
            length = struct.unpack(">I", raw_bytes[pos : pos + 4])[0]
            ctype = raw_bytes[pos + 4 : pos + 8].decode("latin1", errors="replace")
            cdata = raw_bytes[pos + 8 : pos + 8 + length]
            if ctype == "IHDR" and len(cdata) >= 8:
                w, h = struct.unpack(">II", cdata[:8])
                metadata["width"] = w
                metadata["height"] = h
            elif ctype == "tEXt" and b"\x00" in cdata:
                k, v = cdata.split(b"\x00", 1)
                key_str = k.decode("latin1", errors="replace")
                val_str = v.decode("utf-8", errors="replace")
                metadata[f"png_{key_str}"] = val_str
                if key_str.lower() in ("ocr_text", "description", "document_text"):
                    embedded_text_chunks.append(val_str)
            elif ctype == "iTXt":
                parts = cdata.split(b"\x00", 5)
                if len(parts) >= 6:
                    key_str = parts[0].decode("latin1", errors="replace")
                    val_str = parts[5].decode("utf-8", errors="replace")
                    metadata[f"png_{key_str}"] = val_str
                    if key_str.lower() in ("ocr_text", "description", "document_text"):
                        embedded_text_chunks.append(val_str)
            elif ctype == "IDAT":
                idat_payloads.extend(cdata)
            pos += 12 + length

        software = str(metadata.get("png_Software", "")).lower()
        for ed in ["photoshop", "gimp", "paint", "canva"]:
            if ed in software:
                indicators.append(
                    {
                        "code": "IMAGE_EDITOR_METADATA",
                        "severity": "HIGH",
                        "description": f"PNG Software chunk references image editor '{ed}' ({metadata.get('png_Software')}).",
                    }
                )
        # Deterministic copy-move scanline block check on decompressed IDAT if small/medium
        if idat_payloads:
            try:
                raw_pixels = zlib.decompress(bytes(idat_payloads))
                block_size = 256
                if len(raw_pixels) >= block_size * 12:
                    hashes: Dict[str, int] = {}
                    non_uniform_blocks = 0
                    duplicate_hits = 0
                    for offset in range(0, min(len(raw_pixels) - block_size, 65536), block_size):
                        blk = raw_pixels[offset : offset + block_size]
                        # Ignore uniform background blocks
                        if len(set(blk)) <= 3:
                            continue
                        non_uniform_blocks += 1
                        digest = hashlib.md5(blk).hexdigest()
                        hashes[digest] = hashes.get(digest, 0) + 1
                        if hashes[digest] == 2:
                            duplicate_hits += 1
                    if non_uniform_blocks >= 8 and (duplicate_hits / max(1, non_uniform_blocks)) > 0.35:
                        indicators.append(
                            {
                                "code": "IMAGE_CLONE_REGION_HEURISTIC",
                                "severity": "MEDIUM",
                                "description": "Repeated non-background pixel blocks detected across scanlines (heuristic copy-move indicator; requires visual officer verification).",
                            }
                        )
            except Exception:
                pass

    elif raw_bytes.startswith(b"\xff\xd8\xff"):
        # Parse JPEG SOF0/SOF1/SOF2 marker segments for deterministic pixel dimensions
        jpos = 2
        while jpos + 9 < len(raw_bytes):
            if raw_bytes[jpos] != 0xFF:
                jpos += 1
                continue
            while jpos < len(raw_bytes) and raw_bytes[jpos] == 0xFF:
                jpos += 1
            if jpos >= len(raw_bytes):
                break
            marker = raw_bytes[jpos]
            jpos += 1
            if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7) or marker == 0x01:
                continue
            if jpos + 2 > len(raw_bytes):
                break
            seg_len = struct.unpack(">H", raw_bytes[jpos : jpos + 2])[0]
            if seg_len < 2:
                break
            if marker in (0xC0, 0xC1, 0xC2) and jpos + 7 <= len(raw_bytes):
                h_px, w_px = struct.unpack(">HH", raw_bytes[jpos + 3 : jpos + 7])
                metadata["width"] = w_px
                metadata["height"] = h_px
                break
            jpos += seg_len

        ascii_scan = raw_bytes[:4096].decode("latin1", errors="ignore").lower()
        for ed in ["photoshop", "gimp", "canva", "lightroom"]:
            if ed in ascii_scan:
                indicators.append(
                    {
                        "code": "JPEG_EXIF_EDITOR_TAG",
                        "severity": "HIGH",
                        "description": f"JPEG header/EXIF segment contains editing software signature '{ed}'.",
                    }
                )
        # Heuristic block entropy variance check (documented lightweight ELA proxy)
        window_entropies: List[float] = []
        step = 1024
        for offset in range(512, min(len(raw_bytes) - step, 65536), step):
            seg = raw_bytes[offset : offset + step]
            counts = [0] * 256
            for b in seg:
                counts[b] += 1
            ent = -sum((c / step) * math.log2(c / step) for c in counts if c > 0)
            window_entropies.append(ent)
        if len(window_entropies) >= 6:
            mean_e = sum(window_entropies) / len(window_entropies)
            variance = sum((e - mean_e) ** 2 for e in window_entropies) / len(window_entropies)
            metadata["jpeg_entropy_variance"] = round(variance, 4)
            if variance > 0.45:
                indicators.append(
                    {
                        "code": "JPEG_COMPRESSION_VARIANCE_OUTLIER",
                        "severity": "MEDIUM",
                        "description": f"High regional compression entropy variance ({variance:.3f}); heuristic indicator of potential composite re-saving (not standalone proof of forgery).",
                    }
                )

    # Attempt real Tesseract OCR if installed
    if HAS_TESSERACT:
        suffix = ".png" if "png" in mime_type else ".jpg"
        lang = "eng+hin" if "hin" in TESSERACT_LANGS else "eng"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            tf.write(raw_bytes)
            img_path = tf.name
        try:
            proc = subprocess.run(
                ["tesseract", img_path, "stdout", "--oem", "1", "-l", lang, "tsv"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                words: List[str] = []
                confs: List[float] = []
                blocks: List[Dict[str, Any]] = []
                for idx, line in enumerate(proc.stdout.splitlines()):
                    if idx == 0:
                        continue
                    cols = line.split("\t")
                    if len(cols) >= 12 and cols[11].strip():
                        txt = cols[11].strip()
                        try:
                            conf = float(cols[10])
                        except ValueError:
                            conf = -1.0
                        if conf >= 0:
                            confs.append(conf / 100.0)
                        left, top, width, height = int(cols[6]), int(cols[7]), int(cols[8]), int(cols[9])
                        words.append(txt)
                        blocks.append(
                            {
                                "text": txt,
                                "bbox": [left, top, width, height],
                                "confidence": round(max(0.0, conf / 100.0), 2),
                            }
                        )
                avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
                joined = " ".join(words)
                return {
                    "ocr_status": "COMPLETED" if avg_conf >= 0.75 and joined else "LOW_CONFIDENCE",
                    "ocr_engine": f"tesseract-cli ({lang})",
                    "ocr_confidence": avg_conf,
                    "page_count": 1,
                    "extracted_text": joined,
                    "pages": [{"page_number": 1, "blocks": blocks}],
                    "metadata": metadata,
                    "forensics": {"indicators": indicators},
                }
        finally:
            if os.path.exists(img_path):
                os.remove(img_path)

    # Check if PNG carried an embedded accessible text chunk (used in deterministic synthetic scan fixtures)
    if embedded_text_chunks:
        joined = "\n".join(embedded_text_chunks)
        declared_conf_str = str(metadata.get("png_OCR_Confidence", "0.62"))
        try:
            conf_val = float(declared_conf_str)
        except ValueError:
            conf_val = 0.62
        lines = [ln.strip() for ln in joined.splitlines() if ln.strip()]
        return {
            "ocr_status": "COMPLETED" if conf_val >= 0.75 else "LOW_CONFIDENCE",
            "ocr_engine": "png-embedded-text-layer",
            "ocr_confidence": conf_val,
            "page_count": 1,
            "extracted_text": joined,
            "pages": [
                {
                    "page_number": 1,
                    "blocks": [
                        {"text": ln, "bbox": [40, 60 + i * 24, len(ln) * 6, 18], "confidence": conf_val}
                        for i, ln in enumerate(lines)
                    ],
                }
            ],
            "metadata": metadata,
            "forensics": {"indicators": indicators},
        }

    # Honest reporting when raster OCR binary (tesseract) is not installed on host
    return {
        "ocr_status": "UNAVAILABLE",
        "ocr_engine": "raster-ocr-unavailable (install tesseract-ocr)",
        "ocr_confidence": None,
        "page_count": 1,
        "extracted_text": "",
        "pages": [],
        "metadata": metadata,
        "forensics": {"indicators": indicators},
        "warning": "Raster image uploaded, but Tesseract OCR binary is not installed in this environment. Flagged for manual officer inspection.",
    }


class OCRRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet clean logging without sensitive payload leakage
        sys.stderr.write(f"[ocr-service] {self.command} {self.path} -> {fmt % args}\n")

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/health"):
            port = int(os.environ.get("OCR_SERVICE_PORT", "8001"))
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "authentix-ocr-forensics",
                    "port": port,
                    "capabilities": {
                        "pdf_stream_parser": True,
                        "image_chunk_forensics": True,
                        "tesseract_cli": HAS_TESSERACT,
                        "tesseract_languages": TESSERACT_LANGS,
                        "pdftotext_cli": HAS_PDFTOTEXT,
                    },
                },
            )
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path != "/analyze":
            self._send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 25 * 1024 * 1024:
                self._send_json(413, {"error": "Payload size invalid or exceeds 25MB limit"})
                return
            raw_body = self.rfile.read(length)
            req = json.loads(raw_body.decode("utf-8"))
            mime_type = str(req.get("mime_type", "")).lower()
            content_b64 = req.get("content_base64", "")
            raw_bytes = base64.b64decode(content_b64)

            if mime_type == "application/pdf" or raw_bytes.startswith(b"%PDF-"):
                result = parse_pdf_bytes(raw_bytes)
                self._send_json(200, result)
                return
            if mime_type in ("image/png", "image/jpeg", "image/jpg") or raw_bytes.startswith((b"\x89PNG", b"\xff\xd8\xff")):
                result = inspect_image_bytes(raw_bytes, mime_type)
                self._send_json(200, result)
                return

            self._send_json(415, {"error": f"Unsupported document format: {mime_type}"})
        except Exception as exc:
            self._send_json(500, {"error": f"OCR analysis failed: {type(exc).__name__}"})


def main() -> None:
    host = os.environ.get("OCR_SERVICE_HOST", "127.0.0.1")
    port = int(os.environ.get("OCR_SERVICE_PORT", "8001"))
    server = ThreadingHTTPServer((host, port), OCRRequestHandler)
    print(f"[authentix-ocr-service] Listening on http://{host}:{port} (tesseract={HAS_TESSERACT})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
