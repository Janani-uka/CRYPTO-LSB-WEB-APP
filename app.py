import os
import json
import hmac
import hashlib
import numpy as np
from flask import Flask, request, render_template, send_file
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image

# ----------------------------
# Flask setup
# ----------------------------
app = Flask(__name__)   # ✅ FIXED (_name_ → __name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.secret_key = "dev-secret"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ----------------------------
# AES-CBC + HMAC-SHA256
# ----------------------------
KDF_ITERS = 200_000

def _derive_keys(password: str, salt: bytes):
    dk = PBKDF2(password.encode("utf-8"), salt, dkLen=64, count=KDF_ITERS)
    return dk[:32], dk[32:]

def _pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def encrypt_package(password: str, data_bytes: bytes) -> bytes:
    salt = get_random_bytes(16)
    enc_key, mac_key = _derive_keys(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pad(data_bytes))
    core = salt + iv + ct
    tag = hmac.new(mac_key, core, hashlib.sha256).digest()
    return core + tag

def decrypt_package(password: str, payload: bytes) -> bytes:
    if len(payload) < 64:
        raise ValueError("Payload too short")
    salt, iv, tag = payload[:16], payload[16:32], payload[-32:]
    ct = payload[32:-32]
    enc_key, mac_key = _derive_keys(password, salt)
    core = salt + iv + ct
    calc_tag = hmac.new(mac_key, core, hashlib.sha256).digest()
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("HMAC verification failed (wrong password or corrupted image)")
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(ct))

# ----------------------------
# Bit helpers
# ----------------------------
def _bytes_to_bits(data: bytes):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Bit length not multiple of 8")
    return np.packbits(bits.astype(np.uint8)).tobytes()

# ----------------------------
# Deterministic permutation based on password
# - first 32 indices (0..31) reserved for length bits
# ----------------------------
def _perm_positions(password: str, capacity: int):
    seed = int.from_bytes(hashlib.sha256(password.encode()).digest()[:8], "big")
    rng = np.random.default_rng(seed)
    return rng.permutation(capacity)  # deterministic permutation

def encode_image(cover_path: str, password: str, payload: bytes, output_path: str):
    img = Image.open(cover_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten()
    capacity = flat.size

    length_bytes = len(payload).to_bytes(4, "big")
    len_bits = _bytes_to_bits(length_bytes)

    payload_bits = _bytes_to_bits(payload)
    total_payload_bits = len(payload_bits)

    if 32 + total_payload_bits > capacity:
        raise ValueError(f"Not enough capacity: need {32 + total_payload_bits} bits, capacity {capacity} bits")

    flat[:32] = (flat[:32] & 0xFE) | len_bits

    perm = _perm_positions(password, capacity)
    perm_filtered = perm[perm >= 32]
    chosen = perm_filtered[:total_payload_bits]

    flat[chosen] = (flat[chosen] & 0xFE) | payload_bits

    new_pixels = flat.reshape(pixels.shape)
    # ✅ FIXED: Removed deprecated 'mode' argument
    Image.fromarray(new_pixels.astype(np.uint8)).save(output_path, "PNG")

def decode_image(stego_path: str, password: str) -> bytes:
    img = Image.open(stego_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten()
    capacity = flat.size

    if capacity < 32:
        raise ValueError("Image too small to hold data")

    len_bits = (flat[:32] & 1).astype(np.uint8)
    payload_len = int.from_bytes(_bits_to_bytes(len_bits), "big")

    if payload_len <= 0 or payload_len > (capacity - 32) // 8:
        raise ValueError("⚠ Wrong password or no hidden data found in this image")

    total_payload_bits = payload_len * 8
    perm = _perm_positions(password, capacity)
    perm_filtered = perm[perm >= 32]
    chosen = perm_filtered[:total_payload_bits]

    payload_bits = (flat[chosen] & 1).astype(np.uint8)
    return _bits_to_bytes(payload_bits)

# ----------------------------
# Flask routes
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    cover = request.files.get("cover")
    secret_file = request.files.get("secret_file")
    secret_message = request.form.get("secret_message", "")
    password = request.form.get("password", "")

    if not cover or not password.strip():
        return render_template("result.html", message="❌ Missing cover image or password!")

    cover_filename = cover.filename
    cover_path = os.path.join(app.config["UPLOAD_FOLDER"], cover_filename)
    cover.save(cover_path)

    img = Image.open(cover_path).convert("RGB")
    png_cover = os.path.splitext(cover_path)[0] + ".png"
    img.save(png_cover, "PNG")
    cover_path = png_cover

    if secret_file and secret_file.filename:
        file_bytes = secret_file.read()
        file_info = {"type": "file", "filename": secret_file.filename}
        package = json.dumps(file_info).encode() + b"::META::" + file_bytes
    elif secret_message.strip():
        file_info = {"type": "text"}
        package = json.dumps(file_info).encode() + b"::META::" + secret_message.encode()
    else:
        return render_template("result.html", message="❌ Provide a secret message or file!")

    try:
        payload = encrypt_package(password, package)
        output_path = os.path.join(app.config["UPLOAD_FOLDER"], "stego.png")
        encode_image(cover_path, password, payload, output_path)
        return send_file(output_path, as_attachment=True, download_name="stego.png")
    except Exception as e:
        return render_template("result.html", message=f"❌ Error during encryption: {str(e)}")

@app.route("/decrypt", methods=["POST"])
def decrypt():
    stego = request.files.get("stego")
    password = request.form.get("password", "")

    if not stego or not password.strip():
        return render_template("result.html", message="❌ Missing stego image or password!")

    stego_path = os.path.join(app.config["UPLOAD_FOLDER"], stego.filename)
    stego.save(stego_path)

    try:
        payload = decode_image(stego_path, password)
        decrypted = decrypt_package(password, payload)

        if b"::META::" in decrypted:
            meta_json, content = decrypted.split(b"::META::", 1)
            meta = json.loads(meta_json.decode("utf-8"))
            if meta.get("type") == "file":
                safe_name = meta.get("filename", "secret.bin")
                output_file = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
                with open(output_file, "wb") as f:
                    f.write(content)
                return send_file(output_file, as_attachment=True, download_name=safe_name)
            else:
                return render_template("result.html", message=f"✅ Secret Message: {content.decode(errors='ignore')}")
        else:
            return render_template("result.html", message="⚠ No valid metadata found.")
    except Exception as e:
        return render_template("result.html", message=f"❌ Error during decryption: {str(e)}")

@app.route("/send", methods=["POST"])
def send():
    """
    Dummy /send endpoint.
    In a real app, this could integrate with email/FTP/cloud API.
    For now, just confirms success.
    """
    return render_template("result.html", message="📤 Stego image sent successfully (demo mode)!")

# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":   # ✅ FIXED
    app.run(debug=True)
