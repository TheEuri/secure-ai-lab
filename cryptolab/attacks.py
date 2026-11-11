"""Controlled attacks and statistical measurements against cipher variants.

* brute_force   - exhaustive search over a reduced key space, measured rate,
                  extrapolated to the real key space;
* avalanche     - differential test: flip one bit (plaintext or key) and
                  count changed output bits;
* sac_matrix    - Strict Avalanche Criterion per input/output bit pair;
* statistics    - byte histogram, chi-square vs uniform, entropy, serial
                  correlation and repeated blocks;
* frequency_attack_xor - ciphertext-only frequency analysis that recovers
                  a repeating XOR key;
* ecb_image_leak - renders ciphertext of an image to show pattern leakage.

Every function takes a seed so results are reproducible.
"""

import math
import random
import time

import numpy as np
from PIL import Image, ImageDraw
from scipy.stats import chi2

from cryptolab.cipher import BLOCK_BYTES, BlockCipher, get_variant

SAMPLE_TEXT_PT = (
    "A segurança da informação depende de três propriedades fundamentais: "
    "confidencialidade, integridade e disponibilidade. Um sistema criptográfico "
    "só protege os dados quando a chave permanece secreta e quando a saída não "
    "revela padrões da mensagem original. Neste laboratório, a equipe construiu "
    "uma cifra de blocos com substituição, permutação, mistura linear e operações "
    "de ou exclusivo com chaves de rodada. Em seguida, atacou a própria cifra com "
    "força bruta, análise diferencial e análise estatística, comparando versões "
    "fracas e fortes do mesmo algoritmo. O objetivo não é provar que a cifra é "
    "perfeita, mas medir com evidências o quanto ela resiste e onde ela falha. "
    "Quando uma mensagem é cifrada com uma chave curta e repetida, a frequência das "
    "letras do português continua visível no texto cifrado, e um analista paciente "
    "consegue recuperar a chave sem conhecer nenhuma parte do texto claro. Por isso "
    "as chaves precisam ser longas, aleatórias e renovadas a cada mensagem."
)

# relative frequency (%) of letters in Portuguese
_PT_FREQ = {
    "a": 14.6, "e": 12.6, "o": 10.7, "s": 7.8, "r": 6.5, "i": 6.2, "n": 5.0,
    "d": 5.0, "m": 4.7, "u": 4.6, "t": 4.3, "c": 3.9, "l": 2.8, "p": 2.5,
    "v": 1.7, "g": 1.3, "h": 1.3, "q": 1.2, "b": 1.0, "f": 1.0, "z": 0.5,
    "j": 0.4, "x": 0.2, "k": 0.02, "w": 0.01, "y": 0.01,
}
_WEIGHTS = np.full(256, -10.0)
for ch, f in _PT_FREQ.items():
    _WEIGHTS[ord(ch)] = math.log(f + 0.1) + 3
    _WEIGHTS[ord(ch.upper())] = 1.0
_WEIGHTS[ord(" ")] = math.log(18) + 3
for ch in ",.:;-":
    _WEIGHTS[ord(ch)] = 1.0
for b in range(0x80, 0xC0):  # UTF-8 continuation bytes (accents)
    _WEIGHTS[b] = 0.5
_WEIGHTS[0xC3] = 1.5


def _bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _hamming(a: bytes, b: bytes) -> int:
    return int(np.count_nonzero(_bits(a) ^ _bits(b)))


def _flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


# --- brute force -----------------------------------------------------------

SECONDS_PER_YEAR = 365.25 * 24 * 3600
# authentication tag appended by each variant (excluded from "body" metrics)
TAG_BYTES = {"sbx-10r-cbc": 32, "aes-256-gcm": 16}


def brute_force(variant_name: str, *, unknown_bits: int = 12, seed: int = 1) -> dict:
    """Known-plaintext exhaustive search over the first ``unknown_bits`` bits."""

    variant = get_variant(variant_name)
    rng = random.Random(seed)
    key = rng.randbytes(32)
    iv = rng.randbytes(16)
    plaintext = b"SecureBoard!" * 2
    target = variant.encrypt(key, plaintext, iv=iv)

    rest = int.from_bytes(key, "big") & ((1 << (256 - unknown_bits)) - 1)
    found, tried = None, 0
    started = time.perf_counter()
    for prefix in range(1 << unknown_bits):
        candidate = ((prefix << (256 - unknown_bits)) | rest).to_bytes(32, "big")
        tried += 1
        if variant.encrypt(candidate, plaintext, iv=iv) == target:
            found = candidate
            break
    elapsed = max(time.perf_counter() - started, 1e-9)
    rate = tried / elapsed
    full = variant.key_bits
    expected_tries = 2 ** (full - 1)
    return {
        "variant": variant_name,
        "unknown_bits": unknown_bits,
        "tried": tried,
        "found": found == key,
        "seconds": round(elapsed, 4),
        "keys_per_second": round(rate, 1),
        "full_space_log2": full,
        "years_full_space_measured_rate": expected_tries / rate / SECONDS_PER_YEAR,
        "years_full_space_at_1e12": expected_tries / 1e12 / SECONDS_PER_YEAR,
    }


# --- differential ----------------------------------------------------------

def avalanche(variant_name: str, *, samples: int = 500, flip: str = "plaintext",
              seed: int = 1, plaintext_bytes: int = 15) -> dict:
    """Mean fraction of output bits that change after flipping one input bit."""

    if flip not in ("plaintext", "key"):
        raise ValueError("flip must be 'plaintext' or 'key'")
    variant = get_variant(variant_name)
    rng = random.Random(seed)
    key_bit_space = min(variant.key_bits, 256)
    ratios, body_ratios, hist_bins, bits_compared = [], [], np.zeros(129, dtype=int), 0
    tag = TAG_BYTES.get(variant_name, 0)
    for _ in range(samples):
        key, iv = rng.randbytes(32), rng.randbytes(16)
        pt = rng.randbytes(plaintext_bytes)
        base = variant.encrypt(key, pt, iv=iv)
        if flip == "plaintext":
            other = variant.encrypt(key, _flip_bit(pt, rng.randrange(plaintext_bytes * 8)), iv=iv)
        else:
            other = variant.encrypt(_flip_bit(key, rng.randrange(key_bit_space)), pt, iv=iv)
        changed = _hamming(base, other)
        bits_compared = len(base) * 8
        ratio = changed / bits_compared
        ratios.append(ratio)
        body_len = len(base) - tag
        body_ratios.append(_hamming(base[:body_len], other[:body_len]) / (body_len * 8))
        hist_bins[min(128, round(ratio * 128))] += 1
    arr = np.array(ratios)
    return {"variant": variant_name, "flip": flip, "samples": samples,
            "bits_compared": bits_compared, "mean": round(float(arr.mean()), 4),
            "std": round(float(arr.std()), 4), "min": round(float(arr.min()), 4),
            "max": round(float(arr.max()), 4), "histogram": hist_bins.tolist(),
            "body_mean": round(float(np.mean(body_ratios)), 4),
            "body_bits": (len(base) - tag) * 8}


def sac_matrix(*, rounds: int = 10, samples: int = 200, seed: int = 1) -> dict:
    """P(output bit j flips | input bit i flipped) for the SBX block primitive."""

    rng = random.Random(seed)
    counts = np.zeros((128, 128))
    for _ in range(samples):
        cipher = BlockCipher(rng.randbytes(32), rounds)
        block = rng.randbytes(BLOCK_BYTES)
        base = _bits(cipher.encrypt_block(block))
        for i in range(128):
            counts[i] += base ^ _bits(cipher.encrypt_block(_flip_bit(block, i)))
    matrix = counts / samples
    return {"rounds": rounds, "samples": samples,
            "mean_abs_deviation": round(float(np.mean(np.abs(matrix - 0.5))), 4),
            "max_abs_deviation": round(float(np.max(np.abs(matrix - 0.5))), 4),
            "matrix": np.round(matrix, 3).tolist()}


# --- statistical -----------------------------------------------------------

def statistics(variant_name: str, plaintext: bytes, *, seed: int = 1) -> dict:
    rng = random.Random(seed)
    ct = get_variant(variant_name).encrypt(rng.randbytes(32), plaintext, iv=rng.randbytes(16))
    data = np.frombuffer(ct, dtype=np.uint8)
    hist = np.bincount(data, minlength=256)
    expected = len(data) / 256
    stat = float(np.sum((hist - expected) ** 2 / expected))
    probs = hist[hist > 0] / len(data)
    entropy = float(-np.sum(probs * np.log2(probs)))
    serial = float(np.corrcoef(data[:-1].astype(float), data[1:].astype(float))[0, 1]) \
        if len(data) > 2 and data.std() > 0 else 0.0
    blocks = [ct[i:i + 16] for i in range(0, len(ct) - len(ct) % 16, 16)]
    return {"variant": variant_name, "bytes": len(ct), "histogram": hist.tolist(),
            "chi2": round(stat, 2), "chi2_p_value": float(chi2.sf(stat, 255)),
            "entropy_bits_per_byte": round(entropy, 4),
            "serial_correlation": round(serial, 4),
            "repeated_blocks": len(blocks) - len(set(blocks))}


def _index_of_coincidence(column: np.ndarray) -> float:
    n = len(column)
    if n < 2:
        return 0.0
    counts = np.bincount(column, minlength=256).astype(float)
    return float(np.sum(counts * (counts - 1)) / (n * (n - 1)))


def frequency_attack_xor(ciphertext: bytes, key_len_max: int = 8) -> dict:
    """Ciphertext-only attack on repeating-key XOR (Kasiski/Friedman style)."""

    data = np.frombuffer(ciphertext, dtype=np.uint8)
    ics = {L: float(np.mean([_index_of_coincidence(data[i::L]) for i in range(L)]))
           for L in range(1, key_len_max + 1)}
    best_ic = max(ics.values())
    key_len = min(L for L, ic in ics.items() if ic >= 0.9 * best_ic)
    candidates = np.arange(256, dtype=np.uint8)
    key = bytearray()
    for i in range(key_len):
        column = data[i::key_len]
        scores = [_WEIGHTS[column ^ k].sum() for k in candidates]
        key.append(int(np.argmax(scores)))
    plain = bytes(b ^ key[i % key_len] for i, b in enumerate(ciphertext))
    letters = sum(1 for b in plain if chr(b).isalpha() or b in b" ,.:;-" or b >= 0x80)
    readable = letters / max(1, len(plain))
    space_ratio = plain.count(b" ") / max(1, len(plain))
    return {"key_length": key_len, "ic_by_length": {str(k): round(v, 5) for k, v in ics.items()},
            "recovered_key": bytes(key).hex(),
            "plaintext_preview": plain[:160].decode("utf-8", "replace"),
            "readable_ratio": round(readable, 3),
            "success": readable > 0.9 and space_ratio > 0.08}


# --- visual leakage --------------------------------------------------------

def _logo_image(size: int = 128) -> Image.Image:
    img = Image.new("RGB", (size, size), (245, 245, 245))
    d = ImageDraw.Draw(img)
    d.ellipse((14, 14, 74, 74), fill=(200, 30, 30))
    d.rectangle((56, 60, 116, 116), fill=(20, 60, 160))
    d.polygon([(10, 118), (40, 84), (70, 118)], fill=(20, 140, 60))
    return img


def ecb_image_leak(variant_names, *, seed: int = 1) -> dict:
    rng = random.Random(seed)
    original = _logo_image()
    raw = original.tobytes()
    images = {"original": original}
    for name in variant_names:
        ct = get_variant(name).encrypt(rng.randbytes(32), raw, iv=rng.randbytes(16))[: len(raw)]
        images[name] = Image.frombytes("RGB", original.size, ct)
    return images
