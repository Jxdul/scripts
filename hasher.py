import argparse
import base64
import binascii
import hashlib
import hmac
import itertools
import string
import threading
import time
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
import os

# Stored password format: base64(salt):base64(derived), PBKDF2-HMAC-SHA256.
PBKDF2_SHA256_ITERATIONS = 100_000
PBKDF2_SHA256_DKLEN = 32
PBKDF2_SHA256_SALT_LEN = 16


def default_worker_count():
    """
    Prefer the CPUs this process may actually use (containers, taskset).
    Falls back to logical CPU count.
    """
    if hasattr(os, "process_cpu_count"):
        try:
            n = os.process_cpu_count()
            if n is not None and n > 0:
                return n
        except (AttributeError, NotImplementedError):
            pass
    if hasattr(os, "sched_getaffinity"):
        try:
            return len(os.sched_getaffinity(0))
        except (AttributeError, NotImplementedError, OSError):
            pass
    return os.cpu_count() or 4


def default_batch_size(workers):
    """Larger batches amortize IPC; cap so a single batch does not dominate RAM."""
    return min(280_000, max(80_000, workers * 18_000))


def default_max_in_flight(workers):
    """
    Deep pipeline so workers stay busy; capped so we do not queue unbounded
    batches (each holds one full chunk of candidates).
    """
    return max(min(workers * 20, 320), workers + 16)


CHARSET_PRESETS = {
    "lowdigit": string.ascii_lowercase + string.digits,
    "alnum": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + string.punctuation,
    "hex": "0123456789abcdef",
}


def process_batch(batch, hash_type, target_hex_lower):
    """Process a batch of candidates in one worker process."""
    for candidate in batch:
        attempt = "".join(candidate)
        h = hashlib.new(hash_type)
        h.update(attempt.encode("utf-8"))
        if h.hexdigest() == target_hex_lower:
            return attempt
    return None


def parse_pbkdf2_sha256_stored(stored: str) -> tuple[bytes, bytes]:
    """
    Parse password_hash value: base64(salt):base64(derived).
    Salt is 16 bytes; derived key is 32 bytes (256 bits).
    """
    s = stored.strip()
    parts = s.split(":")
    if len(parts) != 2:
        raise ValueError(
            "PBKDF2 stored value must be 'base64(salt):base64(derived)' "
            "with exactly one ':' separator"
        )
    try:
        salt = base64.b64decode(parts[0])
        derived = base64.b64decode(parts[1])
    except binascii.Error as e:
        raise ValueError(f"invalid base64 in stored hash: {e}") from e
    if len(salt) != PBKDF2_SHA256_SALT_LEN:
        raise ValueError(
            f"salt must decode to {PBKDF2_SHA256_SALT_LEN} bytes, got {len(salt)}"
        )
    if len(derived) != PBKDF2_SHA256_DKLEN:
        raise ValueError(
            f"derived key must be {PBKDF2_SHA256_DKLEN} bytes, got {len(derived)}"
        )
    return salt, derived


def process_batch_pbkdf2_sha256(batch, salt, expected_derived):
    """Process a batch of candidates using PBKDF2-HMAC-SHA256."""
    for candidate in batch:
        attempt = "".join(candidate)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            attempt.encode("utf-8"),
            salt,
            PBKDF2_SHA256_ITERATIONS,
            dklen=PBKDF2_SHA256_DKLEN,
        )
        if hmac.compare_digest(derived, expected_derived):
            return attempt
    return None


def batched(iterable, n):
    """Yield lists of up to n items from iterable (memory-bounded)."""
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, n))
        if not chunk:
            break
        yield chunk


def estimate_keyspace(charset_len, min_len, max_len):
    total = 0
    for length in range(min_len, max_len + 1):
        total += charset_len**length
    return total


def _fmt_rate(per_sec):
    """Human-readable hashes per second."""
    if per_sec >= 1e9:
        return f"{per_sec / 1e9:.2f} G/s"
    if per_sec >= 1e6:
        return f"{per_sec / 1e6:.2f} M/s"
    if per_sec >= 1e3:
        return f"{per_sec / 1e3:.2f} K/s"
    return f"{per_sec:.1f} /s"


def crack_hash(
    target_hash,
    hash_type="md5",
    min_length=1,
    max_length=8,
    charset=None,
    workers=None,
    batch_size=None,
    max_in_flight=None,
    progress_interval=1.0,
):
    """
    Brute-force a hash using multiprocessing. Only a bounded number of tasks
    are queued at once so long runs do not exhaust memory.
    """
    if charset is None:
        charset = CHARSET_PRESETS["lowdigit"]

    workers = workers if workers is not None else default_worker_count()
    hash_type_l = hash_type.strip().lower()
    pbkdf2_mode = hash_type_l == "pbkdf2_sha256"
    if pbkdf2_mode:
        salt, expected_derived = parse_pbkdf2_sha256_stored(target_hash)
        target_hex_lower = None
    else:
        salt = expected_derived = None
        target_hex_lower = target_hash.strip().lower()

    if batch_size is None:
        batch_size = default_batch_size(workers)
    if max_in_flight is None:
        max_in_flight = default_max_in_flight(workers)

    if pbkdf2_mode:
        # Each candidate runs full PBKDF2 (100k iterations); keep tasks small
        # so workers stay fed without one batch dominating wall time.
        batch_size = min(batch_size, max(256, workers * 64))

    ks = estimate_keyspace(len(charset), min_length, max_length)
    if pbkdf2_mode:
        print(
            f"Starting brute-force for PBKDF2-HMAC-SHA256 "
            f"({PBKDF2_SHA256_ITERATIONS} iterations, dklen={PBKDF2_SHA256_DKLEN} bytes)"
        )
    else:
        print(f"Starting brute-force for {hash_type_l.upper()} hash: {target_hash}")
    print(
        f"Charset size: {len(charset)} | Length {min_length}..{max_length} | "
        f"Workers: {workers} | Batch: {batch_size} | In-flight cap: {max_in_flight}"
    )
    print(f"Approx. candidates (sum over lengths): {ks:,}")
    start_time = time.time()
    start_mono = time.monotonic()
    found = None

    progress_on = progress_interval is not None and progress_interval > 0
    state = {
        "length": min_length,
        "length_space": 0,
        "tried_length": 0,
        "tried_total": 0,
        "in_flight": 0,
        "batches_done": 0,
    }
    stop_progress = threading.Event()
    prev_sample = {"t": start_mono, "n": 0}

    def progress_loop():
        while True:
            if stop_progress.is_set():
                return
            now = time.monotonic()
            dt = now - prev_sample["t"]
            dn = state["tried_total"] - prev_sample["n"]
            inst = dn / dt if dt > 0 else 0.0
            prev_sample["t"] = now
            prev_sample["n"] = state["tried_total"]

            elapsed = now - start_mono
            avg = state["tried_total"] / elapsed if elapsed > 0 else 0.0
            ls = state["length_space"]
            tl = state["tried_length"]
            pct = (100.0 * tl / ls) if ls else 0.0

            line = (
                f"[{elapsed:8.1f}s] len={state['length']}  "
                f"this_len {tl:>14,} / {ls:>14,} ({pct:5.1f}%)  "
                f"total {state['tried_total']:>15,}  "
                f"avg {_fmt_rate(avg):>10}  now {_fmt_rate(inst):>10}  "
                f"in_flight={state['in_flight']:<4} batches_done={state['batches_done']}"
            )
            print(line, flush=True)
            if stop_progress.wait(progress_interval):
                return

    progress_thread = None

    def drain_done(done_futures, fut_sizes):
        nonlocal found
        for fut in done_futures:
            n = fut_sizes.pop(fut, 0)
            state["tried_length"] += n
            state["tried_total"] += n
            state["batches_done"] += 1
            try:
                result = fut.result()
            except Exception as e:
                stop_progress.set()
                raise e
            if result:
                found = result
                return True
        return False

    try:
        for length in range(min_length, max_length + 1):
            length_space = len(charset) ** length
            state["length"] = length
            state["length_space"] = length_space
            state["tried_length"] = 0
            prev_sample["t"] = time.monotonic()
            prev_sample["n"] = state["tried_total"]
            print(f"Trying length {length} (~{length_space:,} candidates)...", flush=True)

            if progress_on and progress_thread is None:
                what = (
                    "PBKDF2 attempts"
                    if pbkdf2_mode
                    else "candidate strings hashed"
                )
                print(
                    f"Streaming progress every {progress_interval} s ({what}).",
                    flush=True,
                )
                progress_thread = threading.Thread(target=progress_loop, daemon=True)
                progress_thread.start()

            candidates = itertools.product(charset, repeat=length)

            with ProcessPoolExecutor(max_workers=workers) as executor:
                pending = set()
                fut_sizes = {}

                for batch in batched(candidates, batch_size):
                    while len(pending) >= max_in_flight and not found:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                        state["in_flight"] = len(pending)
                        if drain_done(done, fut_sizes):
                            break
                        if found:
                            break

                    if found:
                        break

                    if pbkdf2_mode:
                        fut = executor.submit(
                            process_batch_pbkdf2_sha256,
                            batch,
                            salt,
                            expected_derived,
                        )
                    else:
                        fut = executor.submit(
                            process_batch, batch, hash_type_l, target_hex_lower
                        )
                    fut_sizes[fut] = len(batch)
                    pending.add(fut)
                    state["in_flight"] = len(pending)

                while pending and not found:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    state["in_flight"] = len(pending)
                    if drain_done(done, fut_sizes):
                        break

            if found:
                break
    finally:
        stop_progress.set()
        if progress_thread is not None:
            progress_thread.join(timeout=progress_interval + 2.0)

    elapsed = time.time() - start_time

    if found:
        print(f"\n[+] SUCCESS! Password found: {found}")
        print(f"Time taken: {elapsed:.2f} seconds")
        return found

    print("\n[-] Password not found within the given length / charset.")
    print(f"Time taken: {elapsed:.2f} seconds")
    return None


def build_charset(args):
    if args.charset_string:
        return args.charset_string
    return CHARSET_PRESETS[args.charset_preset]


def main():
    parser = argparse.ArgumentParser(
        description="Brute-force a hash over candidate strings (short passwords only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "hash_type",
        help=(
            "e.g. md5, sha1, sha256, sha512, or pbkdf2_sha256 "
            "(stored form base64(salt):base64(derived))"
        ),
    )
    parser.add_argument(
        "target_hash",
        help="hex digest to match, or for pbkdf2_sha256 the full colon-separated stored value",
    )
    parser.add_argument(
        "--min",
        type=int,
        default=1,
        metavar="N",
        help="Minimum candidate length",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=8,
        metavar="N",
        help="Maximum candidate length",
    )
    parser.add_argument(
        "--charset",
        dest="charset_preset",
        choices=sorted(CHARSET_PRESETS.keys()),
        default="lowdigit",
        help="Charset preset (use --charset-string for a custom alphabet)",
    )
    parser.add_argument(
        "--charset-string",
        metavar="STR",
        help="Custom charset as a literal string (overrides --charset)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Worker processes (default: all usable logical CPUs — "
            "affinity / process_cpu_count when available)"
        ),
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=None,
        metavar="N",
        help="Candidates per task (default: scales with workers)",
    )
    parser.add_argument(
        "--in-flight",
        type=int,
        default=None,
        metavar="N",
        help="Max concurrent batches (default: ~20× workers, capped for RAM)",
    )
    parser.add_argument(
        "--turbo",
        action="store_true",
        help=(
            "Extra-large batches and very deep pipeline (max RAM & CPU throughput; "
            "use if you have headroom)"
        ),
    )
    parser.add_argument(
        "--progress-every",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Print live stats every SEC seconds (0 disables)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable live progress streaming",
    )

    args = parser.parse_args()
    if args.min < 1:
        parser.error("--min must be >= 1")
    if args.max < args.min:
        parser.error("--max must be >= --min")
    if args.workers is not None and args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.no_progress:
        progress_interval = None
    else:
        progress_interval = None if args.progress_every == 0 else args.progress_every
    if progress_interval is not None and progress_interval < 0:
        parser.error("--progress-every must be >= 0")
    if progress_interval == 0:
        progress_interval = None

    charset = build_charset(args)
    if len(charset) < 1:
        parser.error("charset must be non-empty")
    # Deduplicate while preserving order (smaller search if user repeats chars)
    charset = "".join(dict.fromkeys(charset))

    batch_size = args.batch
    max_in_flight = args.in_flight
    if args.turbo:
        w = args.workers if args.workers is not None else default_worker_count()
        if batch_size is None:
            batch_size = min(450_000, max(120_000, w * 28_000))
        if max_in_flight is None:
            max_in_flight = max(min(w * 28, 512), w + 24)

    try:
        crack_hash(
            args.target_hash,
            hash_type=args.hash_type.lower(),
            min_length=args.min,
            max_length=args.max,
            charset=charset,
            workers=args.workers,
            batch_size=batch_size,
            max_in_flight=max_in_flight,
            progress_interval=progress_interval,
        )
    except ValueError as e:
        parser.error(str(e))


if __name__ == "__main__":
    main()
