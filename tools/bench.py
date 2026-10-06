#!/usr/bin/env python3
"""Load test for the onion ingress: real server process, real sockets, real onion requests.

    python3 tools/bench.py [--requests 20000] [--concurrency 64] [--clients 4] [--recipients 2000] [--secure]

--secure runs the server in secure mode and registers every account with a real signed /subscribe.

The server runs as its own process with the dry-run provider (so we measure this server, not Apple),
and requests are pre-built before timing starts (so we measure the server's crypto, not the client's).
Reports throughput, latency percentiles, and the server's own CPU use, which is what makes the
throughput figure meaningful: "N req/s using X% of one core".
"""

import argparse
import asyncio
import base64
import hashlib
import json
import multiprocessing as mp
import os
import random
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "tests"))
import clientcrypto as cc  # noqa: E402  (independent client port, reused so frames match real apps)


def free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def post(port, path, body):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"POST %s HTTP/1.1\r\nHost: b\r\nContent-Length: %d\r\n\r\n" % (path.encode(), len(body)) + body)
    await writer.drain()
    raw = await reader.read()
    writer.close()
    head, _, payload = raw.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), payload


async def get(port, path):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET %s HTTP/1.1\r\nHost: b\r\n\r\n" % path.encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    return raw.partition(b"\r\n\r\n")[2].decode()


def client_proc(args):
    port, frames, concurrency, start_at = args

    async def run():
        lat, statuses = [], {}
        queue = list(reversed(frames))

        async def worker():
            while queue:
                path, body, key = queue.pop()
                t0 = time.perf_counter()
                try:
                    status, out = await post(port, path, body)
                except OSError:
                    statuses["conn_error"] = statuses.get("conn_error", 0) + 1
                    continue
                lat.append(time.perf_counter() - t0)
                if status == 200 and random.random() < 0.02:  # spot-check that replies really decrypt
                    code = cc.parse_v2_reply(out, key)[1]["code"] if path.endswith("v2/lsrpc") else None
                    if code is not None and code not in (0, 1):
                        status = -1
                statuses[status] = statuses.get(status, 0) + 1

        while time.time() < start_at:
            await asyncio.sleep(0.001)
        await asyncio.gather(*[worker() for _ in range(concurrency)])
        return lat, statuses

    return asyncio.run(run())


def secure_accounts(n):
    """n accounts with real Ed25519 keys (id derived from the seed like the app) and a function that builds
    each one's signed /subscribe request for a given device token."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    ids, signers = [], []
    for _ in range(n):
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        h = bytearray(hashlib.sha512(seed).digest()[:32])
        h[0] &= 248; h[31] &= 127; h[31] |= 64
        x = X25519PrivateKey.from_private_bytes(bytes(h)).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        ident = "bd" + x.hex()
        ed = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()

        def sign(token, sk=sk, ident=ident, ed=ed):
            ts = int(time.time())
            return {"pubkey": ident, "session_ed25519": ed, "namespaces": [0], "data": True, "service": "firebase",
                    "sig_ts": ts, "signature": base64.b64encode(sk.sign(f"MONITOR{ident}{ts}10".encode())).decode(),
                    "service_info": {"token": "fcm:" + token}, "enc_key": os.urandom(32).hex()}

        ids.append(ident)
        signers.append(sign)
    return ids, signers


def cpu_seconds(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def rss_mb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS"):
                return int(line.split()[1]) / 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=20000)
    ap.add_argument("--concurrency", type=int, default=64, help="total in-flight requests")
    ap.add_argument("--clients", type=int, default=4, help="load-generator processes")
    ap.add_argument("--recipients", type=int, default=2000)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--secure", action="store_true", help="run the server with --secure and register by signed subscribe")
    ap.add_argument("--registered-ratio", type=float, default=1.0,
                    help="fraction of notifies addressed to registered recipients (the rest are 'untracked')")
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "key")
        out = subprocess.run([sys.executable, "-m", "bchatpn", "keygen", key], cwd=ROOT, capture_output=True, text=True)
        pub = out.stdout.strip().split()[-1]
        port, admin = free_port(), free_port()
        env = {"PATH": os.environ["PATH"], "BCHATPN_LOG_ONLY": "true", "BCHATPN_KEY_FILE": key,
               "BCHATPN_DB_PATH": os.path.join(d, "pn.db"), "BCHATPN_LISTEN_HOST": "127.0.0.1",
               "BCHATPN_LISTEN_PORT": str(port), "BCHATPN_ADMIN_PORT": str(admin), "BCHATPN_LOG_LEVEL": "WARNING",
               "BCHATPN_RATE_PER_SEC": "1000000", "BCHATPN_RATE_BURST": "1000000",
               "BCHATPN_WORKERS": str(a.workers), "BCHATPN_QUEUE_SIZE": "100000"}
        srv = subprocess.Popen([sys.executable, "-m", "bchatpn", "serve"] + (["--secure"] if a.secure else []),
                               cwd=ROOT, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(150):
                try:
                    if '"ok"' in asyncio.run(get(admin, "/healthz")):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                sys.exit("server did not start: " + srv.stderr.read())

            print(f"server pid {srv.pid}, python {sys.version.split()[0]}, cpus {os.cpu_count()}, "
                  f"mode {'SECURE' if a.secure else 'normal'}")

            if a.secure:
                accounts, signers = secure_accounts(a.recipients)
            else:
                accounts = ["bd" + f"{i:064x}" for i in range(a.recipients)]

            async def register_all():
                sem = asyncio.Semaphore(32)

                async def one(i):
                    async with sem:
                        if a.secure:
                            body, k = cc.v4_request(pub, "subscribe", signers[i](f"{i:064x}"))
                            status, o = await post(port, "/beldex/v4/lsrpc", body)
                            assert status == 200 and json.loads(cc.parse_v4_reply(o, k)[1]).get("success") is True
                            return
                        body, k = cc.v2_request(pub, "register", {"token": f"{i:064x}", "pubKey": accounts[i]})
                        status, o = await post(port, "/beldex/v2/lsrpc", body)
                        assert status == 200 and cc.parse_v2_reply(o, k)[1]["code"] == 1

                await asyncio.gather(*[one(i) for i in range(a.recipients)])

            t0 = time.perf_counter()
            asyncio.run(register_all())
            print(f"registered {a.recipients} devices in {time.perf_counter() - t0:.2f}s")

            print(f"building {a.requests} onion requests...", flush=True)
            frames = []
            for i in range(a.requests):
                if random.random() < a.registered_ratio:
                    to = accounts[i % a.recipients]
                else:
                    to = "bd" + f"{random.getrandbits(256):064x}"
                body, k = cc.v2_request(pub, "notify", {"data": f"{i:08d}" + "QUJD" * 100, "send_to": to})
                frames.append(("/beldex/v2/lsrpc", body, k))
            shards = [frames[i :: a.clients] for i in range(a.clients)]

            cpu0, wall0 = cpu_seconds(srv.pid), None
            start_at = time.time() + 1.0
            with mp.Pool(a.clients) as pool:
                jobs = [(port, s, max(1, a.concurrency // a.clients), start_at) for s in shards]
                t_start = time.perf_counter()
                results = pool.map(client_proc, jobs)
                t_end = time.perf_counter()
            wall = t_end - t_start - 1.0 if t_end - t_start > 1.0 else t_end - t_start
            cpu = cpu_seconds(srv.pid) - cpu0

            lat = sorted(x for r in results for x in r[0])
            statuses = {}
            for r in results:
                for k, v in r[1].items():
                    statuses[k] = statuses.get(k, 0) + v
            time.sleep(1.0)  # let the dispatcher drain
            metrics = asyncio.run(get(admin, "/metrics"))

            def metric(name):
                hits = [l for l in metrics.splitlines() if l.startswith(name + " ") or l.startswith(name + "{")]
                return "; ".join(hits) if hits else f"{name} 0"

            pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] * 1000
            print("\n=== results ===")
            print(f"requests completed : {len(lat)}  (HTTP statuses: {statuses})")
            print(f"throughput         : {len(lat) / wall:,.0f} req/s (client-measured wall {wall:.2f}s)")
            print(f"latency (ms)       : p50 {pct(.50):.1f}  p95 {pct(.95):.1f}  p99 {pct(.99):.1f}  max {lat[-1]*1000:.1f}")
            print(f"server CPU         : {cpu:.2f}s total = {100*cpu/wall:.0f}% of one core "
                  f"-> ~{len(lat)/cpu:,.0f} req per CPU-second")
            print(f"server memory      : {rss_mb(srv.pid):.0f} MB RSS with {a.recipients} registered devices")
            print("server counters    :")
            for name in ("bchatpn_notify_accepted", "bchatpn_notify_untracked", "bchatpn_notify_rejected",
                         "bchatpn_push", "bchatpn_queue_depth", "bchatpn_store_errors"):
                print("   ", metric(name))
        finally:
            srv.terminate()
            try:
                srv.wait(10)
            except subprocess.TimeoutExpired:
                srv.kill()


if __name__ == "__main__":
    main()
