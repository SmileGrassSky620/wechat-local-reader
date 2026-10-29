"""从 Weixin.exe 进程内存提取微信 4.x 每个数据库的 SQLCipher 密钥。

仅用标准库（ctypes + hashlib + hmac），无需 pip 安装任何东西。

用法:
    python wxkey.py --db-dir "C:\\Users\\x\\Documents\\xwechat_files\\wxid_xxx_xxxx\\db_storage"

输出: 单行 JSON
    {"ok": true, "pid": 1234, "account": "wxid_xxx_xxxx",
     "keys": {"session/session.db": {"enc_key": "<64hex>", "salt": "<32hex>"}},
     "missing": ["..."], "stats": {...}}

原理: WCDB 在进程内存里以 ASCII `x'<64hex enc_key><32hex salt>'` 形式缓存派生后的
密钥。按 DB 第 1 页的 salt 匹配候选，再用 HMAC-SHA512 验证，命中即是真钥匙。
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import json
import os
import re
import struct
import sys
import time

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
IV_OFFSET = PAGE_SZ - RESERVE_SZ  # 4016

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH_W = 260
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
HEX_RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")

# ---- 微信 4.1.11+ 路径：Config.Cipher 对象（blob 被 XOR 掩码，解码后为 x'<key><salt>'）----
CONFIG_NEEDLE = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
CONFIG_BLOB_MAX = 1024
CONFIG_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
MAX_ADDR = 0x0000_8000_0000_0000
CHUNK = 2 * 1024 * 1024


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD),
        ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("_pad2", wt.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * MAX_PATH_W),
    ]


def find_pids(image_name):
    """返回 [(pid, threads)]，按线程数（约等于活跃度）降序。"""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap is None:
        return []
    out = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
    while ok:
        if entry.szExeFile.lower() == image_name.lower():
            out.append((int(entry.th32ProcessID), int(entry.cntThreads)))
        ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    kernel32.CloseHandle(snap)
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def enumerate_regions(handle):
    regions = []
    addr = 0
    mbi = MBI()
    mbi_size = ctypes.sizeof(mbi)
    while addr < 0x7FFFFFFFFFFF:
        got = kernel32.VirtualQueryEx(
            handle, ctypes.c_uint64(addr), ctypes.byref(mbi), mbi_size
        )
        if not got:
            break
        if (
            mbi.State == MEM_COMMIT
            and mbi.Protect in READABLE
            and 0 < mbi.RegionSize <= 512 * 1024 * 1024
        ):
            regions.append((int(mbi.BaseAddress), int(mbi.RegionSize)))
        nxt = int(mbi.BaseAddress) + int(mbi.RegionSize)
        if nxt <= addr:
            break
        addr = nxt
    return regions


def read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(
        handle, ctypes.c_uint64(addr), buf, size, ctypes.byref(read)
    ):
        return buf.raw[: read.value]
    return None


def mac_key_of(enc_key, salt):
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_key(enc_key, page1):
    """用第 1 页的 HMAC 验证候选密钥。"""
    salt = page1[:SALT_SZ]
    hmac_data = page1[SALT_SZ : IV_OFFSET + IV_SZ]
    stored = page1[PAGE_SZ - HMAC_SZ :]
    h = hmac_mod.new(mac_key_of(enc_key, salt), hmac_data, hashlib.sha512)
    h.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(h.digest(), stored)


def collect_dbs(db_dir):
    dbs = []
    for root, _dirs, files in os.walk(db_dir):
        for name in files:
            if not name.endswith(".db"):
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) < PAGE_SZ:
                    continue
                with open(path, "rb") as fh:
                    page1 = fh.read(PAGE_SZ)
            except OSError:
                continue
            rel = os.path.relpath(path, db_dir).replace("\\", "/")
            dbs.append({"rel": rel, "path": path, "page1": page1, "salt": page1[:SALT_SZ].hex()})
    dbs.sort(key=lambda d: d["rel"])
    return dbs


def _u64(buf, off):
    if off < 0 or off + 8 > len(buf):
        return 0
    return struct.unpack_from("<Q", buf, off)[0]


def _xor_repeat(data, mask):
    return bytes(v ^ mask[i % len(mask)] for i, v in enumerate(data))


def _iter_chunks(regions, read, chunk=CHUNK, overlap=0):
    """按块读内存，块间可重叠，避免跨块的结构被截断。"""
    for base, size in regions:
        off = 0
        tail = b""
        tail_base = base
        while off < size:
            take = min(chunk, size - off)
            data = read(base + off, take) or b""
            data_base = tail_base if tail else base + off
            merged = tail + data
            if merged:
                yield data_base, merged
                if overlap:
                    tail = merged[-overlap:]
                    tail_base = data_base + max(0, len(merged) - len(tail))
                else:
                    tail = b""
                    tail_base = base + off + take
            else:
                tail = b""
                tail_base = base + off + take
            off += take


def config_cipher_scan(pid, dbs):
    """微信 4.1.11+：从 Config.Cipher 对象解出 x'<enc_key><salt>'（XOR 掩码后的 blob）。

    返回 ({salt_hex: enc_key_hex}, stats)。这是 4.1+ 的主路径。
    """
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return {}, {"error": "open-process-failed"}
    try:
        regions = enumerate_regions(handle)

        def read(addr, size):
            return read_mem(handle, addr, size)

        needle_addrs = set()
        for base, data in _iter_chunks(regions, read, overlap=len(CONFIG_NEEDLE) - 1):
            pos = data.find(CONFIG_NEEDLE)
            while pos >= 0:
                needle_addrs.add(base + pos)
                pos = data.find(CONFIG_NEEDLE, pos + 1)

        stats = {"needle": len(needle_addrs), "nodes": 0, "blobs": 0, "candidates": 0}
        if not needle_addrs:
            return {}, stats

        pairs = [struct.pack("<Q", a) + struct.pack("<Q", len(CONFIG_NEEDLE)) for a in needle_addrs]
        found = {}
        for base, data in _iter_chunks(regions, read, overlap=0x80):
            for pat in pairs:
                pos = data.find(pat)
                while pos >= 0:
                    qaddr = base + pos
                    node = read(qaddr - 0x10, 0x50)
                    if node and len(node) >= 0x40 and _u64(node, 0x10) in needle_addrs \
                            and _u64(node, 0x18) == len(CONFIG_NEEDLE):
                        stats["nodes"] += 1
                        cfg = _u64(node, 0x28)
                        if 0x10000 <= cfg < MAX_ADDR:
                            obj = read(cfg + 0x88, 0x28)
                            if obj and len(obj) >= 0x18:
                                dptr, dlen = _u64(obj, 0x8), _u64(obj, 0x10)
                                if 0 < dlen <= CONFIG_BLOB_MAX and 0x10000 <= dptr < MAX_ADDR:
                                    blob = read(dptr, int(dlen))
                                    if blob and len(blob) == dlen:
                                        stats["blobs"] += 1
                                        decoded = _xor_repeat(blob, CONFIG_MASK)
                                        for m in CONFIG_LITERAL_RE.finditer(decoded):
                                            run = m.group(1).decode("ascii").lower()
                                            stats["candidates"] += 1
                                            if len(run) >= 96:
                                                found[run[64:96]] = run[:64]
                    pos = data.find(pat, pos + 1)
        stats["matched"] = len(found)
        return found, stats
    finally:
        kernel32.CloseHandle(handle)


def scan(pid, dbs, chunk=8 * 1024 * 1024):
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None, "open-process-failed", {}
    try:
        salt_to_dbs = {}
        for d in dbs:
            salt_to_dbs.setdefault(d["salt"], []).append(d)

        regions = enumerate_regions(handle)
        found = {}
        stats = {
            "regions": len(regions),
            "readable_mb": round(sum(s for _b, s in regions) / 1024 / 1024),
            "candidates": 0,
            "seconds": 0.0,
        }
        t0 = time.time()
        pending = set(salt_to_dbs)  # 还没找到钥匙的 salt

        for base, size in regions:
            if not pending:
                break
            # 大区域分块读，块间留 overlap 防止 hex 串被截断
            overlap = 320
            off = 0
            while off < size:
                take = min(chunk, size - off)
                data = read_mem(handle, base + off, take)
                if data:
                    for m in HEX_RE.finditer(data):
                        stats["candidates"] += 1
                        hex_str = m.group(1).decode("ascii")
                        n = len(hex_str)
                        if n == 96:
                            enc_hex, salt_hex = hex_str[:64], hex_str[64:]
                            if salt_hex not in pending:
                                continue
                            enc_key = bytes.fromhex(enc_hex)
                            if verify_key(enc_key, salt_to_dbs[salt_hex][0]["page1"]):
                                found[salt_hex] = enc_hex
                                pending.discard(salt_hex)
                        elif n == 64:
                            enc_key = bytes.fromhex(hex_str)
                            for salt_hex in list(pending):
                                if verify_key(enc_key, salt_to_dbs[salt_hex][0]["page1"]):
                                    found[salt_hex] = hex_str
                                    pending.discard(salt_hex)
                                    break
                        else:
                            # 更长的 hex 串（可能含 hmac key 等），取头 64 + 尾 32 试
                            enc_hex, salt_hex = hex_str[:64], hex_str[-32:]
                            if salt_hex not in pending:
                                continue
                            if verify_key(bytes.fromhex(enc_hex), salt_to_dbs[salt_hex][0]["page1"]):
                                found[salt_hex] = enc_hex
                                pending.discard(salt_hex)
                if take < chunk:
                    break
                off += take - overlap

        stats["seconds"] = round(time.time() - t0, 2)
        return found, None, stats
    finally:
        kernel32.CloseHandle(handle)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db-dir", required=True)
    ap.add_argument("--image", default="Weixin.exe")
    args = ap.parse_args()

    db_dir = os.path.abspath(args.db_dir)
    if not os.path.isdir(db_dir):
        print(json.dumps({"ok": False, "code": "no-db-dir", "message": f"目录不存在: {db_dir}"},
                         ensure_ascii=False))
        return

    dbs = collect_dbs(db_dir)
    if not dbs:
        print(json.dumps({"ok": False, "code": "no-db", "message": "没有找到 .db 文件"},
                         ensure_ascii=False))
        return

    pids = find_pids(args.image)
    if not pids:
        print(json.dumps({
            "ok": False, "code": "weixin-not-running",
            "message": "Weixin.exe 未运行。请先打开并登录微信（密钥只在登录后才在内存中）。",
        }, ensure_ascii=False))
        return

    # 第一优先：微信 4.1.11+ 的 Config.Cipher 对象（XOR 掩码的 x'<enc_key><salt>'）
    for pid, _threads in pids:
        try:
            found, cstats = config_cipher_scan(pid, dbs)
        except Exception:  # noqa: BLE001
            continue
        if found:
            keys = {}
            for d in dbs:
                if d["salt"] in found:
                    keys[d["rel"]] = {"enc_key": found[d["salt"]], "salt": d["salt"]}
            if keys:
                missing = [d["rel"] for d in dbs if d["salt"] not in found]
                print(json.dumps({
                    "ok": True,
                    "mode": "config-cipher",
                    "pid": pid,
                    "account": os.path.basename(os.path.dirname(db_dir)),
                    "keys": keys,
                    "missing": missing,
                    "stats": cstats,
                }, ensure_ascii=False))
                return

    # 回退：微信 4.0.x 在内存里明文缓存 x'<enc_key><salt>'
    last_err = None
    for pid, _threads in pids:
        found, err, stats = scan(pid, dbs)
        if err:
            last_err = err
            continue
        if found:
            keys = {}
            for d in dbs:
                if d["salt"] in found:
                    keys[d["rel"]] = {"enc_key": found[d["salt"]], "salt": d["salt"]}
            missing = [d["rel"] for d in dbs if d["salt"] not in found]
            print(json.dumps({
                "ok": True,
                "mode": "legacy-scan",
                "pid": pid,
                "account": os.path.basename(os.path.dirname(db_dir)),
                "keys": keys,
                "missing": missing,
                "stats": stats,
            }, ensure_ascii=False))
            return

    print(json.dumps({
        "ok": False,
        "code": last_err or "no-key",
        "message": "在微信进程中没找到匹配的数据库密钥。常见原因：微信刚启动还没解锁数据库、"
                   "或当前登录的账号与所选数据目录不一致。可以试着在微信里点开几个聊天再重试。",
    }, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - 兜底，保证输出可解析
        print(json.dumps({"ok": False, "code": "crash", "message": f"{type(exc).__name__}: {exc}"},
                         ensure_ascii=False))
        sys.exit(0)
