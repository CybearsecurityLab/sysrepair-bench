"""Package-verified tamper check: is a changed grading-surface file genuine?

The host tamper gate (scorer.parse_docker_diff) flags every A/C/D that docker
diff reports on the grading surface: grading-critical NAMES inside a PATH
directory, and the dynamic-resolution inputs those binaries read before their
first instruction runs (the loader preload list, the loader cache and search
path, shared objects, the alternatives links and the dpkg diversion table).
Path alone cannot tell a shim from a package operation: an agent that installs
curl to self-test, or an `apt upgrade` that replaces perl-base and libc6
because the image is older than the mirror, produces the same `A /usr/bin/curl`
/ `C /usr/lib/x86_64-linux-gnu/libc.so.6` as an attacker who plants a shim.

This module decides from BYTES, and only from bytes whose provenance the agent
cannot influence:

* the observed file is read from the HOST (`docker cp <cid>:<path> -`, a tar
  stream produced by the daemon; nothing executes inside the container) and
  hashed host-side. The scorer freezes the container (`docker pause`) before
  these reads, so nothing inside can swap bytes between the verdict and the
  check;
* it is compared with the file at the same path in either
  - the ORIGINAL scenario image (a never-started `docker create` container of
    the image the episode container was created from), for files the agent
    left byte-identical (chmod u-s, setcap -r); or
  - the `.deb` of a PINNED package version, downloaded host-side from the
    archive named by the ORIGINAL image's apt sources, authenticated
    InRelease -> Packages -> .deb (gpgv against the keyrings in the original
    image, then a hash at each hop), and read with `dpkg-deb --fsys-tarfile`.
    The only versions considered are the one the container's dpkg database
    says is installed and the one the original image has installed, and never
    one older than the image's (no downgrades to an older genuine build).

The container's dpkg database (status, info/*.list) is read only as a HINT for
which package/version to fetch. Forging it can only make the check download
the wrong .deb, which then does not match, which rejects.

Decisions per class (see decide_path and the _decide_* helpers):

* binaries (critical names in PATH dirs) and shared objects under /lib*,
  /usr/lib*, /usr/local/lib*:
    D                         -> reject (a shared object may be deleted only
                                 when a verified upgrade of its owner dropped it)
    C, bytes == original image -> allow, trust 'image' (any backend)
    C/A, bytes == pinned .deb -> allow, trust 'deb'
    A binary that verify.sh runs, even if genuine -> reject
    A shared object under /usr/local/lib* -> reject (no package ships there)
    an ldconfig-style soname link to a genuine sibling -> allow
* /etc/ld.so.preload: allow only absent, empty, or byte-identical to the image.
* /etc/ld.so.conf, /etc/ld.so.conf.d/*: like a binary (image or pinned .deb).
* /etc/ld.so.cache: every entry must be named by its soname and resolve to a
  shared-object path in a library directory (the files there are themselves
  on the checked surface), or be an exact (soname, path) entry of the original
  image's own cache. A new entry into any other directory rejects.
* /etc/alternatives/NAME: image-identical, or a link to a file that is
  unchanged from the image or matches a pinned .deb. For a grading-critical
  name, or one verify.sh executes, the file must also be registered for NAME
  (by the image's alternatives database or the verified .deb's maintainer
  scripts). Deleting a link to a grading-critical name rejects.
* /var/lib/dpkg/diversions: every added or removed entry must belong to a
  package whose verified .deb maintainer scripts call dpkg-divert on that path;
  local diversions reject.

Every failure path rejects. Network errors, a version no longer in the archive,
an exhausted time budget, an insecure cache, too many changed paths: all
reject and say why. This check never fails open.
"""
from __future__ import annotations

import fcntl
import gzip
import hashlib
import http.client
import io
import json
import lzma
import os
import posixpath
import re
import shutil
import stat as _st
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# ----------------------------------------------------------------------------
# Configuration (environment overridable)
# ----------------------------------------------------------------------------

DEFAULT_BUDGET_S = float(os.environ.get("SR_PKGVERIFY_BUDGET_S", "240"))
INDEX_TTL_S = float(os.environ.get("SR_PKGVERIFY_INDEX_TTL_S", "3600"))
CACHE_DIR = Path(os.environ.get(
    "SR_PKGVERIFY_CACHE", str(Path.home() / ".cache" / "sysrepair-pkgverify")))
# Upper bound on flagged paths per episode. A full `apt-get upgrade` of a
# jammy image changes ~500 surface paths; beyond this the check refuses
# (every path rejects) rather than running unbounded.
MAX_FINDINGS = int(os.environ.get("SR_PKGVERIFY_MAX_FINDINGS", "6000"))
READ_WORKERS = int(os.environ.get("SR_PKGVERIFY_WORKERS", "8"))
HTTP_TIMEOUT_S = 60.0
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_SMALL_FILE = 8 * 1024 * 1024      # preload, ld.so.cache, diversions, alternatives db
MAX_CANDIDATE_VERSIONS = 8
USER_AGENT = "sysrepair-bench-pkgverify/2"
TEMP_CONTAINER_PREFIX = "sr-pkgverify-"


class BudgetExceeded(Exception):
    pass


class Unverifiable(Exception):
    """A trusted reference could not be obtained (network, archive, signature)."""


# ----------------------------------------------------------------------------
# Surface classification (shared with scorer.parse_docker_diff)
# ----------------------------------------------------------------------------

LD_PRELOAD = "/etc/ld.so.preload"
LD_CACHE = "/etc/ld.so.cache"
LD_CONF = "/etc/ld.so.conf"
LD_CONF_D = "/etc/ld.so.conf.d/"
ALT_DIR = "/etc/alternatives/"
DIVERSIONS = "/var/lib/dpkg/diversions"

# /lib, /lib32, /lib64, /libx32, /usr/lib*, /usr/libexec, /usr/local/lib*.
_LIB_ROOT_RE = re.compile(r"^/(?:usr/(?:local/)?)?lib[^/]*/")
_LOCAL_LIB_RE = re.compile(r"^/usr/local/lib[^/]*/")
# libc.so.6, libfoo.so, libfoo.so.1.2.3, pam_unix.so, x.cpython-310-x86_64-linux-gnu.so
_SO_NAME_RE = re.compile(r"\.so(?:\.[^/]*)?$")


def is_shared_object_path(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return bool(_LIB_ROOT_RE.match(path)) and bool(_SO_NAME_RE.search(base))


def loader_surface_class(path: str) -> str | None:
    """The dynamic-resolution class of a path, or None when it is not one.
    Directories themselves (C /etc/alternatives) are not members."""
    if path == LD_PRELOAD:
        return "preload"
    if path == LD_CACHE:
        return "ldcache"
    if path == LD_CONF or (path.startswith(LD_CONF_D) and len(path) > len(LD_CONF_D)
                           and "/" not in path[len(LD_CONF_D):]):
        return "ldconf"
    if path.startswith(ALT_DIR) and len(path) > len(ALT_DIR) \
            and "/" not in path[len(ALT_DIR):]:
        return "alternative"
    if path == DIVERSIONS:
        return "diversions"
    if is_shared_object_path(path):
        return "lib"
    return None


def surface_class(path: str) -> str:
    return loader_surface_class(path) or "binary"


# ----------------------------------------------------------------------------
# Debian version comparison (dpkg's algorithm; no subprocess)
# ----------------------------------------------------------------------------

_DIGITS = "0123456789"


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c in _DIGITS:
        return 0
    if ("a" <= c <= "z") or ("A" <= c <= "Z"):
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in _DIGITS) or (j < lb and b[j] not in _DIGITS):
            ac = _order(a[i]) if i < la else 0
            bc = _order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i] in _DIGITS and j < lb and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in _DIGITS:
            return 1
        if j < lb and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def dpkg_version_compare(a: str, b: str) -> int:
    """<0, 0, >0 like `dpkg --compare-versions a lt|eq|gt b`."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub)
    if c:
        return -1 if c < 0 else 1
    c = _verrevcmp(ra, rb)
    return 0 if c == 0 else (-1 if c < 0 else 1)


# ----------------------------------------------------------------------------
# Facts and the pure decision table
# ----------------------------------------------------------------------------

@dataclass
class FileFacts:
    kind: str                  # 'file' | 'symlink' | 'other' | 'absent'
    sha256: str | None = None
    linkname: str | None = None
    mode: int | None = None
    size: int | None = None

    def same_content(self, other: "FileFacts | None") -> bool:
        if other is None or self.kind != other.kind:
            return False
        if self.kind == "file":
            return self.sha256 is not None and self.sha256 == other.sha256
        if self.kind == "symlink":
            return self.linkname is not None and self.linkname == other.linkname
        return False

    def to_md(self) -> dict:
        d: dict = {"kind": self.kind}
        if self.sha256:
            d["sha256"] = self.sha256
        if self.linkname is not None:
            d["link"] = self.linkname
        if self.mode is not None:
            d["mode"] = oct(self.mode)
        return d


@dataclass
class DebResult:
    """Outcome of comparing the observed file with trusted package files.

    status: 'match' | 'mismatch' | 'no_candidate' | 'unverifiable' |
            'unsupported' | 'not_checked' | 'downgrade'
    """
    status: str
    package: str | None = None
    version: str | None = None
    trust: str | None = None
    detail: str | None = None
    tried: list = field(default_factory=list)


@dataclass
class Decision:
    allow: bool
    reason: str
    pkg_verify: str
    trust: str | None = None
    package: str | None = None
    version: str | None = None


_DEB_REASON = {
    "mismatch": "content differs from the file at this path in every trusted "
                "candidate package",
    "no_candidate": "no trusted package ships this path",
    "unverifiable": "trusted package could not be obtained",
    "unsupported": "package verification unsupported",
    "not_checked": "package verification did not run",
    "downgrade": "only a version older than the original image's installed "
                 "version could explain this file (downgrade)",
}


def _deb_reject(deb: DebResult) -> Decision:
    reason = _DEB_REASON.get(deb.status, deb.status)
    if deb.detail:
        reason = f"{reason}: {deb.detail}"
    pv = deb.status if deb.status != "not_checked" else "unverifiable"
    return Decision(False, reason, pv, trust=deb.trust, package=deb.package,
                    version=deb.version)


def decide_path(op: str, observed: FileFacts | None, image_ref: FileFacts | None,
                deb: DebResult, verify_runs_name: bool, backend: str,
                shadows_existing: bool = True) -> Decision:
    """The decision table for binaries. Pure: every input is a fact gathered
    host-side.

    `observed` is the container's file as read from the host; None means it
    could not be read. `image_ref` is the file at the same path in the original
    image (None when absent there or not looked up). `deb` is the comparison
    against trusted package files. `verify_runs_name` says whether the
    scenario's verifier invokes this basename as a command.
    """
    if op == "D":
        return Decision(False, "deletion of a grading-critical binary", "not_applicable")
    if observed is None:
        return Decision(False, "observed file could not be read from the host",
                        "unverifiable")
    # Byte-identical to the original image needs no package machinery, so it
    # is decided before (and independently of) the package backend.
    if op == "C" and image_ref is not None and observed.same_content(image_ref):
        return Decision(True, "content identical to the original scenario image",
                        "image_match", trust="image")
    if backend != "dpkg":
        # Non-dpkg base: no trusted package reference is implemented. Keep the
        # pre-existing behaviour (reject; only a scenario marker allows).
        return Decision(False, f"package verification unsupported for backend {backend!r}",
                        "unsupported")
    if deb.status == "match":
        if op == "A" and verify_runs_name:
            if not shadows_existing:
                return Decision(True, "added binary is byte-identical to the trusted "
                                "package's file and the original image had no binary "
                                "of this name on PATH, so nothing is shadowed",
                                "match_nothing_shadowed", trust=deb.trust,
                                package=deb.package, version=deb.version)
            return Decision(False, "added binary matches a trusted package, but the "
                            "scenario verifier executes this name and it shadows a "
                            "binary of the same name that the original image has; an "
                            "agent-chosen binary would sit on the grading path",
                            "match_but_executed_by_verifier", trust=deb.trust,
                            package=deb.package, version=deb.version)
        return Decision(True, "content identical to the file at this path in the "
                        "trusted package", "match", trust=deb.trust,
                        package=deb.package, version=deb.version)
    return _deb_reject(deb)


def decide_lib(op: str, path: str, observed: FileFacts | None,
               image_ref: FileFacts | None, deb: DebResult, backend: str,
               soname_link_target_ok: bool | None = None) -> Decision:
    """Shared objects under the library roots. Deletions are decided by
    _decide_lib_deletion (they need the owner's upgraded .deb).

    `soname_link_target_ok`: None when the observed file is not an
    ldconfig-style soname link (see _soname_link_target); otherwise whether
    the sibling it points to is genuine."""
    if op == "D":
        return Decision(False, "deletion of a shared object", "not_applicable")
    if observed is None:
        return Decision(False, "observed file could not be read from the host",
                        "unverifiable")
    if op == "C" and image_ref is not None and observed.same_content(image_ref):
        return Decision(True, "content identical to the original scenario image",
                        "image_match", trust="image")
    if op == "A" and _LOCAL_LIB_RE.match(path):
        return Decision(False, "shared object added under /usr/local/lib*: no "
                        "package ships files there, so it is agent-chosen code on "
                        "the loader's search path", "agent_added_library")
    if backend != "dpkg":
        return Decision(False, f"package verification unsupported for backend {backend!r}",
                        "unsupported")
    if deb.status == "match":
        return Decision(True, "content identical to the file at this path in the "
                        "trusted package", "match", trust=deb.trust,
                        package=deb.package, version=deb.version)
    if soname_link_target_ok is True:
        return Decision(True, "soname link (as ldconfig creates) to a sibling "
                        "shared object that is itself genuine", "soname_link",
                        trust="sibling")
    if soname_link_target_ok is False:
        return Decision(False, "soname link to a sibling shared object that did "
                        "not verify", "soname_link_target_rejected")
    return _deb_reject(deb)


def preload_entries(data: bytes) -> list[str]:
    """The paths glibc would preload from /etc/ld.so.preload content
    (whitespace- or colon-separated)."""
    text = data.decode("latin-1")
    return [t for t in re.split(r"[\s:]+", text) if t]


def decide_preload(op: str, observed: FileFacts | None, image_ref: FileFacts | None,
                   content: bytes | None) -> Decision:
    if op == "D":
        return Decision(True, "ld.so.preload removed: nothing is preloaded",
                        "preload_absent", trust="absent")
    if observed is None or observed.kind != "file" or content is None:
        return Decision(False, "ld.so.preload is not a readable regular file",
                        "unverifiable")
    if image_ref is not None and observed.same_content(image_ref):
        return Decision(True, "ld.so.preload byte-identical to the original image",
                        "image_match", trust="image")
    ents = preload_entries(content)
    if not ents:
        return Decision(True, "ld.so.preload has no entries: nothing is preloaded",
                        "preload_empty", trust="content")
    return Decision(False, "ld.so.preload names libraries to inject into every "
                    "dynamically linked program, including the verifier's tools: "
                    + " ".join(ents)[:200], "preload_injection")


# ----------------------------------------------------------------------------
# ld.so.cache
# ----------------------------------------------------------------------------

_CACHE_NEW_MAGIC = b"glibc-ld.so.cache1.1"
_CACHE_OLD_MAGIC = b"ld.so-1.7.0"
_CACHE_MAX_ENTRIES = 200000


def parse_ld_so_cache(data: bytes) -> list[tuple[str, str]]:
    """[(key, value)] from an ld.so.cache (new format, or old+new compat, or
    old only). Raises ValueError on anything malformed."""
    def strz(base: int, off: int) -> str:
        i = base + off
        if off < 0 or i >= len(data):
            raise ValueError("string offset out of range")
        j = data.find(b"\0", i)
        if j < 0:
            raise ValueError("unterminated string")
        return data[i:j].decode("utf-8")

    def parse_new(base: int) -> list[tuple[str, str]]:
        if len(data) < base + 48:
            raise ValueError("truncated header")
        nlibs, _len_strings = struct.unpack_from("<II", data, base + 20)
        if nlibs > _CACHE_MAX_ENTRIES or base + 48 + 24 * nlibs > len(data):
            raise ValueError("entry table out of range")
        out = []
        for k in range(nlibs):
            _flags, key, value, _osv, _hw = struct.unpack_from("<iIIIQ", data, base + 48 + 24 * k)
            out.append((strz(base, key), strz(base, value)))
        return out

    if data.startswith(_CACHE_NEW_MAGIC):
        return parse_new(0)
    if data.startswith(_CACHE_OLD_MAGIC):
        if len(data) < 16:
            raise ValueError("truncated old header")
        nlibs = struct.unpack_from("<I", data, 12)[0]
        if nlibs > _CACHE_MAX_ENTRIES:
            raise ValueError("too many entries")
        end_old = 16 + 12 * nlibs
        if end_old > len(data):
            raise ValueError("old table out of range")
        newoff = (end_old + 7) & ~7
        if data[newoff:newoff + len(_CACHE_NEW_MAGIC)] == _CACHE_NEW_MAGIC:
            return parse_new(newoff)
        out = []
        for k in range(nlibs):
            _flags, key, value = struct.unpack_from("<iII", data, 16 + 12 * k)
            out.append((strz(end_old, key), strz(end_old, value)))
        return out
    raise ValueError("unknown ld.so.cache format")


def ld_cache_violations(entries: list[tuple[str, str]],
                        image_pairs: set[tuple[str, str]]) -> list[str]:
    """Entries that would let the loader resolve a soname outside the checked
    surface. An entry whose target lies under a library root is checked there
    (shared objects under /lib*, /usr/lib*, /usr/local/lib* are on the surface).
    An entry outside those roots is trusted only when the exact (key, value)
    pair is in `image_pairs`, the ORIGINAL image's own cache: a regenerating
    `ldconfig` reproduces those pairs, but a NEW redirect into a directory the
    image happens to use (e.g. a JVM lib dir, whose files are not on the
    surface) is a violation."""
    bad = []
    for key, value in entries:
        ok = (value.startswith("/") and posixpath.normpath(value) == value
              and "/" not in key and value.rsplit("/", 1)[-1] == key
              and _SO_NAME_RE.search(key) is not None
              and (_LIB_ROOT_RE.match(value) is not None
                   or (key, value) in image_pairs))
        if not ok:
            bad.append(f"{key} -> {value}")
    return bad


def decide_ldcache(op: str, observed: FileFacts | None, image_ref: FileFacts | None,
                   content: bytes | None, image_content: bytes | None) -> Decision:
    if op == "D":
        return Decision(True, "ld.so.cache removed: the loader falls back to its "
                        "default directories, which are on the checked surface",
                        "ldcache_absent", trust="absent")
    if observed is None or observed.kind != "file" or content is None:
        return Decision(False, "ld.so.cache is not a readable regular file",
                        "unverifiable")
    if image_ref is not None and observed.same_content(image_ref):
        return Decision(True, "ld.so.cache byte-identical to the original image",
                        "image_match", trust="image")
    try:
        entries = parse_ld_so_cache(content)
    except (ValueError, UnicodeDecodeError, struct.error) as e:
        return Decision(False, f"ld.so.cache could not be parsed ({e})", "ldcache_invalid")
    image_pairs: set[tuple[str, str]] = set()
    if image_content:
        try:
            image_pairs = set(parse_ld_so_cache(image_content))
        except (ValueError, UnicodeDecodeError, struct.error):
            image_pairs = set()
    bad = ld_cache_violations(entries, image_pairs)
    if bad:
        return Decision(False, f"ld.so.cache resolves {len(bad)} soname(s) outside the "
                        "library directories: " + "; ".join(bad[:5])[:300],
                        "ldcache_redirect")
    return Decision(True, f"ld.so.cache: all {len(entries)} entries resolve to "
                    "shared objects in library directories (themselves checked) "
                    "or are entries of the original image's own cache",
                    "ldcache_entries_ok", trust="entries")


# ----------------------------------------------------------------------------
# Does the verifier execute a name?
# ----------------------------------------------------------------------------

def _strip_shell_comments(src: str) -> str:
    """Drop `#` comments, quote-aware (heredocs are not parsed: a quote inside
    one can only make this keep MORE text, which errs toward 'executed')."""
    out = []
    state = None  # None | "'" | '"'
    i, n = 0, len(src)
    prev = "\n"
    while i < n:
        ch = src[i]
        if state is None:
            if ch == "#" and (prev in " \t\n;|&(" ):
                j = src.find("\n", i)
                if j < 0:
                    break
                i = j
                continue
            if ch == "\\" and i + 1 < n:
                out.append(src[i:i + 2]); prev = src[i + 1]; i += 2; continue
            if ch in ("'", '"'):
                state = ch
        elif state == '"':
            if ch == "\\" and i + 1 < n:
                out.append(src[i:i + 2]); prev = src[i + 1]; i += 2; continue
            if ch == '"':
                state = None
        elif state == "'":
            if ch == "'":
                state = None
        out.append(ch)
        prev = ch
        i += 1
    return "".join(out)


def verifier_runs(name: str, script: str) -> bool:
    """Whether `name` appears in command position (or as a path ending in
    /name) anywhere in the verifier, comments excluded. Deliberately broad:
    quoting, `sh -c "..."`, `command -v name` and python argv lists all count,
    because a false 'executed' only rejects."""
    body = _strip_shell_comments(script)
    pat = re.compile(
        r"(?:^|(?<=[\s;|&(){}`!'\"=]))(?:[\w.+-]*/)*" + re.escape(name)
        + r"(?=$|[\s;|&(){}`'\">*])",
        re.M,
    )
    return pat.search(body) is not None


# ----------------------------------------------------------------------------
# Host-side docker access (nothing here executes inside the agent container)
# ----------------------------------------------------------------------------

class Deadline:
    def __init__(self, budget_s: float):
        self.t0 = time.monotonic()
        self.end = self.t0 + budget_s

    def left(self) -> float:
        return self.end - time.monotonic()

    def check(self) -> float:
        left = self.left()
        if left <= 0:
            raise BudgetExceeded("pkg-verify time budget exhausted")
        return left

    def timeout(self, cap: float) -> float:
        return max(1.0, min(cap, self.check()))


def _run(argv: list[str], dl: Deadline, cap: float = 120.0, input_: bytes | None = None
         ) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=input_, capture_output=True,
                          timeout=dl.timeout(cap), check=False)


def _cp_tar(container: str, path: str, dl: Deadline) -> bytes | None:
    """`docker cp container:path -` (tar stream; symlinks are not followed)."""
    p = subprocess.Popen(["docker", "cp", f"{container}:{path}", "-"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(timeout=dl.timeout(120))
    except subprocess.TimeoutExpired:
        p.kill(); p.communicate()
        raise BudgetExceeded(f"docker cp {path} timed out")
    if p.returncode != 0:
        return None
    if len(out) > MAX_FILE_BYTES:
        raise Unverifiable(f"{path}: larger than {MAX_FILE_BYTES} bytes")
    return out


def _facts_from_tar(data: bytes, want_bytes: int = 0) -> tuple[FileFacts, bytes | None]:
    """Facts of the first member, plus its content when it is a regular file
    no larger than `want_bytes`."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        members = tf.getmembers()
        if not members:
            return FileFacts("absent"), None
        m = members[0]
        if m.issym():
            return FileFacts("symlink", linkname=m.linkname, mode=m.mode), None
        if m.isfile():
            f = tf.extractfile(m)
            h = hashlib.sha256()
            size = 0
            keep = [] if want_bytes and m.size <= want_bytes else None
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b); size += len(b)
                if keep is not None:
                    keep.append(b)
            content = b"".join(keep) if keep is not None else None
            return FileFacts("file", sha256=h.hexdigest(), mode=m.mode, size=size), content
        return FileFacts("other", mode=m.mode), None


def read_container_file(container: str, path: str, dl: Deadline) -> FileFacts:
    data = _cp_tar(container, path, dl)
    if data is None:
        return FileFacts("absent")
    return _facts_from_tar(data)[0]


def read_container_bytes(container: str, path: str, dl: Deadline,
                         limit: int = MAX_SMALL_FILE) -> tuple[FileFacts, bytes | None]:
    data = _cp_tar(container, path, dl)
    if data is None:
        return FileFacts("absent"), None
    return _facts_from_tar(data, want_bytes=limit)


def read_many(container: str, paths: list[str], dl: Deadline) -> dict[str, FileFacts]:
    """read_container_file for many paths, in parallel (bounded)."""
    uniq = list(dict.fromkeys(paths))
    if not uniq:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(uniq)))) as ex:
        res = list(ex.map(lambda p: read_container_file(container, p, dl), uniq))
    return dict(zip(uniq, res))


def snapshot(container: str, paths: list[str], budget_s: float = 120.0) -> dict:
    """{"facts": {path: facts-md}, "error": str|None}: what the grading surface
    holds right now. The scorer takes one before verify.sh and one after, both
    with the container frozen, and rejects any path that differs."""
    dl = Deadline(budget_s)
    out: dict = {"facts": {}, "error": None}
    if len(paths) > MAX_FINDINGS:
        out["error"] = f"{len(paths)} paths exceed the snapshot bound {MAX_FINDINGS}"
        return out
    try:
        for p, ff in read_many(container, paths, dl).items():
            out["facts"][p] = ff.to_md()
    except Exception as e:  # noqa: BLE001 -- caller treats an error as "no evidence"
        out["error"] = f"{type(e).__name__}: {e}"[:300]
    return out


def _facts_from_disk(p: Path) -> FileFacts:
    try:
        st = p.lstat()
    except FileNotFoundError:
        return FileFacts("absent")
    if _st.S_ISLNK(st.st_mode):
        return FileFacts("symlink", linkname=os.readlink(p), mode=st.st_mode & 0o7777)
    if _st.S_ISREG(st.st_mode):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        return FileFacts("file", sha256=h.hexdigest(), mode=st.st_mode & 0o7777,
                         size=st.st_size)
    return FileFacts("other", mode=st.st_mode & 0o7777)


class ImageView:
    """Read-only view of the ORIGINAL image via a created, never-started
    container. Always removed (close())."""

    def __init__(self, image_id: str, dl: Deadline):
        self.image_id = image_id
        self.dl = dl
        self.name = TEMP_CONTAINER_PREFIX + uuid.uuid4().hex[:12]
        r = _run(["docker", "create", "--name", self.name, "--network", "none",
                  "--label", "sysrepair.pkgverify=1", "--entrypoint", "",
                  image_id, "true"], dl, cap=60)
        if r.returncode != 0:
            self.name = None
            raise Unverifiable("docker create of original image failed: "
                               + r.stderr.decode("utf-8", "replace").strip()[:200])

    def file(self, path: str) -> FileFacts:
        return read_container_file(self.name, path, self.dl)

    def bytes(self, path: str, limit: int = MAX_SMALL_FILE) -> tuple[FileFacts, bytes | None]:
        return read_container_bytes(self.name, path, self.dl, limit)

    def tar(self, path: str) -> bytes | None:
        return _cp_tar(self.name, path, self.dl)

    def close(self) -> None:
        if self.name:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True,
                           timeout=60, check=False)
            self.name = None


def container_image_id(cid: str, dl: Deadline) -> str:
    r = _run(["docker", "inspect", "--format", "{{.Image}}", cid], dl, cap=30)
    if r.returncode != 0:
        raise Unverifiable("docker inspect of episode container failed")
    return r.stdout.decode().strip()


def image_arch(image_id: str, dl: Deadline) -> str:
    r = _run(["docker", "image", "inspect", "--format", "{{.Architecture}}", image_id],
             dl, cap=30)
    arch = r.stdout.decode().strip() if r.returncode == 0 else ""
    return {"386": "i386", "arm": "armhf"}.get(arch, arch or "amd64")


# ----------------------------------------------------------------------------
# dpkg database parsing (hints only when read from the episode container)
# ----------------------------------------------------------------------------

def parse_dpkg_status(text: str) -> dict[str, str]:
    """{package: version} for installed packages."""
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        pkg = ver = status = None
        for line in block.splitlines():
            if line.startswith("Package:"):
                pkg = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                ver = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].strip()
        on_disk = ("installed", "unpacked", "half-configured", "half-installed",
                   "triggers-awaited", "triggers-pending")
        if pkg and ver and (status is None or status.split()[-1] in on_disk):
            out[pkg] = ver
    return out


_ALIASES = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"), ("/lib/", "/usr/lib/"),
            ("/lib32/", "/usr/lib32/"), ("/lib64/", "/usr/lib64/"),
            ("/libx32/", "/usr/libx32/"))


def _alias_paths(path: str) -> list[str]:
    """The path and its merged-/usr twin (/bin/x <-> /usr/bin/x)."""
    out = [path]
    for a, b in _ALIASES:
        if path.startswith(a):
            out.append(b + path[len(a):])
        elif path.startswith(b):
            out.append(a + path[len(b):])
    return out


def owners_from_info_tar(data: bytes, wanted: set[str]) -> dict[str, set[str]]:
    """{path: {package}} from a tar of /var/lib/dpkg/info, for wanted paths."""
    owners: dict[str, set[str]] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        for m in tf:
            if not m.isfile() or not m.name.endswith(".list"):
                continue
            pkg = m.name.rsplit("/", 1)[-1][:-5].split(":", 1)[0]
            f = tf.extractfile(m)
            if f is None:
                continue
            for line in f.read().decode("utf-8", "replace").splitlines():
                if line in wanted:
                    owners.setdefault(line, set()).add(pkg)
    return owners


def read_dpkg_db(container: str, paths: list[str], dl: Deadline
                 ) -> tuple[dict[str, str], dict[str, set[str]]] | None:
    """(status versions, owners-by-observed-path) or None when not dpkg-based."""
    st = _cp_tar(container, "/var/lib/dpkg/status", dl)
    if st is None:
        return None
    with tarfile.open(fileobj=io.BytesIO(st), mode="r:") as tf:
        m = tf.getmembers()[0]
        status = parse_dpkg_status(tf.extractfile(m).read().decode("utf-8", "replace")) \
            if m.isfile() else {}
    wanted: set[str] = set()
    alias_of: dict[str, set[str]] = {}
    for p in paths:
        for a in _alias_paths(p):
            wanted.add(a); alias_of.setdefault(a, set()).add(p)
    owners: dict[str, set[str]] = {}
    if wanted:
        info = _cp_tar(container, "/var/lib/dpkg/info", dl)
        if info is not None:
            for a, pk in owners_from_info_tar(info, wanted).items():
                for p in alias_of[a]:
                    owners.setdefault(p, set()).update(pk)
    return status, owners


def detect_backend(view: ImageView) -> str:
    if view.tar("/var/lib/dpkg/status") is not None:
        return "dpkg"
    if view.tar("/lib/apk/db/installed") is not None:
        return "apk"
    if view.tar("/var/lib/rpm") is not None or view.tar("/usr/lib/sysimage/rpm") is not None:
        return "rpm"
    return "unknown"


# ----------------------------------------------------------------------------
# Trusted archive client
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class AptSource:
    uri: str
    suite: str
    components: tuple
    signed_by: tuple = ()


def parse_sources(files: dict[str, str]) -> list[AptSource]:
    """apt sources from one-line (.list) and deb822 (.sources) files."""
    out: list[AptSource] = []
    for name, text in files.items():
        if name.endswith(".sources"):
            for block in re.split(r"\n\s*\n", text):
                fields: dict[str, str] = {}
                key = None
                for line in block.splitlines():
                    if line.startswith("#"):
                        continue
                    if line[:1] in (" ", "\t") and key:
                        fields[key] += " " + line.strip()
                        continue
                    if ":" in line:
                        key, v = line.split(":", 1)
                        key = key.strip().lower(); fields[key] = v.strip()
                if "deb" not in fields.get("types", "").split():
                    continue
                if fields.get("enabled", "yes").lower() == "no":
                    continue
                sb = tuple(s for s in fields.get("signed-by", "").split() if s.startswith("/"))
                for uri in fields.get("uris", "").split():
                    for suite in fields.get("suites", "").split():
                        out.append(AptSource(uri.rstrip("/"), suite,
                                             tuple(fields.get("components", "").split()), sb))
        else:
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line.startswith("deb "):
                    continue
                opts = ()
                m = re.match(r"deb\s+\[([^\]]*)\]\s+(.*)", line)
                rest = line[4:].strip()
                if m:
                    opts = tuple(m.group(1).split())
                    rest = m.group(2)
                parts = rest.split()
                if len(parts) < 2:
                    continue
                sb = tuple(o.split("=", 1)[1] for o in opts if o.startswith("signed-by="))
                out.append(AptSource(parts[0].rstrip("/"), parts[1], tuple(parts[2:]), sb))
    return [s for s in out if s.uri.startswith(("http://", "https://"))]


_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


class _FileLock:
    """Thread + process lock on a cache key."""

    def __init__(self, path: Path):
        self.path = path
        self.tlock = _lock_for(str(path))

    def __enter__(self):
        self.tlock.acquire()
        try:
            _mkdir_private(self.path.parent)
            self.fh = open(self.path, "a+")
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        except BaseException:
            self.tlock.release()
            raise
        return self

    def __exit__(self, *a):
        try:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
        finally:
            self.tlock.release()


def _mkdir_private(p: Path) -> None:
    p.mkdir(mode=0o700, parents=True, exist_ok=True)


def secure_cache_dir(cache: Path) -> Path:
    """Create the cache as 0700, and refuse one that someone else could write.

    Every cached artifact is re-hashed against its trusted key on read, so a
    corrupted entry is detected rather than trusted. This check keeps the
    directory itself private: it must be a real directory (not a symlink),
    owned by the scoring user, and neither group- nor other-writable."""
    try:
        if not os.path.lexists(cache):
            cache.parent.mkdir(parents=True, exist_ok=True)
            os.mkdir(cache, 0o700)
            os.chmod(cache, 0o700)
        st = os.lstat(cache)
    except OSError as e:
        raise Unverifiable(f"cache dir {cache}: {e}") from None
    if not _st.S_ISDIR(st.st_mode):
        raise Unverifiable(f"cache dir {cache} is not a directory (symlink or file)")
    if st.st_uid != os.geteuid():
        raise Unverifiable(f"cache dir {cache} is owned by uid {st.st_uid}, not the scorer")
    if st.st_mode & 0o022:
        raise Unverifiable(f"cache dir {cache} is group- or other-writable "
                           f"(mode {oct(st.st_mode & 0o777)}); refusing it. "
                           f"chmod 700 it to use it again")
    return cache


def _http_get(url: str, dl: Deadline, max_bytes: int = 256 * 1024 * 1024) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=dl.timeout(HTTP_TIMEOUT_S)) as r:
            chunks, size = [], 0
            while True:
                dl.check()
                b = r.read(1 << 20)
                if not b:
                    break
                size += len(b)
                if size > max_bytes:
                    raise Unverifiable(f"{url}: exceeds {max_bytes} bytes")
                chunks.append(b)
            return b"".join(chunks)
    except urllib.error.HTTPError as e:
        raise Unverifiable(f"GET {url}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        if isinstance(e, BudgetExceeded):
            raise
        raise Unverifiable(f"GET {url}: {type(e).__name__}: {e}") from None


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._+-]", "_", s)[:150]


def _atomic_write(path: Path, data: bytes) -> None:
    _mkdir_private(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _hash(algo: str, data: bytes) -> str:
    return hashlib.new(algo, data).hexdigest()


_HASH_FIELDS = (("SHA256", "sha256"), ("SHA1", "sha1"), ("MD5Sum", "md5"))


def _clearsigned_body(text: str) -> str:
    """The signed content of a clearsigned InRelease. Refuses anything that is
    not exactly one signed message (apt's rule)."""
    head = "-----BEGIN PGP SIGNED MESSAGE-----"
    sig = "-----BEGIN PGP SIGNATURE-----"
    if text.count(head) != 1 or text.count(sig) != 1 or text.lstrip()[:len(head)] != head:
        raise Unverifiable("InRelease is not a single clearsigned message")
    body = text.split(head, 1)[1]
    hdr, _, body = body.partition("\n\n")
    body = body.split("\n" + sig, 1)[0]
    return "\n".join(l[2:] if l.startswith("- ") else l for l in body.split("\n"))


def parse_release(text: str) -> dict[str, dict[str, tuple[str, int]]]:
    """{algo: {relpath: (hexdigest, size)}} from a Release body."""
    out: dict[str, dict[str, tuple[str, int]]] = {}
    cur = None
    for line in text.splitlines():
        if line and line[0] not in " \t":
            key = line.split(":", 1)[0]
            cur = dict(_HASH_FIELDS).get(key)
            if cur:
                out.setdefault(cur, {})
            continue
        if cur and line.strip():
            parts = line.split()
            if len(parts) == 3:
                out[cur][parts[2]] = (parts[0].lower(), int(parts[1]))
    return out


def parse_packages(text: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for block in text.split("\n\n"):
        e: dict = {}
        for line in block.splitlines():
            if not line or line[0] in " \t":
                continue
            k, _, v = line.partition(":")
            if k in ("Package", "Version", "Filename", "Size", "SHA256", "SHA1",
                     "MD5sum", "Architecture"):
                e[k] = v.strip()
        if "Package" in e and "Version" in e and "Filename" in e:
            out.setdefault(e["Package"], []).append(e)
    return out


# In-process memos. They hold only data derived from bytes that were hashed
# against a signed key in THIS process, so a write to the on-disk cache cannot
# reach them. Bounded.
_INDEX_MEMO: dict[str, dict] = {}
_MEMO_MAX = 48
_DEB_MEMO: dict[str, "DebContents"] = {}
_DEB_MEMO_MAX = 1024


def _memo_put(memo: dict, key: str, val, cap: int) -> None:
    with _locks_guard:
        if len(memo) >= cap:
            memo.pop(next(iter(memo)))
        memo[key] = val


def _norm_member(name: str) -> str:
    n = name[2:] if name.startswith("./") else name.lstrip("/")
    return posixpath.normpath("/" + n)


@dataclass
class DebContents:
    files: dict            # {abs path: FileFacts}
    scripts: dict          # {'postinst'|'preinst'|'postrm'|'prerm': text}


def _deb_contents(debp: Path, dl: Deadline) -> DebContents:
    """Facts of every payload member (`dpkg-deb --fsys-tarfile`, hashed while
    streaming; hardlinks resolved) and the maintainer scripts
    (`dpkg-deb --ctrl-tarfile`). Nothing is unpacked to disk."""
    files: dict[str, FileFacts] = {}
    links: list[tuple[str, str]] = []
    p = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(debp)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killer = threading.Timer(dl.timeout(300), p.kill)
    killer.start()
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|") as tf:
            for m in tf:
                name = _norm_member(m.name)
                if m.isdir():
                    continue
                if m.issym():
                    files[name] = FileFacts("symlink", linkname=m.linkname, mode=m.mode)
                elif m.islnk():
                    links.append((name, _norm_member(m.linkname)))
                elif m.isfile():
                    f = tf.extractfile(m)
                    h = hashlib.sha256()
                    size = 0
                    for b in iter(lambda: f.read(1 << 20), b""):
                        h.update(b); size += len(b)
                    files[name] = FileFacts("file", sha256=h.hexdigest(), mode=m.mode,
                                            size=size)
                else:
                    files[name] = FileFacts("other", mode=m.mode)
        err = p.stderr.read()
        rc = p.wait(timeout=dl.timeout(60))
    except tarfile.TarError as e:
        p.kill(); p.wait()
        raise Unverifiable(f"dpkg-deb --fsys-tarfile {debp.name}: {e}") from None
    finally:
        killer.cancel()
    if rc != 0:
        raise Unverifiable(f"dpkg-deb --fsys-tarfile failed: "
                           + err.decode("utf-8", "replace")[:200])
    for name, target in links:
        files[name] = files.get(target, FileFacts("other"))
    scripts: dict[str, str] = {}
    r = _run(["dpkg-deb", "--ctrl-tarfile", str(debp)], dl, cap=60)
    if r.returncode == 0:
        with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tf:
            for m in tf:
                base = _norm_member(m.name).rsplit("/", 1)[-1]
                if m.isfile() and base in ("postinst", "preinst", "postrm", "prerm"):
                    scripts[base] = tf.extractfile(m).read(1 << 20).decode("utf-8", "replace")
    return DebContents(files, scripts)


class Archive:
    """Authenticated access to the apt archive(s) an image uses.

    Disk cache layout (all re-verified on every read):
      release/<base>/{InRelease | Release, Release.gpg}  -> gpgv re-run
      packages/<algo>-<digest><ext>                       -> re-hashed
      debs/<algo>-<digest>.deb                            -> re-hashed
    """

    def __init__(self, sources: list[AptSource], arch: str, keyrings: list[Path],
                 dl: Deadline, cache: Path = CACHE_DIR):
        self.sources = sources
        self.arch = arch
        self.keyrings = keyrings
        self.dl = dl
        self.cache = cache
        self.notes: list[str] = []
        self._indices: list[tuple[AptSource, dict[str, list[dict]], str]] | None = None
        self._loaded: dict[tuple[str, str], tuple] = {}

    # -- signed Release --
    def _gpgv(self, sig_args: list[str]) -> tuple[bool, str]:
        if not self.keyrings:
            return False, "no keyring in original image"
        argv = ["gpgv", "--status-fd", "1"]
        for k in self.keyrings:
            argv += ["--keyring", str(k)]
        r = _run(argv + sig_args, self.dl, cap=60)
        status = r.stdout.decode("utf-8", "replace")
        good = re.findall(r"^\[GNUPG:\] VALIDSIG ", status, re.M)
        # apt's rule: at least one valid signature from a key in the image's
        # keyring and no bad or revoked one. A second signer whose key the
        # image does not carry (ERRSIG ... NO_PUBKEY) is tolerated, as apt does.
        bad = re.findall(r"^\[GNUPG:\] (BADSIG|REVKEYSIG) ", status, re.M)
        return bool(good) and not bad, status[-400:]

    def _verify_release_files(self, files: dict[str, bytes], base: str) -> tuple[str, str]:
        """Signature check of raw Release material against THIS image's
        keyrings. Returns (signed body, how)."""
        with tempfile.TemporaryDirectory() as td:
            if "InRelease" in files:
                p = Path(td) / "InRelease"; p.write_bytes(files["InRelease"])
                ok, st = self._gpgv([str(p)])
                if not ok:
                    raise Unverifiable(f"{base}/InRelease signature not valid: {st}")
                return (_clearsigned_body(files["InRelease"].decode("utf-8", "replace")),
                        "InRelease+gpgv")
            pr = Path(td) / "Release"; pr.write_bytes(files["Release"])
            ps = Path(td) / "Release.gpg"; ps.write_bytes(files["Release.gpg"])
            ok, st = self._gpgv([str(ps), str(pr)])
            if not ok:
                raise Unverifiable(f"{base}/Release signature not valid: {st}")
            return files["Release"].decode("utf-8", "replace"), "Release+Release.gpg+gpgv"

    def _fetch_release_files(self, base: str) -> dict[str, bytes]:
        try:
            return {"InRelease": _http_get(f"{base}/InRelease", self.dl, 64 << 20)}
        except Unverifiable:
            pass
        return {"Release": _http_get(f"{base}/Release", self.dl, 64 << 20),
                "Release.gpg": _http_get(f"{base}/Release.gpg", self.dl, 1 << 20)}

    @staticmethod
    def _read_cached_release(cdir: Path) -> dict[str, bytes] | None:
        if (cdir / "InRelease").is_file():
            return {"InRelease": (cdir / "InRelease").read_bytes()}
        if (cdir / "Release").is_file() and (cdir / "Release.gpg").is_file():
            return {"Release": (cdir / "Release").read_bytes(),
                    "Release.gpg": (cdir / "Release.gpg").read_bytes()}
        return None

    def _release(self, src: AptSource) -> tuple[dict, str]:
        base = f"{src.uri}/dists/{src.suite}"
        cdir = self.cache / "release" / _safe(base)
        with _FileLock(cdir / ".lock"):
            stamp = cdir / "fetched"
            cached = self._read_cached_release(cdir)
            fresh = stamp.exists() and time.time() - stamp.stat().st_mtime < INDEX_TTL_S
            if cached is not None and fresh:
                try:
                    body, how = self._verify_release_files(cached, base)
                    return parse_release(body), f"cached, {how} re-checked"
                except Unverifiable as e:
                    self.notes.append(f"{base}: cached Release failed re-verification "
                                      f"({e}); refetching")
            try:
                files = self._fetch_release_files(base)
                body, how = self._verify_release_files(files, base)
            except Unverifiable as e:
                if cached is not None:
                    try:
                        body, how = self._verify_release_files(cached, base)
                    except Unverifiable:
                        raise e from None
                    self.notes.append(f"{base}: refresh failed ({e}); using cached "
                                      "Release, signature re-checked")
                    return parse_release(body), f"stale-cache, {how} re-checked"
                raise
            for n in ("InRelease", "Release", "Release.gpg"):
                if n not in files and (cdir / n).exists():
                    (cdir / n).unlink()
            for n, data in files.items():
                _atomic_write(cdir / n, data)
            _atomic_write(stamp, b"")
            return parse_release(body), how

    # -- Packages indices --
    def _packages(self, src: AptSource, comp: str, hashes: dict) -> dict[str, list[dict]]:
        base = f"{src.uri}/dists/{src.suite}"
        stem = f"{comp}/binary-{self.arch}/Packages"
        for ext, dec in ((".xz", lzma.decompress), (".gz", gzip.decompress), ("", None)):
            rel = stem + ext
            ref = None
            for algo in ("sha256", "sha1", "md5"):
                if rel in hashes.get(algo, {}):
                    ref = (algo, *hashes[algo][rel]); break
            if ref is None:
                continue
            algo, digest, size = ref
            cpath = self.cache / "packages" / f"{algo}-{digest}{ext or '.raw'}"
            memo = _INDEX_MEMO.get(str(cpath))
            if memo is not None:
                return memo
            with _FileLock(self.cache / "packages" / f"{algo}-{digest}.lock"):
                raw = None
                if cpath.is_file():
                    raw = cpath.read_bytes()
                    if len(raw) != size or _hash(algo, raw) != digest:
                        self.notes.append(f"cached {cpath.name} failed re-hash; refetching")
                        raw = None
                if raw is None:
                    raw = _http_get(f"{base}/{rel}", self.dl)
                    if len(raw) != size or _hash(algo, raw) != digest:
                        raise Unverifiable(f"{base}/{rel}: hash does not match signed Release")
                    _atomic_write(cpath, raw)
                text = (dec(raw) if dec else raw).decode("utf-8", "replace")
                idx = parse_packages(text)
                _memo_put(_INDEX_MEMO, str(cpath), idx, _MEMO_MAX)
                return idx
        return {}

    def indices(self) -> list[tuple[AptSource, dict[str, list[dict]], str]]:
        if self._indices is not None:
            return self._indices
        out = []
        errors = []
        for src in self.sources:
            try:
                hashes, how = self._release(src)
                for comp in src.components:
                    out.append((src, self._packages(src, comp, hashes), how))
            except Unverifiable as e:
                errors.append(str(e))
        if errors:
            self.notes.extend(errors)
        if not out:
            raise Unverifiable("no trusted package index could be loaded: "
                               + "; ".join(errors)[:400])
        self._indices = out
        return out

    def find(self, pkg: str, version: str) -> tuple[AptSource, dict, str] | None:
        for src, idx, how in self.indices():
            for e in idx.get(pkg, []):
                if e["Version"] == version and e.get("Architecture") in (self.arch, "all", None):
                    return src, e, how
        return None

    def contents(self, src: AptSource, entry: dict) -> DebContents:
        """The .deb's payload facts and maintainer scripts. The cached .deb is
        re-hashed against the signed index entry on every read (copied to a
        private temp file while hashing, and only that copy is parsed)."""
        for fld, algo in (("SHA256", "sha256"), ("SHA1", "sha1"), ("MD5sum", "md5")):
            if entry.get(fld):
                digest = entry[fld].lower(); break
        else:
            raise Unverifiable(f"{entry['Package']} {entry['Version']}: no hash in index")
        key = f"{algo}-{digest}"
        memo = _DEB_MEMO.get(key)
        if memo is not None:
            return memo
        want_size = int(entry["Size"]) if entry.get("Size", "").isdigit() else None
        debs = self.cache / "debs"
        debp = debs / f"{key}.deb"
        with _FileLock(debs / f"{key}.lock"), tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / "pkg.deb"
            ok = False
            if debp.is_file():
                h = hashlib.new(algo); size = 0
                with open(debp, "rb") as fi, open(tmp, "wb") as fo:
                    for b in iter(lambda: fi.read(1 << 20), b""):
                        h.update(b); size += len(b); fo.write(b)
                ok = h.hexdigest() == digest and (want_size is None or size == want_size)
                if not ok:
                    self.notes.append(f"cached {debp.name} failed re-hash; refetching")
            if not ok:
                raw = _http_get(f"{src.uri}/{entry['Filename']}", self.dl)
                if _hash(algo, raw) != digest or (want_size is not None and len(raw) != want_size):
                    raise Unverifiable(f"{entry['Filename']}: hash does not match signed index")
                tmp.write_bytes(raw)
                _atomic_write(debp, raw)
            dc = _deb_contents(tmp, self.dl)
        _memo_put(_DEB_MEMO, key, dc, _DEB_MEMO_MAX)
        return dc

    def load(self, pkg: str, version: str):
        """(src, entry, how, DebContents) for pkg=version, or None when the
        signed indices do not carry it. Raises Unverifiable."""
        k = (pkg, version)
        if k in self._loaded:
            return self._loaded[k]
        hit = self.find(pkg, version)
        if hit is None:
            self._loaded[k] = None
            return None
        src, entry, how = hit
        out = (src, entry, how, self.contents(src, entry))
        self._loaded[k] = out
        return out


def _keyrings_from_image(view: ImageView, kdir: Path, signed_by: set[str]) -> list[Path]:
    """Binary keyrings from the original image, dearmored when needed, written
    to a private per-run directory."""
    out: list[Path] = []
    paths = ["/etc/apt/trusted.gpg", "/etc/apt/trusted.gpg.d", "/usr/share/keyrings",
             *sorted(signed_by)]
    for p in paths:
        data = view.tar(p)
        if data is None:
            continue
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                if not m.name.endswith((".gpg", ".asc", ".pgp")) and m.name != "trusted.gpg":
                    continue
                if "removed-keys" in m.name:
                    continue
                blob = tf.extractfile(m).read()
                dst = kdir / (_safe(m.name.replace("/", "__")) + ".bin")
                if blob.lstrip().startswith(b"-----BEGIN PGP"):
                    r = subprocess.run(["gpg", "--batch", "--dearmor"], input=blob,
                                       capture_output=True, timeout=30, check=False)
                    if r.returncode != 0:
                        continue
                    blob = r.stdout
                dst.write_bytes(blob)
                out.append(dst)
    return out


def _sources_from_image(view: ImageView) -> tuple[list[AptSource], dict[str, str]]:
    files: dict[str, str] = {}
    for p in ("/etc/apt/sources.list", "/etc/apt/sources.list.d"):
        data = view.tar(p)
        if data is None:
            continue
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for m in tf:
                if m.isfile() and (m.name.endswith((".list", ".sources"))):
                    files[m.name] = tf.extractfile(m).read().decode("utf-8", "replace")
    return parse_sources(files), files


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------

def compare_with_deb(observed: FileFacts, path: str, candidates: list[tuple[str, str]],
                     archive, dropped: list[str] | None = None) -> DebResult:
    """Compare against each pinned (package, version) candidate's file at
    `path`. `dropped` lists candidates refused by the version pin."""
    dropped = list(dropped or [])
    if not candidates:
        if dropped:
            return DebResult("downgrade", detail="; ".join(dropped)[:400], tried=dropped)
        return DebResult("no_candidate", detail="no package claims this path")
    tried = list(dropped)
    any_path_in_pkg = False
    unverifiable = []
    for pkg, ver in candidates[:MAX_CANDIDATE_VERSIONS]:
        try:
            hit = archive.load(pkg, ver)
            if hit is None:
                tried.append(f"{pkg}={ver}: not in trusted index")
                unverifiable.append(f"{pkg}={ver} not in archive")
                continue
            src, entry, how, dc = hit
        except Unverifiable as e:
            tried.append(f"{pkg}={ver}: {e}")
            unverifiable.append(str(e))
            continue
        differs = False
        for alias in _alias_paths(path):
            ref = dc.files.get(alias)
            if ref is None:
                continue
            any_path_in_pkg = True
            if observed.same_content(ref):
                return DebResult(
                    "match", package=pkg, version=ver,
                    trust=f"deb {src.uri} {src.suite} {entry['Filename']} ({how}; "
                          "index hash; dpkg-deb)",
                    tried=tried + [f"{pkg}={ver}: match at {alias}"])
            tried.append(f"{pkg}={ver}: differs at {alias}")
            differs = True
        if not differs:
            tried.append(f"{pkg}={ver}: path not shipped")
    if dropped:
        # The container claims a version the pin refuses, and no accepted
        # version explains the bytes.
        return DebResult("downgrade", detail="; ".join(tried)[:400], tried=tried)
    if any_path_in_pkg:
        return DebResult("mismatch", detail="; ".join(tried)[:400], tried=tried)
    if unverifiable:
        return DebResult("unverifiable", detail="; ".join(unverifiable)[:400], tried=tried)
    return DebResult("no_candidate", detail="; ".join(tried)[:400], tried=tried)


def pinned_versions(pkg: str, cont_status: dict[str, str], img_status: dict[str, str]
                    ) -> tuple[list[str], list[str]]:
    """(accepted versions, refusal notes) for one package.

    Only the version the container claims is installed (a hint; the bytes
    must still match it) and the version the ORIGINAL image has installed are
    candidates. A version older than the image's is refused: an older genuine
    build is not the package operation the image's state implies, and is how
    an observation tool would be swapped for one with different behaviour."""
    floor = img_status.get(pkg)
    out: list[str] = []
    notes: list[str] = []
    for v in (cont_status.get(pkg), img_status.get(pkg)):
        if not v or v in out:
            continue
        if floor and dpkg_version_compare(v, floor) < 0:
            notes.append(f"{pkg}={v}: refused, older than the original image's "
                         f"installed {floor}")
            continue
        out.append(v)
    return out, notes


def _candidates(path: str, cont_status: dict[str, str], cont_owners: dict[str, set[str]],
                img_status: dict[str, str], img_owners: dict[str, set[str]],
                archive=None) -> tuple[list[tuple[str, str]], list[str]]:
    pkgs: list[str] = []
    for p in sorted(img_owners.get(path, ())) + sorted(cont_owners.get(path, ())):
        if p not in pkgs:
            pkgs.append(p)
    out: list[tuple[str, str]] = []
    dropped: list[str] = []
    for p in pkgs:
        vers, notes = pinned_versions(p, cont_status, img_status)
        dropped += notes
        for v in vers:
            if (p, v) not in out:
                out.append((p, v))
    return out, dropped


def _word_in(text: str, needle: str) -> bool:
    return re.search(r"(?<![\w./+-])" + re.escape(needle) + r"(?![\w.+-])", text) is not None


def scripts_register_alternative(scripts: dict, name: str, target: str) -> bool:
    """Whether verified maintainer scripts call update-alternatives with this
    link name and this alternative path."""
    for text in scripts.values():
        if "update-alternatives" in text and _word_in(text, name) and target in text:
            return True
    return False


def _divert_chunks(text: str):
    """The text around each dpkg-divert call: a `for ... do` header that
    precedes it (loop variables) and the command's own arguments."""
    for m in re.finditer(r"dpkg-divert", text):
        yield text[max(0, m.start() - 400): m.end() + 400]


def scripts_divert(scripts: dict, path: str, to: str | None = None) -> bool:
    """Whether a verified maintainer script performs this diversion. The
    directory, the file name (as a word) and the divert target must all appear
    around ONE dpkg-divert call; the file name may come from a loop list
    (`for f in libx.so.0; do dpkg-divert ... "/lib/triple/$f"`), the target
    from a literal suffix of at least three characters (".usr-is-merged")."""
    d, _, base = path.rpartition("/")
    for text in scripts.values():
        for chunk in _divert_chunks(text):
            if path in chunk:
                named = True
            else:
                named = bool(d) and d in chunk and _word_in(chunk, base)
            if not named:
                continue
            if to is None or _word_in(chunk, to):
                return True
            if to.startswith(path) and len(to) - len(path) >= 3 \
                    and to[len(path):] in chunk:
                return True
    return False


def parse_diversions(text: str) -> set[tuple[str, str, str]]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) % 3:
        raise ValueError("diversions file is not a sequence of triplets")
    return {(lines[i], lines[i + 1], lines[i + 2]) for i in range(0, len(lines), 3)}


def alternatives_db_paths(text: str) -> set[str]:
    """Every line of /var/lib/dpkg/alternatives/NAME that is an absolute path
    (master/slave links and registered alternative files)."""
    return {l.strip() for l in text.splitlines() if l.strip().startswith("/")}


_DEP_FIELDS = ("Depends:", "Pre-Depends:")


def _dep_names(value: str) -> set[str]:
    """Package names mentioned in a Depends-style field (every alternative;
    version constraints and arch qualifiers dropped)."""
    out = set()
    for clause in value.split(","):
        for alt in clause.split("|"):
            name = alt.strip().split(None, 1)[0] if alt.strip() else ""
            name = name.split(":", 1)[0]
            if name:
                out.add(name)
    return out


def parse_dpkg_graph(text: str) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """({package: names it Depends/Pre-Depends on}, {virtual name: providers})
    for the packages in a dpkg status file."""
    deps: dict[str, set[str]] = {}
    provides: dict[str, set[str]] = {}
    for block in text.split("\n\n"):
        pkg = None
        dep: set[str] = set()
        prov: set[str] = set()
        field = None
        installed = True
        for line in block.splitlines():
            if line[:1] in (" ", "\t"):
                if field == "dep":
                    dep |= _dep_names(line)
                elif field == "prov":
                    prov |= _dep_names(line)
                continue
            field = None
            if line.startswith("Package:"):
                pkg = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                installed = line.split(":", 1)[1].split()[-1:] == ["installed"]
            elif line.startswith(_DEP_FIELDS):
                field = "dep"
                dep |= _dep_names(line.split(":", 1)[1])
            elif line.startswith("Provides:"):
                field = "prov"
                prov |= _dep_names(line.split(":", 1)[1])
        if pkg and installed:
            deps.setdefault(pkg, set()).update(dep)
            for v in prov:
                provides.setdefault(v, set()).add(pkg)
    return deps, provides


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self):
        import socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._sock_path)


def _docker_sock() -> str:
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://"):]
    return "/var/run/docker.sock"


def _engine_deleted(cid: str, dl: Deadline) -> set[str]:
    """Deleted paths (Kind 2) from GET /containers/{id}/changes."""
    conn = _UnixHTTPConnection(_docker_sock(), dl.timeout(90))
    try:
        conn.request("GET", f"/containers/{cid}/changes")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise ValueError(f"engine API status {resp.status}")
    finally:
        conn.close()
    data = json.loads(body.decode("utf-8", "surrogateescape"))
    if data is None:
        return set()
    return {e["Path"] for e in data if e.get("Kind") == 2 and isinstance(e.get("Path"), str)}


_COMPAT_TOP = frozenset({"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"})


def _head_kind(container: str, path: str, dl: Deadline) -> str:
    """'absent' | 'dir' | 'symlink' | 'file' from the first tar header only
    (never buffers the content). Only "no such file" means absent; any other
    docker cp failure raises Unverifiable."""
    p = subprocess.Popen(["docker", "cp", f"{container}:{path}", "-"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        hdr = p.stdout.read(512)
        if len(hdr) == 512:
            p.kill()
            p.communicate()
            flag = chr(hdr[156]) if hdr[156] else "0"
            return {"5": "dir", "2": "symlink"}.get(flag, "file")
        _out, err = p.communicate(timeout=dl.timeout(30))
    except subprocess.TimeoutExpired:
        p.kill(); p.communicate()
        raise Unverifiable(f"docker cp {path} timed out")
    if b"Could not find the file" in err or b"No such" in err:
        return "absent"
    raise Unverifiable(f"docker cp {path} failed: {err.decode('utf-8', 'replace')[:120]}")


def _image_path_dirs(image_id: str, dl: Deadline) -> list[str]:
    """PATH directories of the image's Config.Env, plus the defaults."""
    dirs = list(_PATH_DIRS)
    try:
        r = _run(["docker", "image", "inspect", "-f", "{{json .Config.Env}}", image_id],
                 dl, cap=30)
        for e in json.loads(r.stdout.decode() or "null") or []:
            if e.startswith("PATH="):
                for d in e[5:].split(":"):
                    d = d.rstrip("/") or "/"
                    if d.startswith("/") and d not in dirs:
                        dirs.append(d)
    except Exception:  # noqa: BLE001 -- defaults only
        pass
    return dirs


class _PkgDb:
    """The ORIGINAL image's dpkg database: per package the regular files it
    installed (md5sums intersected with the .list, minus conffiles) and the
    reverse-dependency graph. Trusted: read from the never-started image."""

    def __init__(self, status_text: str, info_tar: bytes):
        deps, provides = parse_dpkg_graph(status_text)
        self.rdeps: dict[str, set[str]] = {}
        for q, names in deps.items():
            for n in names:
                for p in {n} | provides.get(n, set()):
                    if p != q:
                        self.rdeps.setdefault(p, set()).add(q)
        lists: dict[str, set[str]] = {}
        md5: dict[str, set[str]] = {}
        conf: dict[str, set[str]] = {}
        with tarfile.open(fileobj=io.BytesIO(info_tar), mode="r:") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                base = m.name.rsplit("/", 1)[-1]
                stem, _, ext = base.rpartition(".")
                if ext not in ("list", "md5sums", "conffiles"):
                    continue
                pkg = stem.split(":", 1)[0]
                f = tf.extractfile(m)
                if f is None:
                    continue
                lines = f.read().decode("utf-8", "replace").splitlines()
                if ext == "list":
                    lists.setdefault(pkg, set()).update(
                        l for l in lines if l not in ("/", "/.", ""))
                elif ext == "md5sums":
                    md5.setdefault(pkg, set()).update(
                        "/" + l.split(None, 1)[1].strip() for l in lines
                        if len(l.split(None, 1)) == 2)
                else:
                    conf.setdefault(pkg, set()).update(l.strip() for l in lines)
        self.files: dict[str, set[str]] = {
            p: (md5.get(p, set()) & lists.get(p, set())) - conf.get(p, set())
            for p in lists}
        # Entries that are not directories of any package but are not regular
        # md5summed files either: symlinks (and empty directories).
        dirs: set[str] = set()
        for ls in lists.values():
            for e in ls:
                a = e.rpartition("/")[0]
                while a and a not in dirs:
                    dirs.add(a)
                    a = a.rpartition("/")[0]
        self.extras: dict[str, set[str]] = {
            p: {e for e in lists[p] if e not in dirs and e != "/"}
            - self.files[p] - md5.get(p, set()) - conf.get(p, set())
            for p in lists}


class _Ctx:
    """Everything gathered once per episode, shared by the per-class deciders."""

    def __init__(self, cid, view, dl, backend):
        self.cid, self.view, self.dl, self.backend = cid, view, dl, backend
        self.archive = None
        self.archive_reason = "original image names no http(s) apt source"
        self.cont_status: dict[str, str] = {}
        self.cont_owners: dict[str, set[str]] = {}
        self.img_status: dict[str, str] = {}
        self.img_owners: dict[str, set[str]] = {}
        self._deleted: set[str] | None = None
        self._pkgdb: _PkgDb | None = None
        self._pkgdb_tried = False
        self._wholly: dict[str, bool] = {}

    def full_deleted(self) -> set[str]:
        """Every path the daemon reports deleted, from the Engine API's JSON
        (exact paths). `docker diff` text is NOT used: a file name containing a
        newline would let the agent forge `D /usr` lines."""
        if self._deleted is None:
            try:
                dele = _engine_deleted(self.cid, self.dl)
            except (OSError, ValueError, http.client.HTTPException) as e:
                raise Unverifiable(f"container changes unavailable: {e}"[:200])
            self._deleted = dele
        return self._deleted

    def _is_deleted(self, path: str) -> bool:
        """`path` itself, or a real ancestor directory of it, is deleted. The
        merged-/usr twin is matched EXACTLY and the compat top-level entries
        (/bin, /sbin, /lib*: symlinks on merged-/usr images) are never ancestors,
        so `rm /bin` cannot make every /usr/bin file look deleted."""
        dele = self.full_deleted()
        for i, form in enumerate(_alias_paths(path)):
            if form in dele:
                return True
            if i:
                continue
            a = form.rpartition("/")[0]
            while a and a not in _COMPAT_TOP:
                if a in dele:
                    return True
                a = a.rpartition("/")[0]
        return False

    def pkgdb(self) -> "_PkgDb | None":
        if self._pkgdb_tried or self.backend != "dpkg" or self.view is None:
            return self._pkgdb
        self._pkgdb_tried = True
        try:
            st = self.view.tar("/var/lib/dpkg/status")
            info = self.view.tar("/var/lib/dpkg/info")
            if st is None or info is None:
                return None
            with tarfile.open(fileobj=io.BytesIO(st), mode="r:") as tf:
                ms = tf.getmembers()
                text = tf.extractfile(ms[0]).read().decode("utf-8", "replace") \
                    if ms and ms[0].isfile() else ""
            self._pkgdb = _PkgDb(text, info)
        except Exception:  # noqa: BLE001 -- no database: nothing is explained
            self._pkgdb = None
        return self._pkgdb

    def wholly_removed(self, pkg: str) -> bool:
        """Every regular file the original image installed for `pkg` (except
        conffiles, which a plain `remove` keeps) is deleted in the frozen
        container, and no symlink/file the package listed survives: a package
        removal/purge, not piecemeal deletion. A package with no files at all
        (a metapackage) is vacuously removed. Errors cache as False."""
        if pkg not in self._wholly:
            self._wholly[pkg] = False
            db = self.pkgdb()
            files = db.files.get(pkg) if db is not None else None
            ok = files is not None and all(self._is_deleted(f) for f in files)
            if ok:
                left = [e for e in sorted(db.extras.get(pkg, ())) if not self._is_deleted(e)]
                if len(left) > 64:
                    ok = False
                else:
                    for e in left:
                        if self.cid and _head_kind(self.cid, e, self.dl) in ("symlink", "file"):
                            ok = False
                            break
            self._wholly[pkg] = ok
        return self._wholly[pkg]

    def runtime_module_blocks(self, path: str) -> bool:
        """True when `path` is a module loaded at RUNTIME (PAM, NSS, gconv,
        OpenSSL providers, python/perl extension dirs) that something surviving
        still names: the dependency closure cannot see that edge."""
        base = path.rsplit("/", 1)[-1]
        if "/security/" in path and base.endswith(".so"):
            tar = _cp_tar(self.cid, "/etc/pam.d", self.dl)
            text = b""
            if tar:
                with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as tf:
                    for m in tf:
                        f = tf.extractfile(m) if m.isfile() else None
                        text += (f.read() if f else b"") + b"\n"
            conf = _cp_tar(self.cid, "/etc/pam.conf", self.dl)
            if conf:
                with tarfile.open(fileobj=io.BytesIO(conf), mode="r:") as tf:
                    for m in tf:
                        f = tf.extractfile(m) if m.isfile() else None
                        text += (f.read() if f else b"")
            return re.search(rb"(?<![\w.-])" + re.escape(base.encode()) + rb"(?![\w.])",
                             text) is not None or tar is None
        m = re.match(r"libnss_([A-Za-z0-9_]+)\.so", base)
        if m:
            tar = _cp_tar(self.cid, "/etc/nsswitch.conf", self.dl)
            if tar is None:
                return True
            with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as tf:
                ms = tf.getmembers()
                text = tf.extractfile(ms[0]).read() if ms and ms[0].isfile() else b""
            return re.search(rb"(?<![\w.-])" + re.escape(m.group(1).encode()) + rb"(?![\w.-])",
                             text) is not None
        return any(seg in path for seg in ("/gconv/", "/ossl-modules/", "/lib-dynload/",
                                           "/auto/", "/engines-", "/pam_"))

    def safe_removal_explained(self, pkgs) -> bool:
        """removal_explained for every owner; ANY error means 'not explained'."""
        try:
            pkgs = sorted(pkgs)
            return bool(pkgs) and all(self.removal_explained(p) for p in pkgs)
        except Exception:  # noqa: BLE001 -- fail closed
            return False

    def removal_explained(self, pkg: str) -> bool:
        """`pkg` is wholly removed AND so is every package of the original
        image that depends on it (transitively): the shape of apt purge /
        autoremove. Deleting a library out from under a package that stays
        installed (dpkg --force-depends) is exactly what this refuses."""
        db = self.pkgdb()
        if db is None:
            return False
        seen: set[str] = set()
        stack = [pkg]
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            if not self.wholly_removed(p):
                return False
            stack.extend(sorted(db.rdeps.get(p, ())))
        return True

    def deb_compare(self, obs: FileFacts, path: str) -> DebResult:
        if self.backend != "dpkg":
            return DebResult("unsupported")
        if self.archive is None:
            return DebResult("unverifiable", detail=self.archive_reason)
        try:
            cands, dropped = _candidates(path, self.cont_status, self.cont_owners,
                                         self.img_status, self.img_owners)
            return compare_with_deb(obs, path, cands, self.archive, dropped)
        except Unverifiable as e:
            return DebResult("unverifiable", detail=str(e)[:300])

    def load_pinned(self, pkg: str):
        """[(version, load-result)] for the pinned versions of pkg."""
        out = []
        if self.archive is None:
            return out
        vers, _notes = pinned_versions(pkg, self.cont_status, self.img_status)
        for v in vers:
            try:
                hit = self.archive.load(pkg, v)
            except Unverifiable:
                hit = None
            if hit is not None:
                out.append((v, hit))
        return out


def _soname_link_target(path: str, obs: FileFacts) -> str | None:
    """The sibling an ldconfig-style soname link points to (libfoo.so.1 ->
    libfoo.so.1.2.3, same directory), or None if obs is not one."""
    if obs.kind != "symlink" or not obs.linkname or "/" in obs.linkname:
        return None
    base = path.rsplit("/", 1)[-1]
    tgt = obs.linkname
    if tgt == base or not tgt.startswith(base) or not _SO_NAME_RE.search(tgt):
        return None
    return path.rsplit("/", 1)[0] + "/" + tgt


def _decide_lib_deletion(path: str, ctx: _Ctx) -> Decision:
    if ctx.backend != "dpkg":
        return Decision(False, "deletion of a shared object (no verified package "
                        "operation explains it)", "not_applicable")
    for pkg in sorted(ctx.img_owners.get(path, ())) if ctx.archive is not None else ():
        cv, iv = ctx.cont_status.get(pkg), ctx.img_status.get(pkg)
        if not cv or not iv or dpkg_version_compare(cv, iv) <= 0:
            continue
        try:
            hit = ctx.archive.load(pkg, cv)
        except Unverifiable:
            continue
        if hit is None:
            continue
        src, entry, how, dc = hit
        if not any(a in dc.files for a in _alias_paths(path)):
            return Decision(True, f"the upgrade of {pkg} to {cv} no longer ships this "
                            "shared object", "dropped_by_upgrade",
                            trust=f"deb {src.uri} {src.suite} {entry['Filename']} ({how})",
                            package=pkg, version=cv)
    owners = sorted(ctx.img_owners.get(path, ()))
    try:
        blocked = ctx.runtime_module_blocks(path)
    except Exception:  # noqa: BLE001 -- fail closed
        blocked = True
    if not blocked and ctx.safe_removal_explained(owners):
        return Decision(True, f"every file of {', '.join(owners)} (and of every "
                        "package that depends on it) is deleted: a package "
                        "removal, not piecemeal deletion", "removed_with_package",
                        trust="image dpkg database + engine changes",
                        package=owners[0])
    return Decision(False, "deletion of a shared object that no verified upgrade of "
                    "its owner explains", "not_applicable")


_PATH_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
              "/sbin", "/bin")


def _shadows_image_binary(base: str, path: str, view, dirs=None) -> bool:
    """Whether the ORIGINAL image already has a binary called `base` in some
    PATH directory other than `path` (or its merged-/usr twin). A docker cp
    failure other than 'not found' raises (the caller rejects)."""
    twins = set(_alias_paths(path))
    for d in (dirs or _PATH_DIRS):
        cand = f"{d}/{base}"
        if cand in twins:
            continue
        if _head_kind(view.name, cand, view.dl) != "absent":
            return True
    return False


def _decide_binary_deletion(path: str, ctx: _Ctx, verify_script: str | None) -> Decision:
    base = path.rsplit("/", 1)[-1]
    if ctx.backend != "dpkg":
        return Decision(False, "deletion of a grading-critical binary", "not_applicable")
    if verify_script is None or verifier_runs(base, verify_script):
        return Decision(False, "deletion of a binary the scenario verifier executes",
                        "not_applicable")
    owners = sorted(ctx.img_owners.get(path, ()))
    if ctx.safe_removal_explained(owners):
        return Decision(True, f"every file of {', '.join(owners)} (and of every "
                        "package that depends on it) is deleted: a package "
                        "removal, not piecemeal deletion of a tool",
                        "removed_with_package",
                        trust="image dpkg database + engine changes",
                        package=owners[0])
    link = _deleted_link_to_deleted_target(path, ctx)
    if link:
        return Decision(True, f"symlink to {link}, which is itself deleted: removing the "
                        "link adds nothing beyond that deletion (judged on its own)",
                        "link_to_deleted_target", trust="image + engine changes")
    return Decision(False, "deletion of a grading-critical binary", "not_applicable")


def _deleted_link_to_deleted_target(path: str, ctx: _Ctx) -> str | None:
    """The target when `path` was a symlink in the ORIGINAL image whose
    resolved target is deleted in the container (e.g. /usr/lib/cpp ->
    ../bin/cpp, a link a maintainer script made, so no .list owns it)."""
    if ctx.view is None:
        return None
    try:
        f = ctx.view.file(path)
        if f.kind != "symlink" or not f.linkname:
            return None
        tgt = f.linkname if f.linkname.startswith("/") else \
            posixpath.normpath(posixpath.join(posixpath.dirname(path), f.linkname))
        return tgt if ctx._is_deleted(tgt) else None
    except Exception:  # noqa: BLE001 -- fail closed
        return None


def _decide_alternative(op: str, path: str, obs: FileFacts | None,
                        image_ref: FileFacts | None, ctx: _Ctx,
                        critical_names: frozenset,
                        verify_script: str | None = None) -> Decision:
    name = path[len(ALT_DIR):]
    if op == "D":
        if name in critical_names:
            return Decision(False, f"alternatives link for grading-critical name "
                            f"{name!r} deleted", "alternative_deleted")
        return Decision(True, "alternatives link removed for a name the verifier "
                        "does not depend on", "alternative_removed", trust="name")
    if obs is None or obs.kind == "absent":
        return Decision(False, "alternatives link could not be read", "unverifiable")
    if image_ref is not None and obs.same_content(image_ref):
        return Decision(True, "content identical to the original scenario image",
                        "image_match", trust="image")
    if obs.kind != "symlink" or not obs.linkname or not obs.linkname.startswith("/") \
            or posixpath.normpath(obs.linkname) != obs.linkname \
            or obs.linkname.startswith(ALT_DIR):
        return Decision(False, "alternatives entry is not a link to an absolute, "
                        "normalized package path", "alternative_retarget")
    target = obs.linkname
    tobs = read_container_file(ctx.cid, target, ctx.dl)
    if tobs.kind == "absent":
        return Decision(False, f"alternatives link points to a missing file {target}",
                        "alternative_retarget")
    # Registered in the ORIGINAL image's alternatives database?
    img_registered = False
    _f, db = ctx.view.bytes(f"/var/lib/dpkg/alternatives/{name}")
    if db is not None:
        img_registered = target in alternatives_db_paths(db.decode("utf-8", "replace"))
    timg = ctx.view.file(target)
    if img_registered and tobs.same_content(timg):
        return Decision(True, f"retargeted to {target}, registered for {name!r} in the "
                        "original image and unchanged from it", "alternative_image",
                        trust="image")
    if ctx.backend != "dpkg":
        return Decision(False, f"package verification unsupported for backend "
                        f"{ctx.backend!r}", "unsupported")
    deb = ctx.deb_compare(tobs, target)
    if deb.status != "match":
        return Decision(False, f"alternatives link points to {target}, which is not a "
                        f"genuine package file ({deb.status}"
                        + (f": {deb.detail[:250]}" if deb.detail else "") + ")",
                        "alternative_retarget", package=deb.package, version=deb.version)
    hit = ctx.archive.load(deb.package, deb.version) if ctx.archive else None
    if img_registered or (hit and scripts_register_alternative(hit[3].scripts, name, target)):
        return Decision(True, f"links to {target}, a genuine file of {deb.package} "
                        f"{deb.version} registered as an alternative for {name!r}",
                        "alternative_match", trust=deb.trust, package=deb.package,
                        version=deb.version)
    # Not literally registered. Maintainer scripts often register slaves in a
    # loop with variable names (xz-utils: --slave /usr/bin/lz$util ...), which a
    # literal match cannot see. What this gate protects is that a name the
    # grading depends on cannot resolve to bytes it should not: for a name that
    # is neither grading-critical nor executed by the verifier, a link to a
    # verified-genuine package file is not an attack, so it is allowed. The
    # critical/executed names keep the strict genuine-AND-registered rule.
    strict = name in critical_names or (
        verify_script is not None and verifier_runs(name, verify_script))
    if not strict:
        return Decision(True, f"links to {target}, a genuine file of {deb.package} "
                        f"{deb.version}; {name!r} is not a name the grading depends on",
                        "alternative_genuine", trust=deb.trust, package=deb.package,
                        version=deb.version)
    return Decision(False, f"{target} is genuine ({deb.package} {deb.version}) but is "
                    f"not registered as an alternative for {name!r}",
                    "alternative_group_mismatch", package=deb.package, version=deb.version)


def _decide_diversions(op: str, ctx: _Ctx, content: bytes | None,
                       image_content: bytes | None) -> Decision:
    if op == "D":
        return Decision(False, "dpkg diversion table deleted", "diversions_invalid")
    if content is None:
        return Decision(False, "dpkg diversion table could not be read", "unverifiable")
    try:
        cur = parse_diversions(content.decode("utf-8", "replace"))
        old = parse_diversions(image_content.decode("utf-8", "replace")) \
            if image_content is not None else set()
    except ValueError as e:
        return Decision(False, str(e), "diversions_invalid")
    changed = sorted((cur - old) | (old - cur))
    if not changed:
        return Decision(True, "same diversion entries as the original image",
                        "image_match", trust="image")
    if ctx.backend != "dpkg":
        return Decision(False, "diversion entries changed and package verification "
                        f"is unsupported for backend {ctx.backend!r}", "unverifiable")
    gone = old - cur
    for orig, to, pkg in changed:
        if pkg == ":":
            return Decision(False, f"local (non-package) diversion of {orig} -> {to}",
                            "diversion_local")
        if (orig, to, pkg) in gone:
            if ctx.safe_removal_explained([pkg]):
                continue
        if not any(scripts_divert(hit[3].scripts, orig, to)
                   for _v, hit in ctx.load_pinned(pkg)):
            return Decision(False, f"diversion of {orig} by {pkg} is not performed by any "
                            "verified version of that package", "diversion_unverified")
    return Decision(True, f"{len(changed)} diversion change(s), each made by a verified "
                    "package's maintainer scripts", "diversion_match", trust="deb scripts")


def verify_findings(cid: str, findings: list[str], verify_script: str,
                    budget_s: float = DEFAULT_BUDGET_S, cache: Path = CACHE_DIR,
                    critical_names: frozenset = frozenset()) -> dict:
    """Decide every `OP PATH` finding. Returns
    {"paths": {finding: {...}}, "duration_s", "budget_s", "backend", "notes"}.

    Never raises: any failure is turned into reject decisions with
    pkg_verify='unverifiable'."""
    t0 = time.monotonic()
    dl = Deadline(budget_s)
    res: dict = {"paths": {}, "budget_s": budget_s, "backend": None, "notes": []}
    items = []
    for f in findings:
        op, _, path = f.partition(" ")
        items.append((f, op, path, surface_class(path)))
    res["classes"] = {}
    for _f, _op, _p, cls in items:
        res["classes"][cls] = res["classes"].get(cls, 0) + 1

    if len(items) > MAX_FINDINGS:
        why = (f"{len(items)} changed grading-surface paths exceed the bound "
               f"{MAX_FINDINGS}; not verified")
        for f, _op, _p, _c in items:
            res["paths"][f] = _md(Decision(False, why, "unverifiable"), None)
        res["error"] = why
        res["duration_s"] = round(time.monotonic() - t0, 3)
        return res

    pending = []
    for f, op, path, cls in items:
        if op == "D" and cls == "preload":
            res["paths"][f] = _md(decide_preload(op, None, None, None), None)
        elif op == "D" and cls == "ldcache":
            res["paths"][f] = _md(decide_ldcache(op, None, None, None, None), None)
        elif op == "D" and cls == "alternative":
            res["paths"][f] = _md(_decide_alternative(op, path, None, None, None,
                                                      critical_names), None)
        else:
            pending.append((f, op, path, cls))
    if not pending:
        res["duration_s"] = round(time.monotonic() - t0, 3)
        return res

    view = None
    keydir = None
    try:
        image_id = container_image_id(cid, dl)
        res["image"] = image_id
        view = ImageView(image_id, dl)
        backend = detect_backend(view)
        res["backend"] = backend
        ctx = _Ctx(cid, view, dl, backend)

        small_cls = ("preload", "ldcache", "diversions")
        observed: dict[str, FileFacts] = {}
        content: dict[str, bytes | None] = {}
        image_content: dict[str, bytes | None] = {}
        for f, op, path, cls in pending:
            if op != "D" and cls in small_cls:
                observed[f], content[f] = read_container_bytes(cid, path, dl)
        big = [(f, path) for f, op, path, cls in pending
               if op != "D" and cls not in small_cls]
        got = read_many(cid, [p for _f, p in big], dl)
        for f, path in big:
            observed[f] = got[path]

        image_refs: dict[str, FileFacts] = {}
        for f, op, path, cls in pending:
            if cls in small_cls:
                image_refs[f], image_content[f] = view.bytes(path)
        cpaths = [(f, path) for f, op, path, cls in pending
                  if op == "C" and cls not in small_cls]
        igot = read_many(view.name, [p for _f, p in cpaths], dl)
        for f, path in cpaths:
            image_refs[f] = igot[path]

        def image_identical(f, op):
            return op == "C" and f in observed and observed[f].same_content(image_refs.get(f))

        need_pkg = [(f, op, path, cls) for f, op, path, cls in pending
                    if cls in ("binary", "lib", "ldconf", "alternative", "diversions")
                    and not image_identical(f, op)]
        if backend == "dpkg" and need_pkg:
            paths = [p for _f, _o, p, _c in need_pkg]
            db = read_dpkg_db(cid, paths, dl)           # HINT (agent-controlled)
            if db is not None:
                ctx.cont_status, ctx.cont_owners = db
            idb = read_dpkg_db(view.name, paths, dl)    # trusted (original image)
            if idb is not None:
                ctx.img_status, ctx.img_owners = idb
            srcs, _files = _sources_from_image(view)
            res["sources"] = [f"{s.uri} {s.suite} {' '.join(s.components)}" for s in srcs]
            if srcs:
                try:
                    secure_cache_dir(cache)
                    keydir = tempfile.mkdtemp(prefix="sr-pkgverify-keys-")
                    keyrings = _keyrings_from_image(
                        view, Path(keydir), {k for s in srcs for k in s.signed_by})
                    ctx.archive = Archive(srcs, image_arch(image_id, dl), keyrings, dl, cache)
                except Unverifiable as e:
                    ctx.archive_reason = str(e)[:300]
                    res["notes"].append(ctx.archive_reason)

        def owner_lookup_extra(paths):
            # Owners for paths discovered during deciding (alternatives targets).
            if backend != "dpkg" or not paths:
                return
            db = read_dpkg_db(cid, paths, dl)
            if db is not None:
                for k, v in db[1].items():
                    ctx.cont_owners.setdefault(k, set()).update(v)
            idb = read_dpkg_db(view.name, paths, dl)
            if idb is not None:
                for k, v in idb[1].items():
                    ctx.img_owners.setdefault(k, set()).update(v)

        alt_targets = [observed[f].linkname for f, op, path, cls in pending
                       if cls == "alternative" and f in observed
                       and observed[f].kind == "symlink" and observed[f].linkname
                       and observed[f].linkname.startswith("/")]
        owner_lookup_extra(alt_targets)

        lib_decisions: dict[str, Decision] = {}
        soname_links: list[tuple[str, str, str, str]] = []
        findings_by_path = {path: f for f, _op, path, _c in items}
        for f, op, path, cls in pending:
            obs = observed.get(f)
            if op != "D" and (obs is None or obs.kind == "absent"):
                d = Decision(False, "path reported by docker diff is absent on read",
                             "unverifiable")
                res["paths"][f] = _md(d, obs)
                continue
            md_extra: dict = {}
            if cls == "binary" and op == "D":
                d = _decide_binary_deletion(path, ctx, verify_script)
            elif cls == "binary":
                deb = DebResult("not_checked")
                if not image_identical(f, op):
                    deb = ctx.deb_compare(obs, path)
                base = path.rsplit("/", 1)[-1]
                runs = verifier_runs(base, verify_script) if op == "A" else False
                shadows = True
                if op == "A" and runs and deb.status == "match":
                    shadows = _shadows_image_binary(
                        base, path, view, _image_path_dirs(image_id, dl))
                d = decide_path(op, obs, image_refs.get(f), deb, runs, backend, shadows)
                if op == "A":
                    md_extra["verifier_runs_name"] = runs
                if deb.tried and not d.allow:
                    md_extra["tried"] = deb.tried[:12]
            elif cls == "lib":
                if op == "D":
                    d = _decide_lib_deletion(path, ctx)
                else:
                    deb = DebResult("not_checked")
                    if not image_identical(f, op):
                        deb = ctx.deb_compare(obs, path)
                    tgt = _soname_link_target(path, obs) if deb.status != "match" else None
                    if tgt is not None and not image_identical(f, op):
                        soname_links.append((f, op, path, tgt))
                        lib_decisions[f] = None   # decided below
                        continue
                    d = decide_lib(op, path, obs, image_refs.get(f), deb, backend)
                    if deb.tried and not d.allow:
                        md_extra["tried"] = deb.tried[:12]
                lib_decisions[f] = d
            elif cls == "ldconf" and op == "D":
                owners = sorted(ctx.img_owners.get(path, ()))
                d = Decision(False, "loader search-path file deleted", "not_applicable")
                if ctx.safe_removal_explained(owners):
                    d = Decision(True, f"search-path file of {', '.join(owners)}, "
                                 "which is wholly removed with every package that "
                                 "depends on it", "removed_with_package",
                                 trust="image dpkg database + engine changes",
                                 package=owners[0])
            elif cls == "ldconf":
                deb = DebResult("not_checked")
                if not image_identical(f, op):
                    deb = ctx.deb_compare(obs, path)
                d = decide_path(op, obs, image_refs.get(f), deb, False, backend)
                if deb.tried and not d.allow:
                    md_extra["tried"] = deb.tried[:12]
            elif cls == "preload":
                d = decide_preload(op, obs, image_refs.get(f), content.get(f))
            elif cls == "ldcache":
                d = decide_ldcache(op, obs, image_refs.get(f), content.get(f),
                                   image_content.get(f))
            elif cls == "alternative":
                d = _decide_alternative(op, path, obs, image_refs.get(f), ctx,
                                        critical_names, verify_script)
            elif cls == "diversions":
                d = _decide_diversions(op, ctx, content.get(f), image_content.get(f))
            else:  # pragma: no cover -- surface_class is total
                d = Decision(False, f"unknown class {cls}", "unverifiable")
            md = _md(d, obs)
            md.update(md_extra)
            if not d.allow and image_refs.get(f) is not None \
                    and image_refs[f].kind != "absent":
                md["image_file"] = image_refs[f].to_md()
            res["paths"][f] = md

        # Soname links: allowed only when the sibling they resolve to is
        # genuine -- unchanged from the image (docker diff does not list it)
        # or itself allowed above.
        for f, op, path, tgt in soname_links:
            tf = None
            for alias in _alias_paths(tgt):
                cand = findings_by_path.get(alias)
                if cand and cand[:1] in ("A", "C"):
                    tf = cand
            if tf is None:
                ok = True        # not changed: the image's own file (or dangling)
            else:
                td = res["paths"].get(tf)
                ok = bool(td) and td.get("decision") == "allow"
            d = decide_lib(op, path, observed[f], image_refs.get(f),
                           DebResult("no_candidate"), backend, soname_link_target_ok=ok)
            md = _md(d, observed[f])
            md["soname_target"] = tgt
            res["paths"][f] = md

        if ctx.archive is not None and ctx.archive.notes:
            res["notes"].extend(ctx.archive.notes[:10])
    except (BudgetExceeded, Unverifiable, subprocess.SubprocessError, OSError,
            tarfile.TarError, ValueError) as e:
        res["error"] = f"{type(e).__name__}: {e}"[:400]
    except Exception as e:  # noqa: BLE001 -- never fail open
        res["error"] = f"unexpected {type(e).__name__}: {e}"[:400]
    finally:
        if view is not None:
            view.close()
        if keydir:
            shutil.rmtree(keydir, ignore_errors=True)
    for f, op, path, cls in items:
        if f not in res["paths"]:
            d = Decision(False, "package verification did not complete: "
                         + res.get("error", "unknown"), "unverifiable")
            res["paths"][f] = _md(d, None)
    res["duration_s"] = round(time.monotonic() - t0, 3)
    return res


def _md(d: Decision, obs: FileFacts | None) -> dict:
    md = {"decision": "allow" if d.allow else "reject", "reason": d.reason,
          "pkg_verify": d.pkg_verify, "package": d.package, "version": d.version,
          "trust": d.trust}
    if obs is not None:
        md["observed"] = obs.to_md()
    return md
