#!/usr/bin/env python3
import sys, argparse, random, shlex, time, threading, os, base64, pathlib
from queue import Queue, Empty
from collections import deque
from threading import Condition

import curses
from blake3 import blake3
from nacl import signing
from scapy.all import Packet, bind_layers, Ether, sendp, sniff, get_if_hwaddr
from scapy.fields import StrFixedLenField, ByteField, ShortField, MACField

# ---------------- Constants ----------------
ETH_TYPE     = 0x88B5        # lab-only EtherType
PT_DATA      = 1             # L3 payload = raw DATA
PT_L4_DGRAM  = 2             # L3 payload = our UDP-like L4 datagram
PT_NDP       = 3             # Node Discovery Protocol (ARP-like)
NDP_OP_DISCOVER  = 1         # broadcast "who's out there?"
NDP_OP_ADVERTISE = 2         # unicast "I am (node_id, mac)"
ED25519_PUB_LEN = 32
X25519_PUB_LEN  = 32
ED25519_SIG_LEN = 64
NONCE_LEN       = 16
ID_LEN       = 16            # NodeID length (bytes) = BLAKE3(pubkey)[:16]
PAYLOAD_CAP  = 1400          # per-frame payload cap (safe single-frame size)
KEYCTX       = b"layer3-nodeid-v1"
ndp_recv_data = {} # Used to store ndp data recieved from other computers

# Runtime key material (set in main())
ED25519_SK = None                 # nacl.signing.SigningKey
ED25519_PUB_BYTES = b""           # 32 bytes
X25519_PUB_BYTES  = b""           # 32 bytes

# Key locations (private files are mode 0600)
KEYDIR            = os.path.join(os.path.expanduser("~"), ".ministack")
ED25519_PATH      = os.path.join(KEYDIR, "ed25519.key")      # base64(32B Ed25519 secret)
X25519_PRIV_PATH  = os.path.join(KEYDIR, "x25519.key")       # base64(32B X25519 secret)
X25519_PUB_PATH   = os.path.join(KEYDIR, "x25519.pub")       # base64(32B X25519 public)

# ---------------- Global state ----------------
ports: dict[int, tuple[deque, Condition]] = {}  # port -> (queue, cond)
log_q: "Queue[str]" = Queue(maxsize=10000)
stop_flag = threading.Event()

# viewer threads: port -> (thread, stop_event)
_viewers: dict[int, tuple[threading.Thread, threading.Event]] = {}

# ---- TUI-safe text helpers ----
def _safe_payload_preview(b: bytes, max_len: int = 512) -> str:
    s = b.decode("utf-8", "backslashreplace")
    s = s.replace("\x00", r"\x00")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s

def _sanitize_for_curses(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("\x00", r"\x00")

def log(msg: str):
    try:
        log_q.put_nowait(_sanitize_for_curses(msg))
    except:
        pass

def _block(title: str, lines: list[str]) -> str:
    pad = "  "
    return "\n".join([f"[{title}]", *[pad + ln for ln in lines]])

def _short_id(b: bytes) -> str:
    h = id_to_hex(b)
    return h[:11] + "…" + h[-11:]

def _ensure_keydir():
    pathlib.Path(KEYDIR).mkdir(parents=True, exist_ok=True)

def _chmod600(path: str):
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass  # best effort on non-POSIX FS

def load_or_create_ed25519() -> tuple["signing.SigningKey", "signing.VerifyKey"]:
    """
    Load persistent Ed25519. If missing, create and store base64(32B secret).
    Returns (SigningKey, VerifyKey).
    """
    _ensure_keydir()
    if os.path.exists(ED25519_PATH):
        raw_b64 = open(ED25519_PATH, "rb").read()
        raw = base64.b64decode(raw_b64)
        if len(raw) != 32:
            raise ValueError(f"Bad ed25519 key size in {ED25519_PATH}")
        sk = signing.SigningKey(raw)
        vk = sk.verify_key
        return sk, vk

    # Create a new identity
    sk = signing.SigningKey.generate()
    with open(ED25519_PATH, "wb") as f:
        f.write(base64.b64encode(bytes(sk)))
        f.flush(); os.fsync(f.fileno())
    _chmod600(ED25519_PATH)
    return sk, sk.verify_key

def derive_and_store_x25519(sk: "signing.SigningKey", vk: "signing.VerifyKey"):
    _ensure_keydir()
    xsk = sk.to_curve25519_private_key()   # nacl.public.PrivateKey
    xpk = vk.to_curve25519_public_key()    # nacl.public.PublicKey

    # Private: create if missing
    if not os.path.exists(X25519_PRIV_PATH):
        with open(X25519_PRIV_PATH, "wb") as f:
            f.write(base64.b64encode(xsk.encode()))
            f.flush(); os.fsync(f.fileno())
        _chmod600(X25519_PRIV_PATH)

    # Public: refresh each run (harmless if unchanged)
    with open(X25519_PUB_PATH, "wb") as f:
        f.write(base64.b64encode(xpk.encode()))
        f.flush(); os.fsync(f.fileno())

    return xsk, xpk

# ---------------- Packets ----------------
class layer3(Packet):
    name = "Layer3"
    fields_desc = [
        StrFixedLenField("magic",   b"MN", 2),
        ByteField       ("version", 1),
        ByteField       ("ptype",   PT_DATA),
        StrFixedLenField("dst_id",  b"\x00"*ID_LEN, ID_LEN),
        StrFixedLenField("src_id",  b"\x00"*ID_LEN, ID_LEN),
    ]

class ndp(Packet):
    name = "NDP"
    fields_desc = [
        ByteField("op", NDP_OP_DISCOVER),
        StrFixedLenField("node_id", b"\x00"*ID_LEN, ID_LEN),
        MACField("mac", "00:00:00:00:00:00"),
        StrFixedLenField("ed25519_pub", b"\x00"*ED25519_PUB_LEN, ED25519_PUB_LEN),
        StrFixedLenField("x25519_pub",  b"\x00"*X25519_PUB_LEN,  X25519_PUB_LEN),
        StrFixedLenField("nonce",       b"\x00"*NONCE_LEN,       NONCE_LEN), 
        StrFixedLenField("sig",         b"\x00"*ED25519_SIG_LEN, ED25519_SIG_LEN),
    ]

class layer4(Packet):
    name = "Layer4"
    fields_desc = [
        ShortField("src_port", 0),
        ShortField("dst_port", 0),
    ]

bind_layers(Ether, layer3, type=ETH_TYPE)
bind_layers(layer3, ndp, ptype=PT_NDP)
bind_layers(layer3, layer4, ptype=PT_L4_DGRAM)

# ---------------- Helpers ----------------
def gen_node_id(pubkey_bytes: bytes, size: int = ID_LEN) -> bytes:
    return blake3(KEYCTX + pubkey_bytes).digest()[:size]

def node_id_from_pubkey(pubkey: bytes, size: int = ID_LEN) -> bytes:
    return blake3(KEYCTX + pubkey).digest()[:size]

def default_key_path() -> str:
    d = pathlib.Path.home() / ".ministack"
    d.mkdir(mode=0o700, exist_ok=True)
    return str(d / "ed25519.key")   # base64-encoded 32B seed

def load_or_create_signing_key(path: str, force_new: bool = False) -> signing.SigningKey:
    path = path or default_key_path()
    if (not force_new) and os.path.exists(path):
        with open(path, "rb") as f:
            raw = base64.b64decode(f.read())
        return signing.SigningKey(raw)

    sk = signing.SigningKey.generate()
    raw = bytes(sk)  # 32B seed
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(base64.b64encode(raw))
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return sk

def id_to_hex(b: bytes) -> str:
    h = b.hex()
    return "-".join(h[i:i+8] for i in range(0, len(h), 8))

def hex_to_id(s: str, size: int = ID_LEN) -> bytes:
    s = s.replace("-", "").strip()
    b = bytes.fromhex(s)
    if len(b) != size:
        raise ValueError(f"expected {size} bytes, got {len(b)}")
    return b

def alloc_ephemeral() -> int:
    return random.randint(49152, 65535)

def _mac_bytes(mac_str: str) -> bytes:
    # "aa:bb:cc:dd:ee:ff" -> b'\xaa\xbb\xcc\xdd\xee\xff'
    return bytes.fromhex(mac_str.replace(":", ""))

def _ndp_sig_bytes(op: int, node_id: bytes, mac_bytes: bytes,
                   ed25519_pub: bytes, x25519_pub: bytes, nonce: bytes) -> bytes:
    # Canonical transcript so both sides sign/verify exactly the same bytes.
    return (b"MNDPv1|" +
            bytes([op]) +
            node_id +
            mac_bytes +
            ed25519_pub +
            x25519_pub +
            nonce)

def _ndp_verify_bytes(op: int, node_id: bytes, mac_bytes: bytes, ed25519_pub: bytes, x25519_pub: bytes, nonce: bytes, sig: bytes) -> bool:
    transcript = _ndp_sig_bytes(op, node_id, mac_bytes, ed25519_pub, x25519_pub, nonce)
    try:
        signing.VerifyKey(ed25519_pub).verify(transcript, sig)
        return True
    except Exception:
        return False

# ---------------- Per-port queues ----------------
def bind_udp(port: int, capacity: int = 64):
    if port in ports:
        raise ValueError("port already bound")
    ports[port] = (deque(maxlen=capacity), Condition())
    log(f"[BIND L4] bound port {port}  cap={capacity}")

def unbind_udp(port: int):
    if port in ports:
        del ports[port]
        log(f"[UNBIND L4] port {port}")

def publish_to_port(dst_port: int, src_id: bytes, src_port: int, payload: bytes, policy: str = "drop_oldest") -> bool:
    p = ports.get(dst_port)
    if p is None:
        return False
    dq, cv = p
    item = (src_id, int(src_port), payload)
    with cv:
        if policy == "drop_newest" and len(dq) == dq.maxlen:
            return False
        dq.append(item)
        cv.notify()
        return True

def recv_from_port(port: int, timeout: float | None = None):
    p = ports.get(port)
    if p is None:
        raise ValueError("port not bound")
    dq, cv = p
    with cv:
        if not dq:
            if timeout is None:
                while not dq:
                    cv.wait()
            else:
                if not cv.wait(timeout=timeout) and not dq:
                    return None
        return dq.popleft()

def port_stats(port: int):
    dq, _ = ports[port]
    return {"depth": len(dq), "cap": dq.maxlen}

def ndp_sanitation(op: int, node_id: bytes, mac: str, ed_pub: bytes, x2_pub: bytes, nonce: bytes, sig: bytes) -> bool:

    # --- basic sanity ---
    if not (isinstance(ed_pub, (bytes, bytearray)) and len(ed_pub) == ED25519_PUB_LEN):
        log("[!!!] NDP invalid ed25519_pub length"); return False
    if not (isinstance(x2_pub, (bytes, bytearray)) and len(x2_pub) == X25519_PUB_LEN):
        log("[!!!] NDP invalid x25519_pub length"); return False
    if not (isinstance(node_id, (bytes, bytearray)) and len(node_id) == ID_LEN):
        log("[!!!] NDP invalid node_id length"); return False
    if not (isinstance(nonce, (bytes, bytearray)) and len(nonce) == NONCE_LEN):
        log("[!!!] NDP invalid nonce length"); return False
    if not (isinstance(sig, (bytes, bytearray)) and len(sig) == ED25519_SIG_LEN):
        log("[!!!] NDP invalid signature length"); return False

    # --- NodeID must come from Ed25519 pubkey ---
    if blake3(KEYCTX + ed_pub).digest()[:ID_LEN] != node_id:
        log("[!!!] NDP node id validation failed! Invalid node ID!")
        return False

    # --- Signature verification (MAC must be raw 6B in transcript) ---
    mac_bytes = _mac_bytes(mac)  # convert "aa:bb:..." -> b"\xaa\xbb..."
    transcript = _ndp_sig_bytes(int(op), bytes(node_id), mac_bytes, bytes(ed_pub), bytes(x2_pub), bytes(nonce))
    try:
        signing.VerifyKey(bytes(ed_pub)).verify(transcript, bytes(sig))
    except Exception as e:
        log(f"[!!!] NDP packet is invalid! Bad signature: {e!r}")
        return False

    # --- accept & store ---
    ndp_recv_data[bytes(node_id)] = [mac, bytes(ed_pub), bytes(x2_pub), bytes(nonce), bytes(sig)]
    log(_block("NDP LEARN", [
        f"peer  : {id_to_hex(bytes(node_id))}",
        f"mac   : {mac}",
    ]))
    return True

# ---------------- TX/RX: L3 & L4 & NDP ----------------
def send_layer3(iface: str, my_id: bytes, dst_id: bytes, dst_mac: str, payload):
    if isinstance(payload, str):
        payload = payload.encode()
    elif not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes/bytearray/str")
    my_mac = get_if_hwaddr(iface)
    frame = Ether(dst=dst_mac, src=my_mac, type=ETH_TYPE) / \
            layer3(version=1, ptype=PT_DATA, dst_id=dst_id, src_id=my_id) / payload
    sendp(frame, iface=iface, verbose=False)
    log(f"[SEND L3] {iface} -> {dst_mac}  dst_id={id_to_hex(dst_id)}  bytes={len(payload)}")

def send_l4(iface: str, my_id: bytes, dst_id: bytes, dst_mac: str,
            src_port: int, dst_port: int, payload):
    if isinstance(payload, str):
        payload = payload.encode()
    elif not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes/bytearray/str")
    if len(payload) > PAYLOAD_CAP:
        raise ValueError("payload too large for a single Ethernet frame safely")
    my_mac = get_if_hwaddr(iface)
    frame = Ether(dst=dst_mac, src=my_mac, type=ETH_TYPE) / \
            layer3(version=1, ptype=PT_L4_DGRAM, dst_id=dst_id, src_id=my_id) / \
            layer4(src_port=src_port, dst_port=dst_port) / payload
    sendp(frame, iface=iface, verbose=False)
    log(f"[SEND L4] {iface} -> {dst_mac}  {src_port}->{dst_port}  dst_id={id_to_hex(dst_id)}  bytes={len(payload)}")

def ndp_probe(iface: str, my_id: bytes):
    my_mac = get_if_hwaddr(iface)
    mac_b  = _mac_bytes(my_mac)
    nonce  = os.urandom(NONCE_LEN)
    op     = NDP_OP_DISCOVER

    # build and sign transcript
    to_sign = _ndp_sig_bytes(op, my_id, mac_b, ED25519_PUB_BYTES, X25519_PUB_BYTES, nonce)
    sig     = ED25519_SK.sign(to_sign).signature  # 64 bytes

    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac, type=ETH_TYPE) /
        layer3(version=1, ptype=PT_NDP, dst_id=b"\x00"*ID_LEN, src_id=my_id) /
        ndp(op=op,
            node_id=my_id,
            mac=my_mac,
            ed25519_pub=ED25519_PUB_BYTES,
            x25519_pub=X25519_PUB_BYTES,
            nonce=nonce,
            sig=sig)
    )
    sendp(frame, iface=iface, verbose=False)

    # pretty log
    lines = [
        f"iface : {iface}",
        f"node  : {id_to_hex(my_id)}",
        f"mac   : {my_mac}",
        "dst   : ff:ff:ff:ff:ff:ff (broadcast)",
    ]
    log(_block("NDP PROBE", lines))

def ndp_advertise(iface: str, my_id: bytes, requester_mac: str, requester_id: bytes):
    my_mac = get_if_hwaddr(iface)
    mac_b  = _mac_bytes(my_mac)
    nonce  = os.urandom(NONCE_LEN)
    op     = NDP_OP_ADVERTISE

    to_sign = _ndp_sig_bytes(op, my_id, mac_b, ED25519_PUB_BYTES, X25519_PUB_BYTES, nonce)
    sig     = ED25519_SK.sign(to_sign).signature

    frame = (
        Ether(dst=requester_mac, src=my_mac, type=ETH_TYPE) /
        layer3(version=1, ptype=PT_NDP, dst_id=requester_id, src_id=my_id) /
        ndp(op=op,
            node_id=my_id,
            mac=my_mac,
            ed25519_pub=ED25519_PUB_BYTES,
            x25519_pub=X25519_PUB_BYTES,
            nonce=nonce,
            sig=sig)
    )
    sendp(frame, iface=iface, verbose=False)

    lines = [
        f"iface : {iface}",
        f"to    : {requester_mac}",
        f"node  : {id_to_hex(my_id)}",
        f"mac   : {my_mac}",
    ]
    log(_block("NDP ADVERTISE", lines))

def listen_loop(iface: str, my_id: bytes):
    """Background sniffer thread: handles NDP + L4, publishes to queues, logs events."""
    bpf = f"ether proto 0x{ETH_TYPE:04x}"
    local_mac = get_if_hwaddr(iface).lower()
    log(f"[LISTEN L4] iface={iface}  my_id={id_to_hex(my_id)}  filter={bpf}")

    def _on(pkt):
        try:
            if not pkt.haslayer(layer3):
                return
            l3 = pkt[layer3]
            if l3.magic != b"MN" or l3.version != 1:
                return

            # NDP
            if l3.ptype == PT_NDP and pkt.haslayer(ndp):
                n = pkt[ndp]
                src_mac = pkt.src.lower()
                if n.op == NDP_OP_DISCOVER:
                    if src_mac == local_mac:
                        return  # ignore self DISCOVER
                    ndp_advertise(iface, my_id, requester_mac=src_mac, requester_id=bytes(l3.src_id))
                elif n.op == NDP_OP_ADVERTISE:
                    if bytes(l3.dst_id) != my_id:
                        return
                    if src_mac == local_mac:
                        return
                    adv_id  = bytes(n.node_id)
                    adv_mac = n.mac
                    if adv_id == my_id:
                        return

                    ndp_sanitation(n.op, n.node_id, n.mac, n.ed25519_pub, n.x25519_pub, n.nonce, n.sig)
                return

            # L4
            if l3.ptype != PT_L4_DGRAM:
                return
            if bytes(l3.dst_id) != my_id:
                return
            if not pkt.haslayer(layer4):
                return

            l4 = pkt[layer4]
            src_id   = bytes(l3.src_id)
            src_port = int(l4.src_port)
            dst_port = int(l4.dst_port)
            payload  = getattr(l4.payload, "load", None) or bytes(l4.payload)

            ok = publish_to_port(dst_port, src_id, src_port, payload, policy="drop_oldest")
            preview = _safe_payload_preview(payload)
            log(f"[RECV L4] mac={pkt.src} src={id_to_hex(src_id)} {src_port}->{dst_port} "
                f"bytes={len(payload)} text={preview}" + ("" if ok else "  [DROP: no listener]"))

        except Exception as e:
            log(f"[LISTEN] handler error: {e!r}")

    while not stop_flag.is_set():
        try:
            sniff(iface=iface, filter=bpf, store=False, prn=_on, timeout=2)
        except Exception as e:
            log(f"[LISTEN] sniff error: {e!r}")
            time.sleep(0.5)

# ---------------- Port viewers (tail-like) ----------------
def _viewer_loop(port: int, stop_evt: threading.Event):
    log(f"[VIEW] start port={port}")
    while not stop_evt.is_set() and not stop_flag.is_set():
        try:
            msg = recv_from_port(port, timeout=0.5)
        except ValueError:
            log(f"[VIEW] port {port} unbound; stopping")
            break
        if msg is None:
            continue
        src_id, src_port, payload = msg
        txt = _safe_payload_preview(payload, max_len=256)
        log(f"[VIEW {port}] src={id_to_hex(src_id)}:{src_port} bytes={len(payload)} text={txt}")
    log(f"[VIEW] stop port={port}")

def _start_port_viewer(port: int):
    if port in _viewers:
        log(f"[VIEW] already running for port {port}")
        return
    if port not in ports:
        log(f"[VIEW] port {port} is not bound")
        return
    ev = threading.Event()
    th = threading.Thread(target=_viewer_loop, args=(port, ev), daemon=True)
    _viewers[port] = (th, ev)
    th.start()

def _stop_port_viewer(port: int):
    t = _viewers.get(port)
    if not t:
        log(f"[VIEW] no viewer for port {port}")
        return
    th, ev = t
    ev.set()
    _viewers.pop(port, None)

def _list_port_viewers():
    if not _viewers:
        log("[VIEW] (none)")
        return
    for p in list(_viewers.keys()):
        log(f"[VIEW] running on port {p}")

# ---------------- TUI shell ----------------
HELP_TEXT = """\
Commands:
  help
  id
  bind <port> [cap]               - bind a local port with optional capacity (default 64)
  unbind <port>
  ports                           - list bound ports & depths
  ndp                             - broadcast NDP DISCOVER
  send <dst_id_hex> <dst_mac> <dst_port> <text...>
  pull <port>                     - pop one datagram and print
  pull follow <port>              - start a live viewer (consumes messages)
  pull stop <port>                - stop the live viewer for this port
  pull list                       - list active viewers
  keys                            - show NodeID + public keys + file paths
  quit | exit
"""

def run_shell(iface: str, my_id: bytes):
    t = threading.Thread(target=listen_loop, args=(iface, my_id), daemon=True)
    t.start()
    curses.wrapper(lambda stdscr: tui_loop(stdscr, iface, my_id))

def tui_loop(stdscr, iface: str, my_id: bytes):
    curses.curs_set(1)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    rows, cols = stdscr.getmaxyx()
    log_h = max(3, rows - 3)
    inp_h = 3
    log_win = curses.newwin(log_h, cols, 0, 0)
    inp_win = curses.newwin(inp_h, cols, log_h, 0)
    log_win.scrollok(True)

    input_buf = ""

    def wrap_line(s: str, width: int):
        if width <= 1:
            return [s]
        out = []
        for ln in s.splitlines() or [""]:
            while len(ln) > width:
                out.append(ln[:width])
                ln = ln[width:]
            out.append(ln)
        return out

    def redraw():
        try:
            while True:
                line = log_q.get_nowait()
                for sub in wrap_line(line, cols):
                    sub = _sanitize_for_curses(sub)
                    try:
                        log_win.addstr(sub + "\n")
                    except curses.error:
                        pass
        except Empty:
            pass
        log_win.noutrefresh()

        inp_win.erase()
        try:
            inp_win.addstr(0, 0, _sanitize_for_curses(f"[ID {id_to_hex(my_id)}] MAC={get_if_hwaddr(iface)} iface={iface}"))
            inp_win.addstr(1, 0, _sanitize_for_curses(f"> {input_buf}"))
        except curses.error:
            pass
        inp_win.noutrefresh()
        curses.doupdate()

    log(f"[ID] my_id={id_to_hex(my_id)}")
    log("[READY] Type 'help' for commands.")

    last_draw = 0
    while not stop_flag.is_set():
        now = time.time()
        if now - last_draw > 0.05:
            redraw()
            last_draw = now

        ch = stdscr.getch()
        if ch == -1:
            time.sleep(0.01)
            continue
        if ch in (curses.KEY_ENTER, 10, 13):
            line = input_buf.strip()
            input_buf = ""
            if line:
                try:
                    handle_command(line, iface, my_id)
                except Exception as e:
                    log(f"[CMD ERR] {e}")
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            input_buf = input_buf[:-1]
        elif ch == curses.KEY_RESIZE:
            rows, cols = stdscr.getmaxyx()
            log_h = max(3, rows - 3)
            log_win.resize(log_h, cols)
            inp_win.resize(3, cols)
            inp_win.mvwin(log_h, 0)
        else:
            if 0 <= ch < 256:
                input_buf += chr(ch)

def handle_command(line: str, iface: str, my_id: bytes):
    parts = shlex.split(line)
    if not parts:
        return
    cmd = parts[0].lower()

    if cmd in ("quit", "exit"):
        stop_flag.set()
        log("[BYE] shutting down...")
        return

    if cmd == "help":
        for l in HELP_TEXT.splitlines():
            log(l)
        return

    if cmd == "id":
        log(f"[ID] {id_to_hex(my_id)}")
        return

    if cmd == "ports":
        if not ports:
            log("[PORTS] (none)")
        else:
            for p, (dq, _) in ports.items():
                log(f"[PORT] {p} depth={len(dq)}/{dq.maxlen}")
        return

    if cmd == "bind":
        if len(parts) < 2:
            raise ValueError("usage: bind <port> [cap]")
        port = int(parts[1])
        cap  = int(parts[2]) if len(parts) >= 3 else 64
        bind_udp(port, cap)
        return

    if cmd == "unbind":
        if len(parts) != 2:
            raise ValueError("usage: unbind <port>")
        unbind_udp(int(parts[1]))
        return

    if cmd == "ndp":
        ndp_probe(iface, my_id)
        return

    if cmd == "pull":
        # subcommands: list | follow <port> | stop <port> | <port>
        if len(parts) == 2 and parts[1].lower() == "list":
            _list_port_viewers()
            return
        if len(parts) == 3 and parts[1].lower() == "follow":
            port = int(parts[2])
            _start_port_viewer(port)
            return
        if len(parts) == 3 and parts[1].lower() == "stop":
            port = int(parts[2])
            _stop_port_viewer(port)
            return
        if len(parts) == 2:
            port = int(parts[1])
            msg = recv_from_port(port, timeout=0.0)
            if msg is None:
                log(f"[PULL] port={port} (empty)")
            else:
                src_id, src_port, payload = msg
                txt = _safe_payload_preview(payload)
                log(f"[PULL] src={id_to_hex(src_id)}:{src_port} bytes={len(payload)} text={txt}")
            return
        raise ValueError("usage: pull <port> | pull follow <port> | pull stop <port> | pull list")

    if cmd == "send":
        # send <dst_id_hex> <dst_mac> <dst_port> <text...>
        if len(parts) < 5:
            raise ValueError("usage: send <dst_id_hex> <dst_mac> <dst_port> <text...>")
        dst_id = hex_to_id(parts[1])
        dst_mac = parts[2]
        dst_port = int(parts[3])
        payload = " ".join(parts[4:])
        src_port = alloc_ephemeral()
        send_l4(iface, my_id, dst_id, dst_mac, src_port, dst_port, payload)
        return
    
    if cmd == "keys":
        # Show fingerprints and file locations (don’t print private material)
        try:
            ed_b64 = "(missing)"
            xpub_b64 = "(missing)"
            if os.path.exists(ED25519_PATH):
                raw = base64.b64decode(open(ED25519_PATH, "rb").read())
                vk = signing.SigningKey(raw).verify_key
                ed_b64 = base64.b64encode(bytes(vk)).decode("ascii")
            if os.path.exists(X25519_PUB_PATH):
                xpub_b64 = open(X25519_PUB_PATH, "rb").read().decode("ascii")
        except Exception as e:
            log(f"[KEYS] error: {e!r}")
            return

        lines = [
            f"NodeID      : {id_to_hex(my_id)}",
            f"Ed25519 pub : {ed_b64}",
            f"X25519 pub  : {xpub_b64}",
            f"files:",
            f"  {ED25519_PATH} (private)",
            f"  {X25519_PRIV_PATH} (private)",
            f"  {X25519_PUB_PATH}  (public)",
        ]
        log("\n".join(lines))
        return

    raise ValueError(f"unknown command: {cmd}")

# ---------------- Entry ----------------
def main():
    ap = argparse.ArgumentParser(description="Mini L3/L4 + NDP over Ethernet — Interactive Node Shell")
    ap.add_argument("--iface", required=True, help="Network interface (e.g., enp5s0)")
    ap.add_argument("--new-identity", action="store_true",
                    help="Force-generate a new Ed25519 identity (will overwrite existing!)")
    args = ap.parse_args()

    # Identity & encryption keys
    if args.new_identity:
        # Overwrite existing identity (careful!)
        pathlib.Path(KEYDIR).mkdir(parents=True, exist_ok=True)
        sk = signing.SigningKey.generate()
        with open(ED25519_PATH, "wb") as f:
            f.write(base64.b64encode(bytes(sk)))
            f.flush(); os.fsync(f.fileno())
        _chmod600(ED25519_PATH)
        vk = sk.verify_key
    else:
        sk, vk = load_or_create_ed25519()

    # Persistent NodeID derived from the Ed25519 public key
    my_id = gen_node_id(bytes(vk))

    # Create/refresh X25519 keys (for encryption/key agreement)
    xsk, xpk = derive_and_store_x25519(sk, vk)

    # ---- expose runtime key material for NDP signing / adverts ----
    global ED25519_SK, ED25519_PUB_BYTES, X25519_PUB_BYTES
    ED25519_SK         = sk
    ED25519_PUB_BYTES  = bytes(vk)        # 32B
    X25519_PUB_BYTES   = bytes(xpk)       # 32B

    # Nice one-time log on startup
    try:
        ed_pub_b64 = base64.b64encode(bytes(vk)).decode("ascii")
        x_pub_b64  = base64.b64encode(xpk.encode()).decode("ascii")
        log("[KEYS] identity & encryption ready:\n"
            f"  NodeID      : {id_to_hex(my_id)}\n"
            f"  Ed25519 pub : {ed_pub_b64}\n"
            f"  X25519 pub  : {x_pub_b64}\n"
            f"  files       :\n"
            f"    {ED25519_PATH} (private, 0600)\n"
            f"    {X25519_PRIV_PATH} (private, 0600)\n"
            f"    {X25519_PUB_PATH}  (public)")
    except Exception:
        pass

    try:
        run_shell(args.iface, my_id)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
