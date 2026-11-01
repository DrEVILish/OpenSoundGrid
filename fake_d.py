#!/usr/bin/env python3
"""Fake DiGiGrid D (control plane only; clock slave, and clock master when promoted).

Master mode (the controller promotes a master-capable device when the master fails; a device
that refuses stalls the whole system, byte map 10.11): it follows the real D as master, checked
against a capture of the real D as master -- set_master(us) answers 0x27 until announce_master(us) makes us
master; beacons (10 Hz, VLAN priority 7) start at once on the timebase we were locked to;
set_master(us) then schedules a clock switch (transition_state 2 at align_up(now + 11264, 512)),
answering 0 while it is pending and 0x14 afterwards; slaves' sync.unicast requests are answered
at once (t3 = t2 + 1); activate_config is announced with transition_state 5; a new rate takes
effect on announce_master; announce_master(other) makes us a slave again.  Clock-only streams to
software endpoints (TX entries with no channels) are listed in the state file for the audio side.
Use --slave-only for the old behaviour (refuse with 0x27).

Answers a SoundGrid controller (eMotion LV1, SoundGrid Studio) the way the
real DiGiGrid D does, so the controller can find, claim, clock and route it.
It sends no audio and no clock: it never becomes clock master, and it leaves
stream.audio packets to your own audio code.  What it gives that code is the
routing the controller asked for and the sample time at which it starts (see
--state-file).

Behaviour is copied from the real D in the captures (SoundGrid_byte_map.md,
section 10).  As a slave (byte map 10.2) the D, once told its master
by clock.announce_master, swaps 10 timestamps with the master at 10 Hz
(sync.unicast -> sync.03), reporting clock_state 2 with field_c counting down
the exchanges left.  Then it reports clock_state 1 and its sample counter is
the master's.  We do the same, and keep following the master's sync.beacon.

  Live (macOS BPF; needs the access_bpf group, which Wireshark's ChmodBPF sets up):
    python3 tools/fake_d.py --iface en13 [--mac 00:1c:d1:fd:00:01] [--state-file d.json] [-v]

  Offline self-test (replays every request the real D received in a capture
  and compares our replies byte for byte with the real D's replies):
    python3 tools/fake_d.py --selftest capture.pcapng [--real-mac MAC]

  The real D is found from its own device.presence replies (they carry its name), so
  --real-mac is only needed if that fails.

Running on the same Mac as LV1: requests from LV1 leave that Mac and never
come back in, so we read outgoing frames too (BIOCSSEESENT).  Whether LV1 can
see our replies on the same host is untested; a second machine, or a second
NIC on the same switch, is the safe setup.
"""
import argparse, collections, ctypes, fcntl, json, os, random, select, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ETH_SG = 0x8908
BCAST = b'\xff' * 6
DEFAULT_MAC = '00:1c:d1:fd:00:01'
DEVICE_NAME = b'DigiGridD'
OWN_CLASS_PRIO = (1, 2)            # the D's own clock class/priority
OWNER_TIMEOUT = None               # never expire the claim: the IOC kept its owner through a 24 s
                                   # cable pull (byte map 10.10); only device.release or a reboot clears it
LOCK_TIMEOUT = 1.0                 # master beacons must have been heard this recently
SYNC_EXCHANGES = 10                # sync.unicast/sync.03 exchanges before we report locked
SYNC_INTERVAL = 0.1                # seconds between exchanges (the D: 10 Hz)
SYNC_VLAN = 0xe000                 # the D sends sync frames in an 802.1Q tag, priority 7, VLAN 0
ACTIVATE_LEAD = 11264              # samples at 48 kHz; activation = align_up(now + lead, 512)
CLOCK_SWITCH_LEAD = 11264          # samples at 48 kHz; master clock switch = align_up(now + lead, 512)
                                   # (the real D: exactly this, like activate_config; the IOC uses ~10240)
BEACON_INTERVAL = 0.1              # master sync.beacon rate (10 Hz)
SLAVE_START_LEAD = 10240           # samples at 48 kHz; slave start = align_up(now + lead, 512) after
                                   # set_config (one observation, byte map 10.2)
ROUTED_RX_FLAGS = 0x0380           # RX streams with these stream_flags get result 0x0b and are left
                                   # out of get_rx_table/get_rx_status (both captures agree)

# Status codes (u32 at the start of every reply body)
OK, E_BUSY, E_NOT_OWNER, E_CLAIMED, E_SAME_CONFIG, E_REFUSED = 0, 0x14, 0x16, 0x17, 0x25, 0x27

# Replies copied verbatim from the real D (bodies, i.e. bytes after the 22-byte header)
LIST_SERVICES = bytes.fromhex('0000000007000000000001000200040009000a0010000000')
D_SERVICES = (0, 1, 2, 4, 9, 10, 16)


def build_services(services):
    """device.list_services reply: status, count, u16 per service, padded to 4 bytes."""
    body = struct.pack('<II', OK, len(services)) + struct.pack('<%dH' % len(services), *services)
    return body + b'\0' * (-len(body) % 4)
GET_CAPS = bytes.fromhex(
    '00000000000000000400040008002000080020001000f001020000004000b0040000040001000000'
    '44ac000000000400000004000100000080bb00000000040000000400010000008858010000000400'
    '0000040001000000007701000000040000000400')


def build_caps(inputs, outputs):
    """stream.get_caps reply body.  The D's words are kept; only the physical I/O counts
    (offset 8) and the per-rate channel counts change.  build_caps(4, 4) == GET_CAPS."""
    b = bytearray(GET_CAPS)
    struct.pack_into('<HH', b, 8, inputs, outputs)
    n, = struct.unpack_from('<H', b, 34)
    for i in range(n):                       # rate entry: kind, rate, in_first, in_ch, out_first, out_ch
        struct.pack_into('<HH', b, 36 + 16 * i + 10, inputs, 0)
        struct.pack_into('<H', b, 36 + 16 * i + 14, outputs)
    return bytes(b)


FIRMWARE = bytes.fromhex('00000000010d0801110f10000000010002000d00cdab020002000d0000000016'
                         '4f637420333020323032312c2032323a30343a353600')
FIRMWARE_IDS = struct.unpack_from('<9H', FIRMWARE, 12)   # 0, 1, 2, 13, 0xabcd, 2, 2, 13, 0


def build_firmware(ids=None, version_b=None):
    """firmware.get_version reply with the nine u16 words (3 and 7 = model number) and/or the
    second version (4 bytes; the UI shows "1.<b0>.<b1>" as the firmware version) replaced."""
    b = bytearray(FIRMWARE)
    if ids is not None:
        struct.pack_into('<9H', b, 12, *ids)
    if version_b is not None:
        b[8:12] = bytes(version_b)
    return bytes(b)


SVC16_OP30 = struct.pack('<IIHH', 0, 0, 1, 1)
SYNC_OP04 = struct.pack('<II', 0, 1)
DISCOVERY_OP03 = struct.pack('<II', 0, 0)

# Service numbers (controller port n, device port 0x64 + n)
S_DEV, S_STREAM, S_CLOCK, S_FW, S_SYNC, S_DISC, S_16 = 0, 1, 2, 4, 9, 10, 16


def mac_b(s):
    return bytes.fromhex(s.replace(':', ''))


def mac_s(b):
    return b.hex(':')


def u32(x):
    return x & 0xffffffff


def s32(x):
    x = u32(x)
    return x - (1 << 32) if x & 0x80000000 else x


class Clock:
    """Two sample counters: our own free-running one, and an estimate of the master's."""

    def __init__(self, now, rate=48000):
        self.rate = rate
        self.local = (now, random.getrandbits(32))   # the real D's counter is not 0 at boot
        self.master = None                           # (time, master sample time) reference
        self.heard = None                            # time a master beacon was last heard

    @staticmethod
    def _at(ref, now, rate):
        return u32(ref[1] + round((now - ref[0]) * rate))

    def local_st(self, now):
        return self._at(self.local, now, self.rate)

    def master_st(self, now):
        return self._at(self.master, now, self.rate) if self.master else self.local_st(now)

    def set_rate(self, now, rate):
        if rate and rate != self.rate:
            self.local = (now, self.local_st(now))
            if self.master:
                self.master = (now, self.master_st(now))
            self.rate = rate

    def sync(self, now, st, rate=None):
        if rate:
            self.rate = rate
        self.master = (now, st)

    def hearing(self, now):
        return self.heard is not None and now - self.heard < LOCK_TIMEOUT


class FakeD:
    """Protocol state machine.  handle() takes one received SoundGrid frame and
    returns the frames to send as (dst_mac_bytes, payload) pairs.  It has no I/O
    and takes the time as an argument, so the self-test can drive it from a capture."""

    def __init__(self, mac, now, log=print, inputs=4, outputs=4, name=DEVICE_NAME, firmware_ids=None,
                 prop_default=None, fw_version=None, services=D_SERVICES):
        self.mac = mac
        self.caps = build_caps(inputs, outputs)
        self.name = name                       # device type name in device.presence.reply
        self.prop_default = prop_default       # u32 answered for unknown property reads (None: no data)
        self.firmware = build_firmware(firmware_ids, fw_version)
        self.services = tuple(services)        # what device.list_services reports; others are ignored
        self.answer_property = False           # answer clock.property even if service 2 is not listed
        self.log = log
        self.clock = Clock(now)
        self.owner = None              # MAC of the controller that claimed us
        self.owner_seen = None
        self.master = None             # (mac, class, prio) we are told to follow
        self.props = {0x20: struct.pack('<I', 1)}
        self.token = 0                 # config token from the last accepted set_config
        self.activated = 0             # token of the last accepted activate_config
        self.config = None             # parsed set_config
        self.activation = None         # (token, sample_time)
        self.running = 0               # token of the config whose start time has passed
        self.pending = None            # (token, monotonic time it starts), set by activate_config
        self.config_raw = b''          # body of the last accepted set_config (kept across restarts)
        self.net_token = None          # config token in the master's sync.beacon
        self.net_start = {}            # token -> start sample time announced in the beacon
        self.sync_left = 0             # sync exchanges still to do with the master
        self.sync_t1 = None            # our timestamp in the outstanding sync.unicast
        self.sync_used = set()         # t1 values already answered (the network can duplicate frames)
        self.strict_sync = True        # answers must echo our t1 (off when replaying a capture)
        self.sync_next = 0.0           # when to send the next sync.unicast
        self.synced = False            # exchanges done: we report locked, in the master's timebase
        self.lock_reported = False     # the D's first locked status still has field_a 2
        self.lost_logged = False       # logged that the master's beacons stopped
        self.slave_only = False        # refuse to become clock master (the old behaviour)
        self.is_master = False         # we are the clock master
        self.trans = (0, 1)            # beacon transition_state / transition_value (also status event counter)
        self.switch = None             # monotonic time of a scheduled master clock switch
        self.next_beacon = 0.0
        self.answered = {}             # slave MAC -> (t1, time) of the last sync request we answered
        self.on_change = None          # callback(self) when config/clock state changes

    # ---------------------------------------------------------------- frames
    @staticmethod
    def reply(req, body):
        """Reply header: echo the request, swap ports, set the reply bit."""
        h = bytearray(req[:22])
        h[6:8], h[8:10] = req[8:10], req[6:8]
        h[11] = req[11] | 0x80
        h[12:14] = b'\0\0'
        return bytes(h) + body

    @staticmethod
    def status(code):
        return struct.pack('<I', code)

    # -------------------------------------------------------------- dispatch
    def handle(self, src, dst, p, now):
        if len(p) < 22 or src == self.mac:
            return []
        sp, dp, op, mc = struct.unpack_from('<HHBB', p, 6)
        is_reply = bool(mc & 0x80)
        out = []

        # Broadcast/peer traffic we only listen to
        if sp == S_SYNC and dp == S_SYNC and not is_reply:
            if op == 0x01 and len(p) >= 42:        # sync.beacon from the clock master
                if self.master and src == self.master[0]:
                    st, = struct.unpack_from('<I', p, 22)
                    rate, = struct.unpack_from('<I', p, 38)
                    self.clock.sync(now, st, rate)
                    self.clock.heard = now
                    if len(p) >= 70:
                        tok, = struct.unpack_from('<I', p, 50)
                        tstate, tval = struct.unpack_from('<II', p, 62)
                        if tstate == 2:             # master announces when config `tok` starts
                            self.net_start[tok] = tval
                        elif tstate == 5 and self.pending and self.activated != self.pending[0]:
                            # Master announces the start of the config it was just activated with
                            # (the beacon still carries the old token).  Use it instead of our estimate.
                            at = tval
                            if self.activation != (self.pending[0], at):
                                self.activation = (self.pending[0], at)
                                self.pending = (self.pending[0], now + s32(at - st) / self.clock.rate)
                                self.log('   master beacon: config %08x starts at sample %d (0x%08x)' % (
                                    self.pending[0], at, at))
                                self.changed()
                        self.net_token = tok
                        self.running_token(now)
            elif op == 0x03 and dst == self.mac and len(p) >= 46 and self.master and src == self.master[0]:
                self.sync_reply(p[22:], now)
            elif op == 0x02 and dst == self.mac and self.is_master and len(p) >= 26:
                # A slave's timestamp request: answer at once with our receive/send times
                # (the real D as master: t3 - t2 = 1 sample)
                t1, = struct.unpack_from('<I', p, 22)
                last = self.answered.get(src)
                if last and last[0] == t1 and now - last[1] < 0.5:
                    return []                  # the same request seen twice (e.g. a mirrored switch port)
                self.answered[src] = (t1, now)
                t2 = self.now_st(now)
                hdr = struct.pack('<HHHHHBBH', 0x0501, 3, 0x0401, S_SYNC, S_SYNC, 0x03, 0x09, 0) + b'\0' * 8
                return [(src, hdr + struct.pack('<7I', OK, t1, 0, t2, 0, u32(t2 + 1), 0))]
            return []
        if sp == S_DISC and dp == S_DISC and op == 0x02 and not is_reply:
            return [(src, self.reply(p, self.status(OK)))]   # answer every discovery.ping
        if is_reply or dp != 0x64 + sp:
            return []
        if dst not in (self.mac, BCAST):
            return []

        svc = sp
        if svc == S_DEV and op == 0x06:            # device.presence (broadcast, 5 Hz)
            if src == self.owner:
                self.owner_seen = now
            body = struct.pack('<III', OK, 1 if src == self.owner else 0, len(self.name)) + self.name
            return [(src, self.reply(p, body))]
        if dst != self.mac:
            return []

        self.expire_owner(now)
        if svc not in self.services and not (self.answer_property and (svc, op) == (S_CLOCK, 0x16)):
            self.log('  ignored request for unlisted service %d op 0x%02x from %s' % (svc, op, mac_s(src)))
            return []
        fn = HANDLERS.get((svc, op))
        if fn is None:
            self.log('  unhandled request svc %d op 0x%02x from %s: %s' % (svc, op, mac_s(src), p[22:].hex()))
            return []
        if (svc, op) in OWNER_ONLY and self.owner is not None and src != self.owner:
            return [(src, self.reply(p, self.status(E_NOT_OWNER)))]
        body, extra = fn(self, src, p[22:], now), []
        if isinstance(body, tuple):
            body, extra = body
        out.append((src, self.reply(p, body)))
        return out + extra

    # ------------------------------------------------------- clock sync with the master
    def tick(self, now):
        """Periodic work; returns frames to send (the sync.unicast exchange)."""
        out = []
        if self.master is None:
            return out
        self.running_token(now)                # start a pending config on time
        if self.is_master:
            return self.master_tick(now)
        if self.synced and self.clock.heard is not None and not self.clock.hearing(now) and not self.lost_logged:
            # The real D keeps reporting locked and free-runs when its master disappears; the
            # controller fails over (about 2 s) and sends announce_master, which re-syncs us.
            self.log('clock: master beacons stopped; free-running until the controller announces a master')
            self.lost_logged = True
        elif self.clock.hearing(now):
            self.lost_logged = False
        if self.sync_left and now >= self.sync_next and self.clock.heard is not None:
            self.sync_next = now + SYNC_INTERVAL
            hdr = struct.pack('<HHHHHBBH', 0x0501, 3, 0x0401, S_SYNC, S_SYNC, 0x02, 0x09, 0) + b'\0' * 8
            self.sync_t1 = self.clock.local_st(now)
            out.append((self.master[0], hdr + struct.pack('<I', self.sync_t1) + b'\0' * 16, SYNC_VLAN))
        return out

    # ------------------------------------------------------- clock master
    def become_master(self, now, cls, prio, rate):
        if not self.is_master:
            # Keep the timebase we were locked to (a promoted slave continues it seamlessly)
            if self.clock.master is None:
                self.clock.master = (now, self.clock.local_st(now))
            else:
                self.clock.master = (now, self.clock.master_st(now))
            self.log('clock: we are now MASTER (class %d prio %d, %d Hz), timebase continues at %d' % (
                cls, prio, rate or self.clock.rate, self.clock.master_st(now)))
            self.is_master, self.switch = True, None
            self.sync_left, self.synced = 0, True
            self.trans, self.next_beacon = (0, 1), now
        self.master = (self.mac, cls, prio)
        if rate and rate != self.clock.rate:
            self.log('clock: master rate now %d Hz' % rate)
            self.clock.set_rate(now, rate)
        self.changed()

    def schedule_switch(self, now):
        """set_master(us) while idle: a clock switch at a 512-aligned point, announced in the beacon
        (transition_state 2); afterwards the state is 1 until the next activation completes."""
        lead = CLOCK_SWITCH_LEAD * self.clock.rate // 48000
        st = self.now_st(now)
        at = u32((st + lead + 511) & ~511)
        self.switch = now + u32(at - st) / self.clock.rate
        self.trans = (2, at)
        self.log('clock: master clock switch scheduled at sample %d' % at)

    def master_tick(self, now):
        out = []
        if self.switch and now >= self.switch:
            self.switch, self.trans = None, (1, 1)
            self.changed()
        if self.trans[0] == 5 and self.pending is None:
            self.trans = (0, 1)                # the activated config has started
        if now >= self.next_beacon:
            self.next_beacon = max(self.next_beacon + BEACON_INTERVAL, now - BEACON_INTERVAL)
            hdr = struct.pack('<HHHHHBBH', 0x0501, 0, 0x0401, S_SYNC, S_SYNC, 0x01, 0x09, 0) + b'\0' * 8
            body = struct.pack('<12I', self.now_st(now), 0, 0, 0, self.clock.rate, 0, 0, self.running,
                               0, 1, self.trans[0], self.trans[1])
            out.append((BCAST, hdr + body, SYNC_VLAN))
        return out

    def stand_down(self, now):
        if self.is_master:
            self.log('clock: no longer master')
            self.is_master, self.switch, self.trans = False, None, (0, 1)

    def start_sync(self, now):
        self.sync_left, self.sync_next, self.synced, self.lock_reported = SYNC_EXCHANGES, now, False, False
        self.changed()

    def sync_reply(self, b, now):
        """sync.03: status, t1 (our time, echoed), t2/t3 (master receive/send times), each u32 + u32."""
        st, t1, _, t2, _, t3, _ = struct.unpack_from('<7I', b)
        if st or not self.sync_left or t1 in self.sync_used:
            return                             # error, not syncing, or a duplicate answer
        if self.strict_sync and t1 != self.sync_t1:
            return                             # not the answer to our outstanding request
        self.sync_used.add(t1)
        self.sync_t1 = None
        t4 = self.clock.local_st(now)
        rtt = s32(t4 - t1) - s32(t3 - t2)
        self.clock.sync(now, u32(t3 + rtt // 2))
        self.sync_left -= 1
        if not self.sync_left:
            self.synced = True
            self.log('clock LOCKED to %s (round trip %d samples)' % (mac_s(self.master[0]), rtt))
            self.changed()

    def locked(self, now):
        # Stays locked through a master outage (free-running), as the real D does
        return self.master is not None and (self.synced or self.is_master)

    def now_st(self, now):
        """The sample time we report: the master's once locked, our own before."""
        return self.clock.master_st(now) if self.locked(now) else self.clock.local_st(now)

    def expire_owner(self, now):
        if OWNER_TIMEOUT and self.owner and self.owner_seen is not None and now - self.owner_seen > OWNER_TIMEOUT:
            self.log('owner %s silent for %.0f s, releasing claim' % (mac_s(self.owner), OWNER_TIMEOUT))
            self.owner = None

    def changed(self):
        if self.on_change:
            self.on_change(self)

    # ------------------------------------------------------- service 0: device
    def dev_claim(self, src, b, now):
        if self.owner is not None:
            return self.status(E_CLAIMED)
        self.owner, self.owner_seen = src, now
        self.log('claimed by %s' % mac_s(src))
        return self.status(OK)

    def dev_release(self, src, b, now):
        # device.op0a: the IOC's presence reply switched to assigned = 0 right after it
        self.log('released by %s' % mac_s(src))
        self.owner = None
        return self.status(OK)

    def dev_set_state(self, src, b, now):
        self.log('set_state %d' % (struct.unpack_from('<I', b)[0] if len(b) >= 4 else -1))
        return self.status(OK)

    # ------------------------------------------------------- service 2: clock
    def clk_set_master(self, src, b, now):
        m, cls, prio, rate, enable = struct.unpack_from('<6sBBII', b)
        if m == self.mac:
            if self.slave_only:
                self.log('REFUSED clock.set_master(us): slave-only (--slave-only)')
                return self.status(E_REFUSED)
            if not self.is_master:
                return self.status(E_REFUSED)  # the real D: 0x27 until announce_master(us) arrives
            # The real D's answer depends on its transition state, not on the rate (which only
            # changes on announce_master): 2 (switch pending) -> 0, 1 (switched) -> 0x14,
            # 0 (idle, e.g. after an activation) -> schedule a switch and answer 0.
            if self.trans[0] == 2:
                return self.status(OK)
            if self.trans[0] == 1:
                return self.status(E_BUSY)
            self.schedule_switch(now)
            return self.status(OK)
        self.stand_down(now)
        if self.master and self.master[0] == m and self.clock.rate == rate:
            return self.status(E_BUSY)         # already following it: controller follows up with announce_master
        self.follow(now, (m, cls, prio), rate)
        return self.status(OK)

    def clk_announce(self, src, b, now):
        m, cls, prio, rate, _ = struct.unpack_from('<6sBBII', b)
        if m == self.mac:
            if self.slave_only:
                self.log('REFUSED clock.announce_master(us): slave-only (--slave-only)')
                return self.status(E_REFUSED)
            self.become_master(now, cls, prio, rate)
            return self.status(OK)
        self.stand_down(now)
        self.follow(now, (m, cls, prio), rate)
        return self.status(OK)

    def follow(self, now, master, rate):
        if master != self.master or rate != self.clock.rate:
            self.log('clock: slave to %s class %d prio %d at %d Hz' % (mac_s(master[0]), master[1], master[2], rate))
        new = self.master is None or master[0] != self.master[0]
        rate_change = bool(rate) and rate != self.clock.rate
        if new:
            self.clock.heard = self.clock.master = None   # wait for the new master's beacons
        self.master = master
        self.clock.set_rate(now, rate)
        if new or rate_change:                 # the real D re-runs the exchanges after a rate change too
            self.start_sync(now)
        self.changed()

    def clk_status(self, src, b, now):
        st = self.now_st(now)
        if self.is_master:                     # the D as master: state 1, itself, event counter = transition
            return struct.pack('<IIIIiII6sBBIHBBII', OK, self.clock.rate, 1, 0, 0, 0, 0, self.mac,
                               self.master[1], self.master[2], st, 0, self.master[1], self.master[2],
                               self.trans[0], 0)
        if self.master is None:                # never given a master (seen at power-up)
            state, fa, fb, fc = 0, 0, 0, 0
            mid = (b'\0' * 6,) + OWN_CLASS_PRIO
        elif self.locked(now):                 # locked: the real D also jitters field_b by +-1
            state, fa, fb, fc = 1, 0 if self.lock_reported else 2, 0, 0
            self.lock_reported = True
            mid = self.master
        else:                                  # syncing: field_c = exchanges left
            state, fa, fb, fc = 2, 2, 0, self.sync_left
            mid = self.master
        return struct.pack('<IIIIiII6sBBIHBBII', OK, self.clock.rate, state, fa, fb, fc, 0,
                           mid[0], mid[1], mid[2], st, 0, mid[1], mid[2], 0, 0)

    def clk_property(self, src, b, now):
        pid, ln, flags = struct.unpack_from('<IHH', b)
        if flags & 8:                          # write
            self.props[pid] = b[8:8 + ln]
            self.log('clock.property write 0x%x = %s' % (pid, b[8:8 + ln].hex()))
        data = self.props.get(pid, b'')
        if not data and ln == 0 and self.prop_default is not None:
            # A model's first property read (e.g. the D's 0x20) is a plain u32; the D answers 1
            data = struct.pack('<I', self.prop_default)
            if pid not in self.props:
                self.log('clock.property 0x%x read: answering %d (--prop-default)' % (pid, self.prop_default))
                self.props[pid] = data
        return struct.pack('<IIHH', OK, pid, len(data), flags) + data

    # ------------------------------------------------------ service 10: discovery
    def disc_op01(self, src, b, now):
        ping = struct.pack('<HHHHHBBH', 0x0501, 3, 0x0201, S_DISC, S_DISC, 0x02, 0x0a, 0) + b'\0' * 8
        return self.status(OK), [(BCAST, ping)]

    # ------------------------------------------------------- service 1: stream
    def st_set_config(self, src, b, now):
        cfg = parse_set_config(b)
        if cfg['token'] == self.token:
            return struct.pack('<II', E_SAME_CONFIG, cfg['version'])
        self.token, self.config, self.config_raw = cfg['token'], cfg, bytes(b)
        # The rate is not taken from set_config: it changes only through set_master/announce_master
        # (a rate-only set_config is refused with 0x25 on the real D, and the controller sends the
        # clock commands first).
        self.log('set_config token %08x: %d Hz, clock master %s, %d tx, %d rx' % (
            cfg['token'], cfg['rate'], cfg['clock_master'], len(cfg['tx']), len(cfg['rx'])))
        for t in cfg['tx']:
            self.log('   tx%d -> %s stream %d fpp %d ch %s' % (t['index'], t['dst_mac'], t['dst_stream_id'], t['fpp'], t['channels']))
        for r in cfg['rx']:
            self.log('   rx <- %s stream %d fpp %d map %s' % (r['src_mac'], r['stream_id'], r['fpp'], r['map']))
        res = [0] * len(cfg['tx']) + [0x0b if r['stream_flags'] == ROUTED_RX_FLAGS else 0 for r in cfg['rx']]
        if self.master is not None and not self.is_master:
            # Slave: no activate_config comes; the streams start at a fixed lead after set_config
            lead = SLAVE_START_LEAD * self.clock.rate // 48000
            mst = self.clock.master_st(now)
            at = u32((mst + lead + 511) & ~511)
            self.pending = (cfg['token'], now + u32(at - mst) / self.clock.rate)
            self.activation = (cfg['token'], at)
            self.log('   streams start at about sample %d (0x%08x): an estimate, often one 512-block late; '
                     'receivers should switch on the first packet with the new token (byte map 10.5)' % (at, at))
        self.changed()
        return struct.pack('<IIIHH', OK, cfg['version'], cfg['token'], len(cfg['tx']), len(cfg['rx'])) + \
            struct.pack('<%dH' % len(res), *res)

    def st_activate(self, src, b, now):
        tok, = struct.unpack_from('<I', b)
        if tok == self.activated:
            return self.status(E_SAME_CONFIG)
        self.activated = tok
        lead = ACTIVATE_LEAD * self.clock.rate // 48000
        at = u32((self.now_st(now) + lead + 511) & ~511)
        self.activation = (tok, at)
        self.pending = (tok, now + u32(at - self.now_st(now)) / self.clock.rate)
        if self.is_master:
            self.trans = (5, at)               # announced in our beacon so slaves can follow
        if not self.locked(now):
            self.log('WARNING: activating while not locked to a clock master; start time is on our local counter')
        self.log('activate_config %08x: streams start at sample %d (0x%08x)' % (tok, at, at))
        self.changed()
        return struct.pack('<II', OK, at)

    def table_head(self, n):
        g = self.config['guid'] if self.config else b'\0' * 16
        return struct.pack('<II16sIHH', OK, self.token, g, 1, n, n)

    def listed_rx(self):
        return [r for r in (self.config['rx'] if self.config else []) if r['stream_flags'] != ROUTED_RX_FLAGS]

    def st_rx_table(self, src, b, now):
        first, mx = struct.unpack_from('<HH', b)
        rx = self.listed_rx()
        out = struct.pack('<II16sIHH', OK, self.token, self.config['guid'] if self.config else b'\0' * 16, 1,
                          len(rx[first:first + mx]), len(rx))
        for r in rx[first:first + mx]:
            ch = [m[0] for m in r['map']]       # the D lists the stream channels
            e = struct.pack('<H6sHHHH', r['stream_id'], mac_b(r['src_mac']), r['fpp'], r['stream_flags'],
                            len(ch), 0) + struct.pack('<%dH' % len(ch), *ch)
            out += e + b'\0' * (-len(e) % 4)
        return out

    def st_tx_table(self, src, b, now):
        first, mx = struct.unpack_from('<HH', b)
        tx = (self.config['tx'] if self.config else [])[first:first + mx]
        out = self.table_head(len(tx))
        for t in tx:
            e = struct.pack('<H6sHHHH', t['index'], mac_b(t['dst_mac']), t['dst_stream_id'], t['fpp'],
                            len(t['channels']), 0) + struct.pack('<%dH' % len(t['channels']), *t['channels'])
            out += e + b'\0' * (-len(e) % 4)
        return out

    def st_rx_status(self, src, b, now):
        # Reports the new token only once the config has started.  One 28-byte record per
        # listed RX stream; we report every one as healthy (the audio side is not ours).
        _r, want, _p = struct.unpack_from('<HHI', b)
        tok = self.running_token(now)
        rx = self.listed_rx() if tok == self.token else []
        n = min(want, len(rx))
        return struct.pack('<IIHH', OK, tok, n, len(rx)) + \
            b''.join(struct.pack('<6Ii', i, 0, 0, 0, 0, 0, 8) for i in range(n))

    def running_token(self, now):
        # Clock master: activate_config gave us the start time.
        if self.pending and now >= self.pending[1]:
            self.running, self.pending = self.pending[0], None
            self.log('config %08x running' % self.running)
            self.changed()
        # Slave: only the master gets activate_config.  Our config starts when the master's
        # beacon carries its token, at the start time the beacon announced (if it did).
        if self.token != self.running and self.net_token == self.token and self.pending is None \
                and self.locked(now):
            start, st = self.net_start.get(self.token), self.now_st(now)
            if start is None or u32(st - start) < 0x80000000:
                self.running = self.token
                self.activation = (self.token, start if start is not None else st)
                self.log('config %08x running (master beacon), started at sample %d (0x%08x)' % (
                    self.token, self.activation[1], self.activation[1]))
                self.changed()
        return self.running

    def load_config(self, raw):
        """Restore the last set_config (from the state file) after a restart."""
        cfg = parse_set_config(raw)
        self.token, self.config, self.config_raw = cfg['token'], cfg, raw
        self.log('restored config %08x from state file (%d tx, %d rx)' % (cfg['token'], len(cfg['tx']), len(cfg['rx'])))

    # ------------------------------------------------------- state export
    def state(self, now):
        cfg = self.config
        return {
            'mac': mac_s(self.mac),
            'owner': mac_s(self.owner) if self.owner else None,
            'sample_rate': self.clock.rate,
            'clock_master': mac_s(self.master[0]) if self.master else None,
            'we_are_master': self.is_master,
            'clock_only_tx': [t for t in (cfg['tx'] if cfg else []) if not t['channels']],
            'locked': self.locked(now),
            'sample_time_now': self.now_st(now),
            'sample_time_at': time.time(),
            'config_token': '%08x' % self.token,
            'activated_token': '%08x' % self.activated,
            'running_token': '%08x' % self.running_token(now),
            'activation_sample_time': self.activation[1] if self.activation else None,
            'tx': cfg['tx'] if cfg else [],
            'rx': cfg['rx'] if cfg else [],
            'set_config_hex': self.config_raw.hex(),
        }


def parse_set_config(b):
    ver, tok, rate, cm, cport, guid, p1, ntx, nrx = struct.unpack_from('<III6sH16sIHH', b)
    o, tx, rx = 44, [], []
    for _ in range(ntx):
        st = o
        dm, idx, sid, fl, fpp, sfl, _r, n = struct.unpack_from('<6sHHHHHHH', b, o)
        o += 20
        ch = list(struct.unpack_from('<%dH' % n, b, o)); o += 2 * n
        o += -(o - st) % 4
        tx.append({'dst_mac': mac_s(dm), 'index': idx, 'dst_stream_id': sid, 'flags': fl, 'fpp': fpp,
                   'stream_flags': sfl, 'channels': ch})
    for _ in range(nrx):
        sm, sid, fl, fpp, sfl, n = struct.unpack_from('<6sHHHHH', b, o)
        o += 16
        m = struct.unpack_from('<%dH' % (2 * n), b, o); o += 4 * n
        rx.append({'src_mac': mac_s(sm), 'stream_id': sid, 'flags': fl, 'fpp': fpp, 'stream_flags': sfl,
                   'map': [[m[i], m[i + 1]] for i in range(0, len(m), 2)]})
    return {'version': ver, 'token': tok, 'rate': rate, 'clock_master': mac_s(cm), 'guid': guid,
            'tx': tx, 'rx': rx}


const = lambda body: (lambda self, src, b, now: body)
HANDLERS = {
    (S_DEV, 0x02): lambda self, src, b, now: build_services(self.services),
    (S_DEV, 0x05): FakeD.dev_claim,
    (S_DEV, 0x08): FakeD.dev_set_state,
    (S_DEV, 0x0a): FakeD.dev_release,
    (S_STREAM, 0x10): lambda self, src, b, now: self.caps,
    (S_STREAM, 0x14): FakeD.st_rx_table,
    (S_STREAM, 0x17): FakeD.st_rx_status,
    (S_STREAM, 0x18): FakeD.st_tx_table,
    (S_STREAM, 0x1c): FakeD.st_activate,
    (S_STREAM, 0x1e): FakeD.st_set_config,
    (S_CLOCK, 0x10): const(struct.pack('<I', OK)),
    (S_CLOCK, 0x11): FakeD.clk_announce,
    (S_CLOCK, 0x12): FakeD.clk_status,
    (S_CLOCK, 0x16): FakeD.clk_property,
    (S_CLOCK, 0x20): FakeD.clk_set_master,
    (S_FW, 0x01): lambda self, src, b, now: self.firmware,
    (S_SYNC, 0x04): const(SYNC_OP04),
    (S_DISC, 0x01): FakeD.disc_op01,
    (S_DISC, 0x03): const(DISCOVERY_OP03),
    (S_16, 0x30): const(SVC16_OP30),
}
# Requests the real D refused with 0x16 when they came from a controller that did not own it
OWNER_ONLY = {(S_DEV, 0x08), (S_STREAM, 0x14), (S_STREAM, 0x17), (S_STREAM, 0x18), (S_STREAM, 0x1c),
              (S_STREAM, 0x1e), (S_CLOCK, 0x11), (S_CLOCK, 0x12), (S_CLOCK, 0x20)}


# ---------------------------------------------------------------------------
# macOS BPF link
# ---------------------------------------------------------------------------
def _iow(n, size):
    return 0x80000000 | (size << 16) | (ord('B') << 8) | n

BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xc0044266
BIOCSETF = _iow(103, 16)
BIOCPROMISC = 0x20004269
BIOCSETIF = _iow(108, 32)
BIOCIMMEDIATE = _iow(112, 4)
BIOCSHDRCMPLT = _iow(117, 4)
BIOCSSEESENT = _iow(119, 4)

# Accept EtherType 0x8908 (plain or 802.1Q), but drop stream.audio (opcode 0) so
# audio traffic never reaches Python.
_FILTER = [
    (0x28, 0, 0, 12),       # 0  ldh [12]
    (0x15, 0, 2, 0x8908),   # 1  jeq 0x8908 ? 2 : 4
    (0x30, 0, 0, 24),       # 2  ldb [24]   opcode
    (0x15, 6, 5, 0),        # 3  jeq 0 ? 10 (drop) : 9 (keep)
    (0x15, 0, 5, 0x8100),   # 4  jeq 0x8100 ? 5 : 10
    (0x28, 0, 0, 16),       # 5  ldh [16]
    (0x15, 0, 3, 0x8908),   # 6  jeq 0x8908 ? 7 : 10
    (0x30, 0, 0, 28),       # 7  ldb [28]   opcode
    (0x15, 1, 0, 0),        # 8  jeq 0 ? 10 : 9
    (0x06, 0, 0, 0x40000),  # 9  keep
    (0x06, 0, 0, 0),        # 10 drop
]


class BpfLink:
    def __init__(self, iface):
        self.fd = None
        for i in range(256):
            try:
                self.fd = os.open('/dev/bpf%d' % i, os.O_RDWR)
                break
            except OSError as e:
                if e.errno == 13:
                    sys.exit('permission denied on /dev/bpf*: add yourself to access_bpf (Wireshark ChmodBPF)')
        if self.fd is None:
            sys.exit('no free /dev/bpf device')
        fcntl.ioctl(self.fd, BIOCSBLEN, struct.pack('I', 1 << 20))
        fcntl.ioctl(self.fd, BIOCSETIF, struct.pack('16s16x', iface.encode()))
        for req in (BIOCIMMEDIATE, BIOCSHDRCMPLT, BIOCSSEESENT):
            fcntl.ioctl(self.fd, req, struct.pack('I', 1))
        fcntl.ioctl(self.fd, BIOCPROMISC)      # we answer to a MAC the NIC does not own
        self._insns = (ctypes.c_ubyte * (8 * len(_FILTER))).from_buffer_copy(
            b''.join(struct.pack('HBBI', *x) for x in _FILTER))
        fcntl.ioctl(self.fd, BIOCSETF, struct.pack('IxxxxQ', len(_FILTER), ctypes.addressof(self._insns)))
        self.blen = struct.unpack('I', fcntl.ioctl(self.fd, BIOCGBLEN, b'\0' * 4))[0]

    def recv(self, timeout):
        """Yield (src, dst, payload) for SoundGrid frames, waiting at most `timeout`."""
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return
        buf = os.read(self.fd, self.blen)
        o = 0
        while o + 18 <= len(buf):
            caplen, _dl, hdrlen = struct.unpack_from('<IIH', buf, o + 8)
            fr = buf[o + hdrlen:o + hdrlen + caplen]
            o += (hdrlen + caplen + 3) & ~3
            if len(fr) < 14:
                continue
            et = struct.unpack_from('>H', fr, 12)[0]
            off = 14
            if et == 0x8100 and len(fr) >= 18:
                et, off = struct.unpack_from('>H', fr, 16)[0], 18
            if et == ETH_SG:
                yield fr[6:12], fr[0:6], fr[off:]

    def send(self, src, dst, payload, vlan=None):
        tag = struct.pack('>HH', 0x8100, vlan) if vlan is not None else b''
        fr = dst + src + tag + struct.pack('>H', ETH_SG) + payload
        os.write(self.fd, fr + b'\0' * max(0, 60 - len(fr)))


# ---------------------------------------------------------------------------
# Live
# ---------------------------------------------------------------------------
def run_live(a):
    mac = mac_b(a.mac)
    stamp = lambda: time.strftime('%H:%M:%S')
    log = lambda s: print('%s %s' % (stamp(), s), flush=True)
    link = BpfLink(a.iface)
    ids = [int(x, 0) for x in a.firmware_ids.split(',')] if a.firmware_ids else None
    if ids is not None and len(ids) != 9:
        sys.exit('--firmware-ids needs 9 comma-separated numbers')
    fw = [int(x) for x in a.fw_version.split('.')] if a.fw_version else None
    if fw is not None and (len(fw) != 4 or not all(0 <= x < 256 for x in fw)):
        sys.exit('--fw-version needs 4 numbers 0-255, e.g. 17.31.0.0')
    svcs = [int(x) for x in a.services.split(',')] if a.services else D_SERVICES
    d = FakeD(mac, time.monotonic(), log, a.inputs, a.outputs, a.name.encode(), ids, a.prop_default, fw, svcs)
    d.answer_property = a.answer_property
    d.slave_only = a.slave_only
    for pv in a.prop or []:
        pid, val = (int(x, 0) for x in pv.split('='))
        d.props[pid] = struct.pack('<I', val)
        log('clock.property 0x%x will read as %d' % (pid, val))
    if a.verbose:
        from sg_decode import decode
    if a.state_file:
        def write_state(dev):
            tmp = a.state_file + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(dev.state(time.monotonic()), f, indent=1)
            os.replace(tmp, a.state_file)
        try:
            raw = bytes.fromhex(json.load(open(a.state_file)).get('set_config_hex', ''))
            if raw:
                d.load_config(raw)
        except (OSError, ValueError):
            pass
        d.on_change = write_state
        write_state(d)
    log('fake device "%s" %s on %s, %d in x %d out, firmware ids %s, version %s (%s, control plane only)' % (
        a.name, a.mac, a.iface, a.inputs, a.outputs, ','.join('0x%x' % x for x in (ids or FIRMWARE_IDS)),
        a.fw_version or '17.15.16.0', 'clock slave only' if a.slave_only else 'clock slave or master'))

    def send(frames):
        for to, out, *vlan in frames:
            link.send(mac, to, out, *vlan)
            if a.verbose and out[10] != 0x06:
                _, name, _ = decode(out, False)
                log('  > %s %s %s' % (mac_s(to), name, out[22:].hex()))

    while True:
        for src, dst, p in link.recv(0.02):
            now = time.monotonic()
            send(d.handle(src, dst, p, now))
            if a.verbose and src != mac and p[10] != 0x06 and dst in (mac, BCAST) and not (p[6] == 9 and p[10] == 1):
                _, name, _ = decode(p, True)
                log('< %s %s %s' % (mac_s(src), name, p[22:].hex()))
        now = time.monotonic()
        d.expire_owner(now)
        send(d.tick(now))


# ---------------------------------------------------------------------------
# Self-test against a capture
# ---------------------------------------------------------------------------
def find_device_mac(frames, name=DEVICE_NAME):
    """MAC of the device in a capture (frames as in selftest): the node that sends the most
    replies carrying its name, i.e. its device.presence.reply frames, to another node."""
    votes = collections.Counter(s for ts, s, d, v, p in frames
                                if len(p) > 11 and p[11] & 0x80 and s != d and name in p)
    return votes.most_common(1)[0][0] if votes else None


def selftest(path, real_mac=None):
    from pcapng import sg_frames
    from sg_decode import decode
    frames = [(ts, mac_b(s), mac_b(d), v, p) for ts, s, d, v, p in sg_frames(path)
              if not (p[10] == 0 and p[6:8] == b'\x01\x00')]
    D = mac_b(real_mac) if real_mac else find_device_mac(frames)
    if D is None:
        sys.exit('no %s presence reply in the capture: give --real-mac' % DEVICE_NAME.decode())
    t0 = frames[0][0]
    # Real replies from D, indexed for matching: (dst, ctx, port pair, opcode, msgclass) -> [(ts, payload, padded)]
    real = collections.defaultdict(collections.deque)
    for ts, s, d, v, p in frames:
        if s == D and (p[11] & 0x80):
            padded = len(p) + (18 if v is not None else 14) <= 60 + (4 if v is not None else 0)
            real[(d, p[2:4], p[6:10], p[10], p[11], p[14:22])].append((ts, p, padded))
    dev = FakeD(D, t0, log=lambda s: None)
    dev.strict_sync = False                    # recorded answers echo the real D's timestamps, not ours
    stats = collections.defaultdict(collections.Counter)
    shown = collections.Counter()
    master_capture = False
    for ts, s, d, v, p in frames:
        if s == D and p[10] == 0x01 and p[6] == 9:
            master_capture = True
        for to, out, *_ in dev.handle(s, d, p, ts) + dev.tick(ts):
            _, name, _ = decode(out, False)
            if not out[11] & 0x80:
                stats[name]['sent (unsolicited)'] += 1
                continue
            q = real[(to, out[2:4], out[6:10], out[10], out[11], out[14:22])]
            while q and q[0][0] < ts - 0.001:
                q.popleft()
            if not q or q[0][0] > ts + 1.0:
                stats[name]['no real reply'] += 1
                continue
            _, rp, padded = q.popleft()
            verdict = compare(name, out, rp, padded)
            stats[name][verdict] += 1
            if verdict.startswith('DIFF') and shown[name] < 3:
                shown[name] += 1
                print('%-30s t=%.3f %s\n    ours: %s\n    real: %s' % (name, ts - t0, verdict, out[22:].hex(), rp[22:].hex()))
    print('\n%-32s %s' % ('reply', 'results'))
    for name in sorted(stats):
        print('%-32s %s' % (name, ', '.join('%s: %d' % kv for kv in sorted(stats[name].items()))))
    if master_capture:
        print('\nNote: in this capture the real D was clock MASTER; the fake ran in master mode too. '
              'The status event counter while an activate_config is pending is not consistent on the real D '
              '(0 here, 5 in another capture).')


def compare(name, ours, real, padded):
    if ours[:22] != real[:22]:
        return 'DIFF header'
    ob, rb = ours[22:], real[22:]
    if len(rb) < len(ob) or (len(rb) > len(ob) and not padded):
        return 'DIFF length (%d vs %d)' % (len(ob), len(rb))
    rb = rb[:len(ob)]
    if name == 'clock.get_status.reply':       # sample_time and field_b (+-1 phase jitter) are live values
        ob, rb = ob[:16] + ob[20:36] + ob[40:], rb[:16] + rb[20:36] + rb[40:]
    if name == 'stream.get_rx_status.reply':   # per-record arrival offset jitters (5..10 in the capture)
        mask = lambda x: b''.join(x[i:i + 4] if (i - 12) % 28 != 24 else b'' for i in range(0, len(x), 4))
        ob, rb = mask(ob), mask(rb)
    if name == 'stream.activate_config.reply' and ob[:4] == rb[:4] == b'\0\0\0\0':
        a, r = struct.unpack_from('<I', ob, 4)[0], struct.unpack_from('<I', rb, 4)[0]
        return 'match (start time aligned)' if a % 512 == 0 and r % 512 == 0 else 'DIFF start time not aligned'
    return 'match' if ob == rb else 'DIFF body'


def main(**defaults):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--inputs', type=int, default=4, help='physical inputs reported in get_caps (default %(default)s)')
    ap.add_argument('--outputs', type=int, default=4, help='physical outputs reported in get_caps (default %(default)s)')
    ap.add_argument('--name', default=DEVICE_NAME.decode(), help='device type name in presence replies (default %(default)s)')
    ap.add_argument('--firmware-ids', help='the 9 u16 words in the firmware reply, e.g. 0,1,2,13,0xabcd,2,2,13,0 (the D\'s)')
    ap.add_argument('--prop-default', type=lambda x: int(x, 0), help='answer unknown clock.property reads with this u32 (the D answers 0x20 with 1)')
    ap.add_argument('--services', help='services listed by device.list_services, e.g. 0,1,4,9,10,16 (the D: 0,1,2,4,9,10,16)')
    ap.add_argument('--prop', action='append', metavar='ID=VALUE', help='answer clock.property ID with u32 VALUE, e.g. 0x20=0 (repeatable)')
    ap.add_argument('--slave-only', action='store_true', help='refuse to become clock master (0x27), as the earlier versions did')
    ap.add_argument('--answer-property', action='store_true', help='answer clock.property (the model property) even when service 2 is not listed')
    ap.add_argument('--fw-version', help='second firmware version, shown in the UI as 1.<a>.<b> (the D\'s is 17.15.16.0; e.g. 17.31.0.0)')
    ap.add_argument('--iface', help='network interface, e.g. en13')
    ap.add_argument('--mac', default=DEFAULT_MAC, help='our MAC address (default %(default)s)')
    ap.add_argument('--state-file', help='write routing/clock state as JSON here on every change')
    ap.add_argument('-v', '--verbose', action='store_true', help='log every request and reply')
    ap.add_argument('--selftest', metavar='PCAPNG', help='replay a capture and compare with the real D')
    ap.add_argument('--real-mac', help='MAC of the real D in the capture (default: found from its presence replies)')
    ap.set_defaults(**defaults)
    a = ap.parse_args()
    if a.selftest:
        selftest(a.selftest, a.real_mac)
    elif a.iface:
        try:
            run_live(a)
        except KeyboardInterrupt:
            pass
    else:
        ap.error('give --iface or --selftest')


if __name__ == '__main__':
    main()
