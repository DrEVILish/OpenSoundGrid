# SoundGrid Bridge: FPGA Control-Plane Specification

Version 0.1, 2026-10-13. This spec covers the control plane only: discovery, ownership, attach, clock (slave and master), and routing. The audio datapath is specified elsewhere; section 8 lists what the control logic must hand to it.

**Source of truth.** Every rule here comes from the captures in this folder and is written up in [SoundGrid_byte_map.md](SoundGrid_byte_map.md) ("BM §n" below). The reference implementation is [tools/fake_d.py](tools/fake_d.py); section 12 explains how to use it as an acceptance test.

**Interim identity.** Until Waves registers the bridge, it presents itself as a **DiGiGrid D (4 in × 4 out)**. Every value copied from the D is marked **`[D]`** and listed in section 11. Each one must be replaced with the bridge's own value before release.

---

## 1. Conventions

- **Byte order:** all multi-byte fields are little-endian unless marked otherwise. Offsets are counted from the first byte after the EtherType (the "SG payload"), as in the byte map.
- **Sample counter (`st`):** a 32-bit counter of sample periods at the current rate. It wraps at 2³², which is about 24.8 h at 48 kHz.
- **`align_up(x, 512)`** means `(x + 511) & ~511`, computed modulo 2³².
- **Lead constants** are given in samples at 48 kHz. At another rate, scale them by `rate / 48000`. The scaling is an assumption: it was only observed at 48 kHz.

---

## 2. Identity values (interim)

| Item | Value | Source |
| --- | --- | --- |
| MAC address | the bridge's own (the Waves OUI `00:1c:d1` was used in tests; it is not required) | own |
| Presence type name | `DigiGridD` (9 bytes) **`[D]`**. Only used as the label for an *unknown* model (BM §10.4). | `[D]` |
| Service list | 0, 1, 2, 4, 9, 10, 16 **`[D]`** | `[D]` |
| Firmware reply | the D's reply, byte for byte (§5.4) **`[D]`**: model number 13 in words 3 and 7, `version_b` 17.15.16.0, build string `Oct 30 2021, 22:04:56` | `[D]` |
| Model property | `clock.property 0x20` = u32 `1` **`[D]`** | `[D]` |
| Capabilities | the D's `stream.get_caps` reply, 4 in × 4 out at 44.1/48/88.2/96 kHz **`[D]`** | `[D]` |
| Own clock class / priority | 1 / 2 **`[D]`** (the controller's `announce_master` supplies the values actually used) | `[D]` |

Rules learned about identity (BM §10.4):
- **The model number (firmware words 3 and 7) decides the device type:** the UI name, picture and I/O layout, and the model-specific property the controller reads first. The reported channel counts are ignored.
- **Firmware `version_b` byte 2 must not be 0.** With 0 the controller re-reads the firmware forever and the device never appears. The UI shows `1.<b0>.<b1>`.
- **The model number needs a matching device module in the controller.** Unknown numbers produce an "incompatible device: \<presence name\>" dialog.
- **The device must be able to become clock master** (§6.4). Model 13 is a master candidate, and a device that refuses stalls the whole system (BM §10.11).

---

## 3. Frame layer

### 3.1 Ethernet
- EtherType **`0x8908`** carries all control, clock and audio traffic. There is no IP and no UDP.
- **Minimum frame:** pad to 60 bytes (without FCS) **with zeros**. The real D leaves stale bytes in the padding; receivers must ignore padding bytes.
- **VLAN tag:** send `sync.beacon` and `sync.unicast` inside an 802.1Q tag with TCI `0xE000` (priority 7, VLAN 0), as the D does **`[D]`**. Send everything else untagged. Accept both tagged and untagged frames on receive.
- **Accept** frames addressed to your own MAC or to broadcast. Drop frames whose source MAC is your own.

### 3.2 Common header (22 bytes)

| Off | Len | Field | Notes |
| ---: | ---: | --- | --- |
| 0 | 2 | `proto_version` | always `01 05` |
| 2 | 2 | `context_id` | echo it in replies; for frames you originate use the value in §3.4 |
| 4 | 2 | `service_version` | per service: `01 05` svc 0, `01 10` svc 1, `01 11` svc 2, `01 06` svc 4, `01 04` svc 9, `01 02` svc 10, `01 01` svc 16 |
| 6 | 2 | `src_port` | service *n*: the controller uses port *n*, the device uses port `0x64 + n` |
| 8 | 2 | `dst_port` | |
| 10 | 1 | `opcode` | |
| 11 | 1 | `msgclass` | bit 7 = reply; bits 0–6 = interface code (svc0 `01`, svc1 `00`, svc2 `02`, svc4 `01`, svc9 `09`, svc10 `0a`, svc16 `0f`) |
| 12 | 2 | reserved | 0 |
| 14 | 8 | cookie | echo it in replies (usually `44 33 22 11 88 77 66 55`) |

### 3.3 Reply rule
To build any reply: **copy the request's 22-byte header, swap `src_port`/`dst_port`, set bit 7 of `msgclass`, set `reserved` to 0**, then append the reply body. Every reply body starts with **`u32 status`**.

| Status | Name | Used for |
| --- | --- | --- |
| `0x00` | OK | |
| `0x14` | busy / already | `set_master` that is already in effect (§6) |
| `0x16` | not owner | owner-only request from a non-owner (§5.1) |
| `0x17` | already claimed | `device.claim` when owned |
| `0x25` | same config | `set_config`/`activate_config` with the active token |
| `0x27` | refused | `set_master(us)` before `announce_master(us)` (§6.4) |

### 3.4 Frames the device originates

| Frame | ctx | svc ver | ports | opcode | msgclass | cookie | VLAN | Body |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `discovery.ping` (broadcast) | `03 00` | `01 02` | 10 → 10 | `02` | `0a` | 0 | no | empty |
| `sync.unicast` (slave → master) | `03 00` | `01 04` | 9 → 9 | `02` | `09` | 0 | **yes** | `u32 t1`, then 16 zero bytes |
| `sync.03` (master → slave) | `03 00` | `01 04` | 9 → 9 | `03` | `09` (no reply bit) | 0 | no | `u32 0, u32 t1, u32 0, u32 t2, u32 0, u32 t3, u32 0` |
| `sync.beacon` (master, broadcast) | `00 00` | `01 04` | 9 → 9 | `01` | `09` | 0 | **yes** | §6.4 |

---

## 4. Device state

| State variable | Reset value | Meaning |
| --- | --- | --- |
| `owner` | none | MAC of the controller that claimed the device. **Keep it across link loss** (BM §10.10); clear it only on `device.release` or power-on. |
| `master` | none | `(mac, class, prio)` of the clock master the controller announced, or the device itself |
| `is_master` | false | the device is clock master |
| `rate` | 48000 | current sample rate |
| `local_st` | any (the D's is not 0 at boot) | free-running sample counter |
| `master_st` | — | estimate of the master's counter (equals `local_st` + offset); the device's own counter when it is master |
| `sync_left` | 0 | sync exchanges still to do (0–10) |
| `synced` | false | the sync exchanges have completed |
| `trans` | (0, 1) | master only: beacon `transition_state` and `transition_value` |
| `token`, `config` | 0, none | last accepted `set_config` |
| `activated` | 0 | token of the last accepted `activate_config` |
| `running` | 0 | token of the config whose start time has passed |
| `props` | {`0x20`: 1} **`[D]`** | `clock.property` store |

**State machine (summary):**

```
power-on ──▶ UNCLAIMED ──claim──▶ CLAIMED ──(controller adds it: set_state 2)──▶ IN SESSION
                ▲                    │
                └──── release ───────┘
CLOCK (independent of the above):
  NO MASTER (state 0)
     │ announce_master(other)                     announce_master(us)
     ▼                                                   │
  SYNCING (state 2, c = exchanges left) ──10 answers──▶ LOCKED SLAVE (state 1) ──announce_master(us)──▶ MASTER (state 1, itself)
     ▲    new master / new rate (announce_master)       │                                                 │
     └───────────────────────────────────────────────────┴──────────── announce_master(other) ◀────────────┘
```

---

## 5. Requests and replies

### 5.1 Dispatch
1. Only handle requests (bit 7 of `msgclass` clear) whose `dst_port` is `0x64 + src_port`. The exceptions are the peer and broadcast traffic in §5.3 and §6.
2. **Ignore** requests for services not in the service list, and any opcode not listed here (no reply). Firmware-update opcodes are not known yet; ignoring them is the safe default.
3. **Owner-only requests** get `0x16` and no other effect when the device is owned by another MAC: `device.set_state`, `stream.get_rx_table`, `stream.get_rx_status`, `stream.get_tx_table`, `stream.activate_config`, `stream.set_config`, `clock.announce_master`, `clock.get_status`, `clock.set_master`.

### 5.2 Service 0: device

| Op | Request | Reply body | Effect |
| --- | --- | --- | --- |
| `06` presence (broadcast from each controller, 5 Hz) | controller record (ignore its content) | `u32 0`, `u32 assigned` (1 if the sender's MAC is `owner`, else 0), `u32 9`, `DigiGridD` **`[D]`** | answer every presence frame, to its sender |
| `05` claim | empty | `u32 0` if unowned (set `owner` = sender), else `u32 0x17` | |
| `02` list_services | empty | `00000000 07000000 0000 0100 0200 0400 0900 0a00 1000 0000` **`[D]`** | |
| `08` set_state | `u32 value` | `u32 0` | value 2 = in session; value 1 = probably identify (blink the identify LED; the controller sent 2 again after about 4 s; seen once, BM §10.3) |
| `0a` release | empty | `u32 0` | clear `owner` (BM §10.7) |

### 5.3 Service 10: discovery

| Op | Request | Reply / action |
| --- | --- | --- |
| `01` | `MAC[6]` (`ff:ff:ff:ff:ff:ff`) | reply `u32 0`, then broadcast a `discovery.ping` (§3.4) |
| `03` | empty | `u32 0`, `u32 0` |
| `02` ping, from any node (ports 10 → 10, not a reply) | empty | reply to the sender with `u32 0` (reply rule) |
| `02` reply to our ping | — | ignore |

### 5.4 Services 4, 9, 16 and the fixed clock replies (attach)

| Request | Reply body |
| --- | --- |
| `firmware.get_version` (svc 4, op `01`) | `00000000 010d0801 110f1000 0000 0100 0200 0d00 cdab 0200 0200 0d00 0000 00 16 "Oct 30 2021, 22:04:56\0"` **`[D]`**. Bytes 4–7 are `version_a` (1.13.8.1), 8–11 `version_b` (17.15.16.0), 12–29 nine u16 words (**words 3 and 7 = model number 13**), then `u8 0`, `u8 22`, the build string. |
| `sync.op04` (svc 9, op `04`) | `u32 0`, `u32 1` |
| `svc16.op30` (svc 16, op `30`) | `u32 0`, `u32 0`, `u16 1`, `u16 1` |
| `clock.op10` (svc 2, op `10`) | `u32 0` |
| `stream.get_caps` (svc 1, op `10`) | `00000000 00000000 0400 0400 0800 2000 0800 2000 1000 f001 02000000 4000 b004 0000 0400` then 4 rate entries `01000000 <rate u32> 0000 0400 0000 0400` for 44100, 48000, 88200, 96000 **`[D]`**. The 4/4 values are the I/O counts (ignored by the controller for hardware, but keep them consistent). |
| `clock.property` (svc 2, op `16`) | request `u32 id, u16 len, u16 flags, data`. Reply `u32 0, u32 id, u16 len, u16 flags, data`. Flags: 1 = read, 8 = write (store `data` under `id`). **`0x20` must read as u32 `1`** **`[D]`**: 0 makes the controller poll it about 780 times a second, and 2 shows "firmware error" (BM §6). Unknown id: reply with `len` 0. |

### 5.5 Service 2: clock
See §6. Op `20` set_master, `11` announce_master, `12` get_status.

### 5.6 Service 1: streams
See §7. Op `1e` set_config, `1c` activate_config, `14` get_rx_table, `18` get_tx_table, `17` get_rx_status.

---

## 6. Clock

### 6.1 `clock.get_status` (request `u32 1`) reply, 52-byte body

`u32 0, u32 rate, u32 state, u32 a, i32 b, u32 c, u32 0, MAC master[6], u8 class, u8 prio, u32 st, u16 0, u8 class, u8 prio, u32 event, u32 0`

| Situation | state | a | b | c | master / class / prio | st | event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| No master yet (power-on) | 0 | 0 | 0 | 0 | zeros / 1 / 2 **`[D]`** | `local_st` | 0 |
| Slave, syncing | **2** | 2 | 0 | **exchanges left** (10 … 1) | the announced master | `local_st` | 0 |
| Slave, locked (first reply after lock) | **1** | **2** | 0 | 0 | the announced master | **`master_st`** | 0 |
| Slave, locked | 1 | 0 | phase error in samples (the D reports −1/0/+1; 0 is acceptable) | 0 | the announced master | `master_st` | 0 |
| Master | 1 | 0 | 0 | 0 | **own MAC** / class / prio from the `announce_master` | `master_st` | `trans` state (0, 1, 2 or 5) |

`st` must be within a few samples of the master's own counter once locked (the D: ±5).

### 6.2 Slave: following a master
**`announce_master(other)`** (body `MAC[6], u8 class, u8 prio, u32 rate, u32 0`):
1. If you are master, stand down (§6.5).
2. Set `master` = (MAC, class, prio) and `rate` = the given rate. **The status reports the new rate at once.**
3. **If the master or the rate changed:** start a sync round (§6.3). If the master is new, ignore the old master's timebase and wait for the new master's beacons.
4. Reply `u32 0`.

**`set_master(other)`** (body `MAC[6], u8 class, u8 prio, u32 rate, u32 enable`):
- If it names the master you are already following at the same rate, reply `0x14`.
- Otherwise do steps 1–3 above and reply 0. The controller follows up with `announce_master`, whose class/priority is what gets reported.

**`sync.beacon` from the announced master:** take its `st` (offset 22) and rate (offset 38) to keep `master_st` disciplined, and note that the master is heard. **Ignore beacons from any other MAC.** A returning ex-master beacons for about 0.5 s before the controller demotes it (BM §10.9).

**Master disappears (no beacons):** do nothing. **Keep reporting locked and free-run at the last rate.** The controller fails over within about 2 s and sends `announce_master` (BM §10.9).

### 6.3 Slave: sync round (10 exchanges)
1. Set `sync_left` = 10 and `synced` = false. The status shows state 2 from now on.
2. Wait until at least one beacon from the master has been received.
3. Every **100 ms** **`[D]`**, send `sync.unicast` (§3.4) with `t1` = `local_st` now. The IOC sends all 10 back to back; both work.
4. On `sync.03` from the master (ports 9 → 9, op `03`, msgclass `09`, to us) with status 0, where `t1` equals the outstanding request's `t1` and hasn't been answered yet (the network can duplicate frames):
   `t4` = `local_st` now; `rtt` = (t4 − t1) − (t3 − t2); `master_st` at t4 = t3 + rtt / 2; `sync_left` −= 1.
5. When `sync_left` reaches 0: `synced` = true; the next status is "locked, first" (a = 2), then "locked".

The FPGA should timestamp `t1` and `t4` in hardware, and discipline its media clock (PLL) toward `master_st` using the beacons and, when routed, the `sample_time` of incoming audio packets. The protocol does not prescribe how; only the reported `st` and the audio timing are visible to the system.

### 6.4 Master mode (required: the controller promotes master candidates, BM §10.11–10.12)
**Becoming master:**
- `set_master(us)` while not master: reply **`0x27`**.
- **`announce_master(us)`**: become master, reply 0.
  1. **Keep the timebase:** `master_st` continues from the master you were locked to; if never locked, from `local_st`.
  2. Set `trans` = (0, 1), `sync_left` = 0, `synced` = true.
  3. **Start beacons immediately** (the D: within 10 ms of the announce).
  4. If the announced rate differs from the current rate, switch to it now.

**`set_master(us)` while master.** The reply depends on `trans`, not on the rate:

| `trans` state | Reply | Effect |
| --- | --- | --- |
| 0 (idle) | 0 | schedule a clock switch: `trans` = (2, `align_up(master_st + 11264, 512)`) **`[D]`**; when `master_st` reaches that value, `trans` = (1, 1) |
| 2 (switch pending) | 0 | none |
| 1 (switched) | **`0x14`** | none |
| 5 (activation pending) | 0 | schedule a switch, as for state 0 |

**A new rate takes effect on `announce_master(us, rate)`**, not on `set_master`. That is the D's behaviour **`[D]`**; the IOC instead schedules the rate switch with `set_master`.

**Beacon:** broadcast every **100 ms**, tagged (§3.1). Body, 12 × u32:

`st, 0, 0, 0, rate, 0, 0, running_token, 0, 1, trans_state, trans_value`

**Answering slaves:** on `sync.unicast` to us (ports 9 → 9, op `02`), reply at once with `sync.03`: `t1` echoed, `t2` = `master_st` on receipt, `t3` = `t2` + 1 (the D's value). **Answer each (slave MAC, t1) only once;** a duplicate within 0.5 s gets no reply.

**`activate_config`** while master: see §7.3. It also sets `trans` = (5, start sample); after the start, `trans` = (0, 1).

**Clock-only streams:** a master's config contains TX entries with **no channels** (and `stream_flags` 0) addressed to the software endpoints (drivers, server). For each one, send header-only `stream.audio` packets (34-byte header, §8) with the stream's `fpp` (16 or 32), at Fs/fpp packets per second. This is the datapath's job; the control logic hands it the list.

### 6.5 Standing down
`announce_master(other)` or `set_master(other)` while master: stop the beacons, stop answering `sync.unicast`, clear `trans`, then follow the new master (§6.2: a sync round starts).

### 6.6 Rate changes (controller-driven)
The controller changes the master's rate first, then sends every slave `announce_master(master, …, new rate)`. A slave **switches rate and re-syncs**. The controller then sends a new `set_config` with a new token; a `set_config` repeating the old token gets `0x25`. **Audio stops for about 1.5–2.7 s** during the change (BM §10.6–10.8). At 96 kHz the controller doubles `fpp` (e.g. 8 → 16), so the packet rate stays the same.

---

## 7. Streams (routing)

### 7.1 `stream.set_config` (op `1e`)
Request format: BM §5.2 (version, token, rate, clock master MAC, controller GUID, TX entries, RX entries).
- **If `token` equals the current `token`:** reply `u32 0x25`, `u32 version`. No other effect.
- **Otherwise:** store the config. **Do not change the rate** (it comes only from the clock commands). Reply:
  `u32 0, u32 version, u32 token, u16 n_tx, u16 n_rx`, then one u16 result per TX entry (0), then one per RX entry: **`0x0b` if its `stream_flags` = `0x0380`, else 0**. Pad with zeros to a 4-byte boundary, counted from the start of the body.
- **Slave:** no `activate_config` will come. The new config's streams start when the sender starts them (§7.4).
- Store the controller GUID for the table replies.

### 7.2 Tables
- **`get_tx_table` (op `18`)**, request `u16 first, u16 max`. Reply: `u32 0, u32 token, GUID[16], u32 1, u16 returned, u16 total`. Then per TX entry: `u16 index, MAC dst[6], u16 dst_stream_id, u16 fpp, u16 n, u16 0, u16 channel[n]`, padded to 4 bytes per entry.
- **`get_rx_table` (op `14`).** Same header. List only RX entries whose `stream_flags` ≠ `0x0380`, each as `u16 stream_id, MAC src[6], u16 fpp, u16 stream_flags, u16 n, u16 0, u16 stream_channel[n]` (the map's **stream** channels), padded to 4.
- **`get_rx_status` (op `17`)**, request `u16 0, u16 wanted, u32 1`. Reply: `u32 0, u32 running_token, u16 returned (= min(wanted, total)), u16 total` (the number of listed RX entries, and 0 while the running token differs from `token`). Then one 28-byte record per returned stream: `u32 index, u32 0 × 5, i32 offset`. The offset looks like an arrival-time offset; the D reports 5–10, and the reference reports 8.
- **The token reported by `get_rx_status` changes only when the new config has started** (BM §5.5).

### 7.3 `stream.activate_config` (op `1c`), sent to the master only
Request `u32 token, u16 0`.
- **If `token` equals `activated`:** reply `u32 0x25`. This includes token 0 at power-on.
- **Otherwise:** `activated` = token; start = `align_up(master_st + 11264, 512)` **`[D]`**; reply `u32 0, u32 start`. As master, announce it in the beacon (`trans` = (5, start)). Start the new config's TX streams exactly at `start`.

### 7.4 When a new routing starts (BM §10.5)
- **Sender (TX):** pick the start sample yourself. As master, use the `activate_config` start. As slave, use `align_up(master_st + 10240, 512)` from receipt of `set_config` (one observation); the D and the DSP server landed on the same 512-block. Stamp packets with the new token from that sample on.
- **Receiver (RX):** keep the old routing until the **first packet carrying the new token** arrives, and switch at that packet's `sample_time`. **Never schedule the RX switch from `set_config`:** the sender's start was one 512-block earlier than the estimate in 3 of 4 measurements. Switches are seamless (no gap).
- **Tokens are reused** when the routing returns to an earlier state. Don't treat a token as unique.
- **Running token:** becomes the new token at its start sample. Report it in `get_rx_status` and, as master, in the beacon.

### 7.5 Stream sizes
A stream carries at most `floor((1500 − 34) / (4 × fpp))` channels: 11 at fpp 32, 45 at fpp 8. The controller splits larger routes into several streams, and a stream's map can be non-contiguous (BM §10.4). Server stream channels are `0x0f00 + n`.

---

## 8. Interface to the audio datapath

For every running config the control logic provides:

| Item | Source |
| --- | --- |
| `rate`, and the timebase `master_st` (sample counter) | §6 |
| config **token** (goes in every audio packet header, offset 14) | §7 |
| **TX streams:** destination MAC, `dst_stream_id`, `fpp`, list of local channels in stream order, **start sample** | `set_config` + §7.4 |
| **RX streams:** source MAC, `stream_id`, `fpp`, map (stream channel → local channel); **switch on the first packet with the new token** | `set_config` + §7.4 |
| **Clock-only TX streams** (as master): destination, stream id, `fpp` | §6.4 |

Audio packet header (34 bytes, BM §5.1): `01 05 | 03 00 | 01 10 | 01 00 | 01 00 | 00 | 00 | 00 00 | u32 token | u32 0 | u32 0 | u32 sample_time | u16 fpp | u16 stream_id`, then samples as **float32 LE, planar** (all `fpp` samples of channel 0, then channel 1, …). Packets go out every `fpp` samples, and `sample_time` advances by `fpp` per packet.

---

## 9. Timers and rates

| Timer | Value |
| --- | --- |
| Presence replies | one per received presence frame (each controller sends 5 per second) |
| Sync exchange | 10 exchanges, one per 100 ms **`[D]`** |
| Master beacon | every 100 ms |
| Clock switch lead / activation lead (master) | 11264 samples at 48 kHz, aligned to 512 **`[D]`** |
| Slave TX start lead | 10240 samples at 48 kHz, aligned to 512 (one observation) |
| Duplicate sync request window | 0.5 s |
| Owner expiry | **none** (keep until `device.release` or power-on) |
| Master loss | no timer: keep locked, free-run, wait for `announce_master` |

---

## 10. Robustness rules
- Ignore unknown services, opcodes and replies (no reply, no state change).
- **Link loss without power loss:** keep the owner, config, token and timebase, and resume at once. The IOC resumed its streams and beacons before the controller did anything (BM §10.10).
- **Power-on:** be silent until the first controller presence frame, then answer it with `assigned = 0` (BM §10.1).
- **Duplicates:** answer a duplicated `sync.unicast` once; use a duplicated `sync.03` once.
- **Padding:** send zeros; ignore whatever arrives in received padding.
- **The controller's other polling** (`clock.get_status` and `stream.get_rx_status` at about 5 Hz each while in session) must always be answered; it is how the UI shows the device.

---

## 11. Values borrowed from the DiGiGrid D (replace before release)

| # | Item | Interim (D) value | Replace with |
| --- | --- | --- | --- |
| 1 | Firmware words 3 and 7 (model number) | 13 | **the bridge's registered model number (from Waves)** |
| 2 | Firmware `version_a` / `version_b` / words 0–2, 4–6, 8 / build string | 1.13.8.1 / 17.15.16.0 / … / `Oct 30 2021, 22:04:56` | the bridge's versions; **`version_b` byte 2 ≠ 0**, matching the build the device module expects |
| 3 | Model property | `0x20` = 1 | **the property id and value the bridge's module reads first** (from Waves) |
| 4 | Presence type name | `DigiGridD` | the bridge's product name (shown for an unknown model) |
| 5 | Service list | 0, 1, 2, 4, 9, 10, 16 | the services the bridge's module expects (is 16 required?) |
| 6 | `stream.get_caps` | 4 × 4 at 44.1–96 kHz, the D's other words | the bridge's real I/O counts and rates |
| 7 | Clock class / priority | 1 / 2 | from Waves, if the module expects different values |
| 8 | Leads (11264 / 10240) and sync pacing (100 ms) | the D's | confirm for the bridge's model; the IOC differs slightly |
| 9 | Rate change as master (via `announce_master`) | the D's behaviour | confirm for the bridge's model (the IOC uses `set_master`) |
| 10 | VLAN priority 7 on beacons and `sync.unicast` | the D's | keep unless Waves says otherwise |

Questions to ask Waves are in BM §10.4.

---

## 12. Verification

The reference model [tools/fake_d.py](tools/fake_d.py) implements this spec. It runs with the D values by default (4 × 4).

- **Byte-exact replay.** `python3 tools/fake_d.py --selftest <capture>` replays every request the real D received and compares the replies:
  - The D-as-slave capture: all replies match.
  - The D-as-master capture: all match except 3 status replies (event counter while an activation is pending; inconsistent on the real D).

  Feed the same captured requests to the FPGA (in simulation or on hardware) and compare its replies with `fake_d.py`'s for the same input.
- **Live:** `python3 tools/fake_d.py --iface <if> --state-file s.json -v` behaves as the bridge's control plane; the state file shows what §8 hands to the datapath. Tests that passed with it: claim and attach, slave sync (green "SOE"), routing and token switching, master failover and return (BM §10.12).
- **Test cases to run on the FPGA** (each captured with the switch mirroring the bridge's port):
  1. Power-on attach and add to session
  2. Slave sync, then routing to and from the bridge
  3. 48k → 96k → 48k
  4. Master switched to the bridge and back
  5. IOC unplugged (bridge promoted), then plugged back in
  6. Identify
  7. Remove from session and add again
  8. Bridge link pulled for 10 s

---

## 13. Open items (not blocking)
- What the remaining constant fields mean (presence flags, the caps words, the RX-status counters, status fields a and d).
- The exact sender start-time rule (§7.4).
- The firmware-update protocol (svc 4, other opcodes): unknown; currently ignored.
- What the clock-status event counter shows while an activation is pending (0 or 5).
- The upper u32 of `sync.03` timestamps (always 0 so far).
