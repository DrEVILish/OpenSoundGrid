# SoundGrid Protocol: Byte-Level Map

This map was reverse-engineered from network captures of real SoundGrid devices (the captures aren't in this repository). Every SoundGrid frame in the 21 original captures decodes with **zero unexplained bytes** using `tools/sg_decode.py`. That means every byte belongs to a named field. Some fields still have only a provisional name, and the confidence column marks those.

- `decoded_examples.md`: one real frame of each of the 65 message types, decoded field by field.
- `tools/sg_decode.py`: the decoder (`--summary` shows coverage, `--filter` and `--hex` show frames).
- `wireshark/soundgrid.lua`: a Wireshark dissector that uses the same rules.
- `tools/fake_d.py`: a control-plane emulator of a DiGiGrid D that runs as clock slave. It is checked byte for byte against the captures (§13), and live it syncs to the IOC and is claimed by the controller. **It encodes every rule in this map that a device needs, so treat it as the reference implementation for the FPGA.**
- [`FPGA_control_spec.md`](FPGA_control_spec.md): the control-plane specification for the bridge's FPGA, written from this map and `fake_d.py` (interim D identity, every borrowed value marked).
- `tools/fake_d16.py`: the same fake reporting 16 × 16 channels (it was still shown as 4 × 4, §5.6).
- `tools/scan_models.py`: steps the fake through firmware model numbers and records how the controller treats each (§10.4).
- `screenshots/`: the controller UI for each model number the scan made visible (`model13_D.png` etc.).
- Captures added later: the D-as-slave capture (port mirror of the real D as clock slave: attach, sync, routed audio, unplug; §10.2), the IOC-session capture (IOC added to a session, routed, identified, removed; §10.3), the IOC power-on capture (IOC from power-on; §10.4). All three also decode with zero unexplained bytes.

**Key results so far:**
- A slave syncs to the clock master with 10 `sync.unicast` → `sync.03` timestamp exchanges, reporting `clock_state` 2 (syncing), then 1 (locked) in the master's timebase (§10.2). Without this the UI shows the device as not synced; with it, green "SOE". It re-syncs whenever the controller sends `announce_master` (new rate or new master); if the master disappears it stays locked and free-runs until the controller fails over (§10.6–10.9).
- **The device model is the firmware reply's words 3 and 7** (13 = DiGiGrid D, 9 = IOC, 1–13 all registered, §10.4). It alone sets the manufacturer, model name, picture and I/O in the UI and the model-specific `clock.property` the controller reads; a device only syncs and appears after that property is answered correctly. The reported channel counts have no visible effect; the presence name is only used as the label for an unknown model.
- **A device whose model is a master candidate must be able to become master.** When the master fails, the controller retries `set_master`/`announce_master` on the candidate about 5 times a second forever; a slave-only device that refuses stalls the system (§10.11).
- **A new device needs a registered model number *and* a device module installed in the controller.** Model numbers this SoundGrid Studio (14.9) has no module for (16 and up) are rejected with an "incompatible device" dialog (§10.4).

## Conventions

- **Offsets are 0-based from the first byte after the EtherType** (the "SG payload"). Add 14 for the Ethernet frame offset, or 18 if the frame has an 802.1Q tag. The old `SG protocol.md` used 1-based offsets, so its byte *n* is offset *n−1* here.
- All multi-byte integers are **little-endian** unless a row says otherwise.
- Confidence: **H** means the meaning is proven by values that vary across captures (rates, counts, MACs, tokens, CRCs). **M** means the structure is certain and the meaning is a strong inference. **L** means the structure is certain and the meaning is unknown (only constants were observed).

---

## 1. Network and devices in the captures

The MAC addresses and host name below are placeholders, not the real ones. The Waves devices keep Waves' vendor prefix `00:1c:d1`.

| MAC | Role (from its own messages) |
| --- | --- |
| `02:00:00:00:00:01` | A Mac. Runs the SoundGrid **driver** ("SG driver", host `host.localdomain`, version `17.3.37.122`). In the D captures it also runs the controller apps (context IDs `0x7c58`, `0x7c59`, `0x7c5a`, `0x7c5b`). |
| `02:00:00:00:00:02` | The **controller** (context `0x8a36`) and its own "SG driver". |
| `00:1c:d1:00:00:01` | Waves hardware that names itself **"IOC "**. It is the clock master in most captures and sends clock-only streams. |
| `00:1c:d1:00:00:02` | Waves **"DigiGridD"** (DiGiGrid D). It has 4 in and 4 out, and its firmware is dated "Oct 30 2021, 22:04:56". |
| `02:00:00:00:00:04` | A SoundGrid **DSP server**, which receives the driver's playback streams. |
| `02:00:00:00:00:03` | Another "SG driver" host. |

- **EtherType `0x8908`** carries everything: control, clock and audio. There is no IP or UDP.
- When DiGiGrid D is clock master, it sends its `sync.beacon` inside an **802.1Q tag with priority 7, VLAN 0**.
- **No length field.** The message type determines the body length. Frames shorter than 60 bytes are padded on the wire. The DiGiGrid D does not zero its padding, so stale bytes can appear after the real body (for example `00 f0 01`). Frames captured on the sending Mac show their true, unpadded length.

---

## 2. Common header (22 bytes, every frame)

| Off | Len | Field | Values seen | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 0 | 2 | `proto_version` | `01 05` | SoundGrid protocol version (byte 0 major, byte 1 minor). | H |
| 2 | 2 | `context_id` (LE) | `0x8a36`, `0x7c58`–`0x7c5b`, `0x0000`, `0x0003`, `0x0006`, `0x0007` | Who owns the exchange. Controller requests carry that controller instance's 16-bit ID, and the reply echoes it. Unsolicited traffic uses small fixed values: `0` for sync beacons, `3` for audio and unicast sync, `6` for presence, `7` for discovery pings. | M |
| 4 | 2 | `service_version` | `01 05` (svc 0), `01 10` (svc 1), `01 11` (svc 2), `01 06` (svc 4), `01 07` (svc 6), `01 0b` (svc 7), `01 04` (svc 9 and bus), `01 02` (svc 10), `01 01` (svc 16) | Version of the service interface. It is constant per service across all devices. | H |
| 6 | 2 | `src_port` (LE) | see §3 | Service port of the sender. | H |
| 8 | 2 | `dst_port` (LE) | see §3 | Service port of the receiver. | H |
| 10 | 1 | `opcode` | see §3 | Command within the service. | H |
| 11 | 1 | `msgclass` | bit 7 = reply, bits 0–6 = interface code | The interface code is constant per service: svc0 `01`, svc1 `00`, svc2 `02`, svc4 `01`, svc6 `06`, svc7 `07`, svc9 `09`, svc10 `0a`, svc16 `0f`, bus `0b`. Bus messages always have bit 7 set. | H |
| 12 | 2 | `reserved_12` | always `00 00` | Reserved. | L |
| 14 | 4 | `cookie_a` (LE) | see below | Transaction or sequence ID. | H |
| 18 | 4 | `cookie_b` (LE) | see below | Second half of the cookie. | M |

**Cookie usage** (offsets 14–21):

| Traffic | `cookie_a` | `cookie_b` |
| --- | --- | --- |
| Controller commands (svc 0, 1, 2, 4, 6, 7, 9, 16) and their replies | `0x11223344` | `0x55667788`, i.e. bytes `44 33 22 11 88 77 66 55`. This is a fixed placeholder; requests are matched by order, not by ID. |
| `device.presence` broadcast | 32-bit sequence (+1 every 200 ms) | `0x65787430` (bytes `30 74 78 65`) |
| `device.presence.reply` | echoes the sequence | Waves hardware echoes `0x65787430`. Software drivers return their own small integer (0x19–0x28, or 1–3). |
| svc 10 discovery | small sequence (`0x01`, `0x02`, `0x15`…) | `0x55667788` |
| Message bus (port 0x70) | 16-bit sequence (`0x0b6b`, `0x013b`…) | 0 |
| Audio / clock-only data (`stream.audio`) | **config token** of the stream configuration | 0 |
| `sync.beacon` / `sync.unicast` / `sync.03` | 0 | 0 |

**Reply body convention:** almost every reply body starts with a `u32 status`, where 0 means OK. When the status is non-zero, nothing follows. Error codes seen: `0x12`, `0x14` (set_master already pending, so the controller then sends `announce_master`), `0x16` (device not ready / not owned), `0x17` (`device.op05` refused by DiGiGrid D), `0x25` (`set_config` / `activate_config` with the token that is already active, including token 0 at boot), `0x27` (`set_master` refused).

---

## 3. Services, ports and opcodes

Service *n* uses **port n on the controller side** and **port 0x64+n on the device side**. Requests go from port n to port 0x64+n, and replies come back from 0x64+n to n. Broadcast and peer traffic uses port n on both ends (`sync.beacon` 9→9, `discovery.ping` 10→10, audio 1→1, bus 0x70→0x70). `device.list_services` returns a device's service numbers: the driver supports {0, 1, 7, 9, 10} and DiGiGrid D supports {0, 1, 2, 4, 9, 10, 16}.

| Svc | Name | Opcode | Message (decoder name) | Direction | Rate | Purpose | Conf |
| ---: | --- | ---: | --- | --- | --- | --- | --- |
| 0 | device | 02 | `device.list_services` | ctrl→dev | at attach | List supported services | H |
| 0 | device | 05 | `device.claim` | ctrl→dev | at attach | **Claim the device for this controller.** The D's presence `assigned` flag flips 0→1 within 40 ms. Later claims return `0x17` (already claimed). | H |
| 0 | device | 06 | `device.presence` | ctrl→broadcast | 5 Hz | Controller presence beacon | H |
| 0 | device | 06 | `device.presence.reply` | dev→ctrl | 5 Hz | "I am here", device type name, and whether the device belongs to this controller | H |
| 0 | device | 08 | `device.set_state` | ctrl→dev | rare | Set state (value 2 seen) | L |
| 0 | device | 0a | `device.release` (op0a) | ctrl→dev | rare | Release ownership: the presence reply switches to `assigned 0` (§10.7) | H |
| 0 | device | 0b | `device.app_identity` | app↔app (loopback) | at app start | Controller apps on one host swap identities: the reply carries app name (`eMotion LV1`, `-SH1`…`-SH3`), host name, user and OS | H |
| 1 | stream | 00 | `stream.audio` | dev→dev | Fs/fpp | Audio and clock-only stream packets | H |
| 1 | stream | 10 | `stream.get_caps` | ctrl→dev | attach, 5 Hz while idle | Channel and rate capabilities | H |
| 1 | stream | 14 | `stream.get_rx_table` | ctrl→dev | after config | Read back the receive streams | H |
| 1 | stream | 17 | `stream.get_rx_status` | ctrl→dev | 5 Hz | Per-receive-stream health counters | H |
| 1 | stream | 18 | `stream.get_tx_table` | ctrl→dev | after config | Read back the transmit streams | H |
| 1 | stream | 1c | `stream.activate_config` | ctrl→dev | after config | Commit a config token on DiGiGrid D | M |
| 1 | stream | 1e | `stream.set_config` | ctrl→dev | on routing change | **Full routing/stream configuration** | H |
| 2 | clock | 10 | `clock.op10` | ctrl→dev | attach | Empty request with a status reply | L |
| 2 | clock | 11 | `clock.announce_master` | ctrl→dev | on clock change | Tell the device who the clock master is and the rate | H |
| 2 | clock | 12 | `clock.get_status` | ctrl→dev | ~2.5 Hz | Clock state, master, sample counter | H |
| 2 | clock | 16 | `clock.property` | ctrl→dev | rare | Get/set device property (register-style) | M |
| 2 | clock | 20 | `clock.set_master` | ctrl→dev | on clock change | Make the device master or slave at a given rate | H |
| 4 | firmware | 01 | `firmware.get_version` | ctrl→dev | attach | Firmware versions and build date | H |
| 6 | ioc | 11, 12 | `ioc.op11`, `ioc.op12` | ctrl→IOC | rare | Empty requests with a status reply | L |
| 7 | host | 10 | `host.get_info` | ctrl→driver | attach | Host name and driver version strings | H |
| 7 | host | 11 | `host.poll` | ctrl→driver | 5 Hz | Driver keepalive | H |
| 7 | host | 12 | `host.set_channels` | ctrl→driver | on mode change | Set driver input/output channel count | H |
| 9 | sync | 01 | `sync.beacon` | master→broadcast | 10 Hz | Clock master's sample counter | H |
| 9 | sync | 02 | `sync.unicast` | **slave→master** | 10 Hz × 10 after `announce_master` | Timestamp request: the slave's own sample counter | H |
| 9 | sync | 03 | `sync.03` (timestamp reply) | master→slave | one per request | Echoes the slave's timestamp and adds the master's receive and send times | H |
| 9 | sync | 04 | `sync.op04` | ctrl→dev | attach | Reply is a u32 (1 seen) | L |
| 0x70 | bus | 02, 03, 04 | `bus.msg02/03/04` | app↔app | event | GUID-addressed message bus with Protobuf payloads | H (framing) |
| 10 | discovery | 01 | `discovery.op01` | ctrl→dev | rare | Carries a MAC (`ff:ff:ff:ff:ff:ff`). Afterwards the device broadcasts `discovery.ping` | M |
| 10 | discovery | 02 | `discovery.ping` | dev→broadcast | rare | Every SoundGrid node answers with status 0 (`028a`) | M |
| 10 | discovery | 03 | `discovery.op03` | ctrl→dev | attach | Reply is status plus u32 0 | L |
| 16 | svc16 | 30 | `svc16.op30` | ctrl→D | attach | Reply is status, u32 0, u16 1, u16 1 | L |

---

## 4. Service 0: device and presence

### 4.1 `device.presence` (opcode 06, broadcast from controller, every 200 ms)
62 bytes, or 62 + 29×N when the peer list is not empty.

| Off | Len | Field | Example | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 0–21 | 22 | header | `01 05 06 00 01 05 00 00 64 00 06 01 00 00` seq `30 74 78 65` | ctx=6, port 0→0x64 | H |
| 22 | 4 | magic | `a4 b8 dc 79` | Constant in every presence record from every controller | H |
| 26 | 4 | node_word | `31 01 00 18` (Mac) / `58 bb 17 00` (controller) | A counter that tracks the sequence. On the Mac, the top byte is `0x18` and the low 24 bits equal the sequence. | M |
| 30 | 16 | controller GUID | | Controller identity. The Mac's apps use the same GUID with last byte `20`–`23`. | H |
| 46 | 4 | crc32 | `d5 5d 5c 38` | **CRC-32 (zlib) of `reverse(bytes 26–29)` followed by bytes 30–45**, stored LE. Checked on every presence frame in all captures. | H |
| 50 | 1 | flag_a | `01` | | L |
| 51 | 1 | flag_b | `01` | | L |
| 52 | 1 | flag_c | `00` | | L |
| 53 | 1 | flag_d | `01` | | L |
| 54 | 1 | field_e | `04` | | L |
| 55 | 2 | reserved | `00 00` | | L |
| 57 | 1 | peer_count | `00` / `01` | Number of 29-byte peer entries that follow | H |
| 58 | 29×N | peer[i] | | `u32 node_word`, `MAC[6]`, `GUID[16]`, `u8 a`, `u8 b`, `u8 c`. When the Mac controller ran alongside the controller, it listed the controller (`02:00:00:00:00:02`) here. | M |
| end−4 | 4 | session_tag | `39 bc 4b 9a` | Constant for one controller run and different between runs. Not a CRC of anything in the frame. | M |

### 4.2 `device.presence.reply` (opcode 06, reply from each device, port 0x64→0)

| Off | Len | Field | Example | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 14 | 8 | cookie | seq + responder value | see §2 | H |
| 22 | 4 | status | 0 | | H |
| 26 | 4 | assigned_to_sender | 0 / 1 | 1 when the device belongs to the controller that sent the beacon. In the D-and-IOC capture, DiGiGrid D answered 0 to the Mac controller's beacons and 1 to beacons with sequence `0x013a…`, which came from a controller whose beacons are not in the capture. | M |
| 30 | 4 | name_len | 9 | Byte length of the name | H |
| 34 | n | device_type_name | `SG driver`, `DigiGridD`, `IOC `, or a DSP server's model name | Device type string | H |

### 4.3 `device.presence.reply`, local relay form (port 0x64→0x64, 85 bytes, loopback only)
The Mac's local SoundGrid service sends one of these to each controller app on the same host for every node it knows.

| Off | Len | Field | Meaning | Conf |
| ---: | ---: | --- | --- | --- |
| 22 | 4 | status | 0 | H |
| 26 | 4 | relay_value | Changes per record (for example `0x0c68`) | L |
| 30 | 4 | reserved | 0 | L |
| 34 | 28 | presence record | `magic`, `node_word`, `GUID`, `crc32` with the same CRC rule as §4.1 | H |
| 62 | 16 | owner GUID | GUID of the local controller | M |
| 78 | 7 | flags | `03 01 ff 01 04 00 00` or `01 01 9f 01 04 00 00`, the same layout as presence offsets 50–56 | L |

### 4.4 Other service-0 messages

| Message | Request body | Reply body | Conf |
| --- | --- | --- | --- |
| `device.list_services` (02) | empty | `u32 status`, `u32 count`, `u16 service[count]`, then zero padding to a 4-byte boundary | H |
| `device.claim` (05) | empty | `u32 status`: 0 when it claims a free device, `0x17` when already claimed | H |
| `device.app_identity` (0b) | `GUID from[16]`, `GUID to[16]` | `u32 status`, `GUID a[16]`, `GUID b[16]`, then four `u8 len` + string fields: app name, host name, user name, OS name | H |
| `device.set_state` (08) | `u32 value` (2) | `u32 status` | L |
| `device.release` (0a) | empty | `u32 status`; the device is no longer owned (presence `assigned 0`) | H |

---

## 5. Service 1: streaming and routing

### 5.1 `stream.audio` (opcode 00): audio and clock-only packets

| Off | Len | Field | Example | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 0 | 2 | proto_version | `01 05` | | H |
| 2 | 2 | context_id | `03 00` | 3 = realtime | H |
| 4 | 2 | service_version | `01 10` | | H |
| 6 | 2 | src_port | `01 00` | | H |
| 8 | 2 | dst_port | `01 00` | | H |
| 10 | 1 | opcode | `00` | | H |
| 11 | 1 | msgclass | `00` | | H |
| 12 | 2 | reserved | `00 00` | | L |
| 14 | 4 | **config token** | `7b 81 07 aa` | The token from the `stream.set_config` that created this stream. It changes whenever the routing changes. | H |
| 18 | 4 | reserved | 0 | | L |
| 22 | 4 | reserved | 0 | Possibly the upper half of the timestamp. Always 0. | L |
| 26 | 4 | **sample_time** | `00 fe c8 ba` | Sample counter of the first frame in the packet. It advances by `frames_per_packet` each packet, at the clock master's timebase. | H |
| 30 | 2 | **frames_per_packet** | `20 00` | 32 for audio. Clock-only streams use 8, 16 or 32. Packets per second = Fs ÷ fpp (1500/s at 48 kHz, fpp 32). | H |
| 32 | 2 | **stream_id** | `01 00` | The `dst_stream_id` from the sender's TX entry. The 16-channel playback used stream 1 (11 ch) plus stream 2 (5 ch). | H |
| 34 | 4·fpp·nch | **samples** | | **float32 LE, planar**: all `fpp` samples of channel 0, then channel 1, and so on. nch = (len−34)/(4·fpp). Verified with the 1 kHz sine capture: each channel is continuous within and across packets. | H |

Payload size by channel count at fpp 32: 0 ch = 34 bytes, so the frame is padded to 60 (the old "data_frame_60"). Then 1 ch = 162, 2 = 290, 3 = 418, 4 = 546, 5 = 674, 6 = 802, 7 = 930, 8 = 1058 (the old "1072 frame"), 9 = 1186, 10 = 1314, 11 = 1442 (the maximum that fits the 1500-byte MTU at fpp 32). A stream with more channels than fit is split into several streams. **The limit depends on fpp:** at fpp 8 (the DSP server's streams) up to 45 channels fit, and the server sent 16 channels to a fake device in one stream.

A **clock-only stream** (channel_count 0) carries no samples. It is the timing reference a device receives from the clock master, sent at Fs/fpp packets per second (3000/s for fpp 16, 6000/s for fpp 8).

### 5.2 `stream.set_config` (opcode 1e): the routing table
The controller sends one full configuration per device: the device's clock, every stream it transmits, and every stream it receives.

| Off | Len | Field | Example | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 22 | 4 | config_version | 1 | | M |
| 26 | 4 | **config_token** | `8c 43 d6 17` | A random 32-bit ID for this configuration. It reappears in audio packets, tables, status replies and `sync.beacon`. A rate-only config uses 0. | H |
| 30 | 4 | **sample_rate** | `80 bb 00 00` = 48000 | | H |
| 34 | 6 | **clock_master_mac** | `00:1c:d1:00:00:01` | Which node is the clock master | H |
| 40 | 2 | clock_master_port | 0 | | L |
| 42 | 16 | controller GUID | | | H |
| 58 | 4 | param_1 | 1 | | L |
| 62 | 2 | **tx_stream_count** | 1 | | H |
| 64 | 2 | **rx_stream_count** | 2 | | H |
| 66 | … | TX entries, then RX entries | | | |

**TX entry** (20 + 2·n bytes, padded to 4):

| Rel | Len | Field | Meaning | Conf |
| ---: | ---: | --- | --- | --- |
| 0 | 6 | dst_mac | Receiver of this stream | H |
| 6 | 2 | index | Local TX stream index (0, 1, …) | H |
| 8 | 2 | dst_stream_id | Stream ID placed in the audio packets (offset 32) | H |
| 10 | 2 | flags | 0 or `0x0004`. The bit toggles between successive configs. | L |
| 12 | 2 | frames_per_packet | 32, or 16/8 for clock-only streams | H |
| 14 | 2 | stream_flags | `0x0380` when the stream carries channels, 0 when clock-only | M |
| 16 | 2 | reserved | 0 | L |
| 18 | 2 | channel_count | n | H |
| 20 | 2·n | local_channel[] | Device channels sent, in stream order | H |

**RX entry** (16 + 4·n bytes):

| Rel | Len | Field | Meaning | Conf |
| ---: | ---: | --- | --- | --- |
| 0 | 6 | src_mac | Sender of the stream | H |
| 6 | 2 | stream_id | The sender's `dst_stream_id` | H |
| 8 | 2 | flags | `0x0004` / `0x000c` (bit 3 toggles between configs), `0x0024` seen | L |
| 10 | 2 | frames_per_packet | | H |
| 12 | 2 | stream_flags | `0x0380` with channels from a host driver, `0x0020` from the DSP server, 0 when clock-only | M |
| 14 | 2 | channel_count | n | H |
| 16 | 4·n | map[] | `u16 stream_channel`, `u16 local_channel` pairs. DiGiGrid D loopback gives (0,0)(1,1)(2,2)(3,3). The DSP server sent stream channels `0x0f06` and `0x0f07` mapped to local 0 and 1. | M |

### 5.3 `stream.set_config` reply

| Off | Len | Field | Conf |
| ---: | ---: | --- | --- |
| 22 | 4 | status | H |
| 26 | 4 | config_version (1) | M |
| 30 | 4 | config_token (echo) | H |
| 34 | 2 | tx_stream_count | H |
| 36 | 2 | rx_stream_count | H |
| 38 | 2·(tx+rx) | per-stream result (`u16`). This is why replies are 40/42/44 bytes long. TX entries are always 0. **DiGiGrid D returns `0x000b` for RX entries with `stream_flags 0x0380` (host driver streams; audio still flows) and 0 for others (`0x0020`, from the DSP server).** So `0x0b` is not an error; RX entries that get it are also left out of `get_rx_table` and `get_rx_status`. The Mac driver returns 0. | M |

### 5.4 `stream.get_rx_table` (14) and `stream.get_tx_table` (18)
Request: `u16 first_entry` (0), `u16 max_entries` (4). The device answers with the configuration it actually applied. DiGiGrid D lists every TX stream, but only the RX streams whose set_config result was 0 (§5.3). For those, its RX entry lists the map's **stream** channels (`0x0f00`–`0x0f03` for the DSP server), not the local ones.

Reply header: `u32 status`, `u32 config_token`, `GUID controller[16]`, `u32 table_version (1)`, `u16 entries_returned`, `u16 entries_total`.

| RX entry | Len | | TX entry | Len |
| --- | ---: | --- | --- | ---: |
| stream_id | 2 | | index | 2 |
| src_mac | 6 | | dst_mac | 6 |
| frames_per_packet | 2 | | dst_stream_id | 2 |
| stream_flags (`0x0380`/0) | 2 | | frames_per_packet | 2 |
| channel_count n | 2 | | channel_count n | 2 |
| reserved | 2 | | reserved | 2 |
| local_channel[n] | 2·n | | local_channel[n] | 2·n |
| pad to 4 | | | pad to 4 | |

### 5.5 `stream.get_rx_status` (17)
Request: `u16 reserved (0)`, `u16 records_requested`, `u32 param (1)`.

Reply: `u32 status`, `u32 config_token`, `u16 records_returned`, `u16 records_total`, then one 28-byte record per returned stream. On DiGiGrid D, `config_token` is the config that is **running**: after `set_config` + `activate_config` it keeps reporting the old token until the `activation_sample_time` is reached (about 0.24 s later). As a slave the D gets no `activate_config`, and the token changes when its own start time is reached (§10.2). `records_returned = min(records_requested, records_total)`. On the D, `records_total` is the number of RX streams listed in `get_rx_table`: 0 in the earlier captures, 1 for the DSP server stream in the D-as-slave capture (offset 5–10). Per-record layout:

| Rel | Len | Field | Values seen | Conf |
| ---: | ---: | --- | --- | --- |
| 0 | 4 | stream_index | 0, 1, 2 | H |
| 4 | 4 | counter_a | 0, or 1 right after a reconfig | L |
| 8 | 4 | counter_b | 0 | L |
| 12 | 4 | counter_c | 0, or 1 right after a reconfig | L |
| 16 | 4 | counter_d | 0 | L |
| 20 | 4 | counter_e | 0 | L |
| 24 | 4 | offset (i32) | 0, −17, −33 | L (looks like an arrival-time offset) |

### 5.6 `stream.get_caps` (10) reply

| Off | Len | Driver value | DiGiGrid D value | Conf |
| ---: | ---: | --- | --- | --- |
| 22 | 4 | status | status | H |
| 26 | 4 | 0 | 0 | L |
| 30 | 2+2 | 32, 32 | 4, 4 | M (D: physical I/O) |
| 34 | 2+2 | 8, 32 | 8, 32 | L |
| 38 | 2+2 | 8, 32 | 8, 32 | L |
| 42 | 2+2 | 40, 1024 | 16, 496 | L |
| 46 | 4 | 1 | 2 | L |
| 50 | 2+2 | 32, 512 | 64, 1200 | L |
| 54 | 2 | 0 | 0 | L |
| 56 | 2 | **rate_count** (4) | 4 | H |
| 58 | 16×n | rate entries: `u32 kind` (2 for driver, 1 for D), **`u32 rate_hz`**, `u16 in_first`, **`u16 in_channels`**, `u16 out_first`, **`u16 out_channels`** | | H |

The driver's in/out channel counts follow `host.set_channels`: they read 128/64/48/32/16/8/4 in the channel-modes capture.

**The controller ignores these counts for hardware.** A fake `DigiGridD` that reported 16 × 16 at every rate (`tools/fake_d16.py`) was still shown and patched as 4 × 4, with no errors. The I/O layout comes from the controller's built-in model for the device type. **The presence name does not choose the model or, for a known model, the label** (but it is the label for an unknown model, see below). A fake that announced itself as `TestBridge` (with the D's MAC prefix, services, caps and firmware reply) was claimed, synced and handled as a DiGiGrid D, and, like fakes named `DigiGridTest`, `AlphaBeta` and `Bridge16` (all with model number 13), was labelled **"D"** in the UI, as the real D is. **The device label comes from the model, not from the name.** (A "Test" label seen once came from the control software, not from the device.) No visible effect of the presence name has been found. The controller also claimed it as soon as it saw the presence reply, before asking for firmware. Remaining candidates for the type ID: the firmware reply (version bytes and the nine ID words), the service list, or the MAC address. Being tested with `fake_d.py --firmware-ids`. (H)

### 5.7 `stream.activate_config` (1c)
Request: `u32 config_token`, `u16 reserved`. Reply: `u32 status`, then **`u32 activation_sample_time`**. This is proven: the first packet of every stream in the new config, from the D *and* from the Mac, carries exactly this `sample_time`. The D chooses a point about 0.24 s ahead, aligned to 512 samples: across 10 activations in two captures, the result always equals `align_up(now + 11264, 512)` at 48 kHz (lead 11294–11745 samples). Sent only to the **clock master** (the D in 10.1). Slaves never get it; see §10.2 for how they pick their start time. (H)

---

## 6. Service 2: clock (seen with DiGiGrid D and IOC)

A **clock ID** is 8 bytes: `MAC[6]`, `u8 class`, `u8 priority`. Values seen: `…7f46 01 02` (D announcing itself), `…01 03`, `…01 04` (in `set_master`).

| Message | Body | Conf |
| --- | --- | --- |
| `clock.set_master` (20) | `clock_id[8]`, **`u32 rate_hz`**, `u32 enable (1)`. Reply `u32 status`: 0 OK, `0x14` busy, `0x27` refused. | H |
| `clock.announce_master` (11) | `clock_id[8]`, **`u32 rate_hz`**, `u32 0`. Reply status. | H |
| `clock.op10` (10) | empty. Reply status. | L |
| `clock.get_status` (12) | request `u32 1` | H |
| `clock.property` (16) | `u32 property_id`, `u16 data_len`, `u16 access_flags` (1 = read, 8 = write, 6 = ?), `data[len]`. The reply is `u32 status` followed by the same structure with data filled in. Property `0x20` on D, and `0x0b`/`0x0c` on IOC: `0x0b` carries 20-byte blocks whose last byte is a running checksum, which looks like codec or preamp register access. | M |

**`clock.property` seen so far:**

| Device | Property | Request | Reply | Meaning |
| --- | --- | --- | --- | --- |
| D | `0x20` | read (flags 1, len 0) | u32 `1` | the D family's model property (read at attach). Looks like a firmware state: 1 = normal; 0 = the controller polls it ~780×/s; 2 = "firmware error" in the UI (§10.11) |
| IOC | `0x0c` | read (flags 1, len 0) | u32 `2` | the IOC's model property |
| IOC | `0x0c` | write (flags 8) `01000000` | `01 00 02 03` | a setting (reply is not an echo) |
| IOC | `0x0c` | flags 6, 16 bytes | echoed | a configuration block written and read back |
| IOC | `0x0c` | flags 4, 16 bytes, polled 17×/s | 296 bytes, changing | meters or status (device panel open) |
| IOC | `0x0b` | flags 1, 20-byte blocks | mostly echoed | register access: `03`, register number, value pairs, last byte a checksum |

Flags: 1 = read, 8 = write, 4 = read block, 6 = write block and read back. Each model's first property (the one that must be answered before the device is added) is listed in §10.4.

`clock.get_status` reply (52-byte body):

| Off | Len | Field | D as master | D as slave to IOC, locked (the D-as-slave capture) | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 22 | 4 | status | 0 | 0 | H |
| 26 | 4 | **rate_hz** | 48000 | 48000 | H |
| 30 | 4 | **clock_state** | 1 | 1 | H: **0 = no master yet, 2 = syncing, 1 = locked** (as master or slave). The IOC's `2` in the D-and-IOC capture was "syncing". |
| 34 | 4 | field_a | 0 | 0 (2 while syncing, and in the first locked reply) | L |
| 38 | 4 | field_b (i32) | 0 | −1 / 0 / +1 | M (phase error in samples, it seems) |
| 42 | 4 | field_c | 0 | 0; while syncing, the **sync exchanges left** (10, 8, 6, 4, 2) | H |
| 46 | 4 | field_d | 0 | 0 | L |
| 50 | 8 | **master clock_id** | `001cd1000002 01 02` | `001cd1000001 01 03` (as given by `announce_master`); all zero with `01 02` before any master | H |
| 58 | 4 | **sample_time** | `0x be83e102` | the master's counter (±5) once locked; the D's own counter before | H (the same timebase as audio and the beacon) |
| 62 | 2 | reserved | 0 | 0 | L |
| 64 | 2 | class/priority echo | `01 02` | `01 03` | M |
| 66 | 4 | event_counter | 0–5 | 1–5 | L |
| 70 | 4 | reserved | 0 | 0 | L |

---

## 7. Service 7: host / driver

| Message | Body | Conf |
| --- | --- | --- |
| `host.get_info` (10) | request empty. Reply: `u32 status`, `u32 string_count (2)`, then for each string `u8 len` + chars: `"host.localdomain"`, `"17.3.37.122"`, then `u32 0` | H |
| `host.poll` (11) | request empty. Reply: `u32 status`, `u32 host_state (0)` | H (keepalive), L (state) |
| `host.set_channels` (12) | **`u32 input_channels`, `u32 output_channels`** (128, 64, 48, 32, 16, 8 or 4). Reply status. The old doc called these "mode value A / mirror B"; they are really two separate counts that happened to be equal. | H |

---

## 8. Service 9: sync and the message bus

### 8.1 `sync.beacon` (opcode 01, broadcast from the clock master, 10 Hz, 48-byte body)

| Off | Len | Field | Example | Meaning | Conf |
| ---: | ---: | --- | --- | --- | --- |
| 0–21 | 22 | header | ctx 0, ports 9→9, cookie 0 | | H |
| 22 | 4 | **sample_time** | `48 0e 94 c3` | Master sample counter. It steps by exactly Fs/10 (4800 at 48 kHz) between beacons. | H |
| 26 | 4 | sample_time_hi | 0 | | L |
| 30 | 4 | field_8 | 0 or `0xfc000000` | | L |
| 34 | 4 | reserved | 0 | | L |
| 38 | 4 | **sample_rate** | 48000 / 44100 / 88200 / 96000 | It follows rate changes live. | H |
| 42 | 8 | reserved | 0 | | L |
| 50 | 4 | **config_token** | `ef e1 70 01` | The active stream-configuration token (0 while unconfigured) | H |
| 54 | 4 | reserved | 0 | | L |
| 58 | 4 | field_36 | 1 | | L |
| 62 | 4 | transition_state | 0 normal, 1 during a change, 2 clock/rate change scheduled, **5 config activation scheduled** (§10.4) | | H |
| 66 | 4 | transition_value | 1, or a future sample_time when state = 2 | Probably the scheduled switch point | M |

### 8.2 Other service-9 messages
- `sync.unicast` (02), **from a slave to its clock master** (D → IOC in the D-as-slave capture, IOC → D in the D-and-IOC capture), ctx 3, sent in an 802.1Q tag with priority 7 like the beacon. Body (20 bytes): `u32 t1` (the slave's own sample counter), `u32 0`, 12 bytes of 0. **H**
- `sync.03` (03), the master's answer, ctx 3, msgclass `0x09` (no reply bit). Body: `u32 status`, `u32 t1` (echo), `u32 0`, `u32 t2` (master counter on receive), `u32 0`, `u32 t3` (master counter on send, about 20 samples after t2), `u32 0`. A PTP-style exchange: the slave gets offset and round-trip time from t1–t4. **H**
- In the D-and-IOC capture the D, as master, never answered the IOC's requests (the Mac replied `0x12`). **M**
- `sync.op04` (04): empty request. The reply is `u32 status`, `u32 1`. **L**

### 8.3 Message bus (port 0x70 ↔ 0x70, opcodes 02/03/04, msgclass `0x8b`)
Controller applications use this to talk to each other. It runs over Ethernet on loopback (Mac↔Mac) and between hosts (Mac↔controller).

| Off | Len | Field | Meaning | Conf |
| ---: | ---: | --- | --- | --- |
| 14 | 4 | cookie_a | Message sequence | H |
| 22 | 4 | status | 0 | M |
| 26 | 2 | reserved | 0 | L |
| 28 | 16 | src GUID | Sending app | H |
| 44 | 16 | dst GUID | Receiving app | H |
| 60 | 1 | reserved | 0 | L |
| 61 | 16 | origin GUID | | M |
| 77 | 2 | **length** | Bytes that follow (4 stamp + 4 flags + Protobuf) | H |
| 79 | 4 | stamp (BE) | Increases over time (`d3593603`, `d3596514`…) | M |
| 83 | 4 | flags | `00 01 00 01` | L |
| 87 | length−8 | **Protobuf** | for example `08 00 10 99 8c 86 ff 06 1a 10 <GUID> 20 02 2a 14 08 02 12 10 a0…a0 00 1c d1 00 00 02`, which contains device MACs and GUIDs. The decoder prints these as field=value. | H (encoding), L (schema) |

---

## 9. Service 10: discovery, and the small services

| Message | Body | Conf |
| --- | --- | --- |
| `discovery.op01` (01) | request `MAC[6]` = `ff:ff:ff:ff:ff:ff`. Reply status. Right afterwards the target broadcasts `discovery.ping`. | M |
| `discovery.ping` (02) | broadcast, empty body (ctx 7, or 3 from DiGiGrid D). Every node replies with status 0. | M |
| `discovery.op03` (03) | empty. Reply `u32 status`, `u32 0`. | L |
| `firmware.get_version` (svc 4, 01) | Reply: `u32 status`, `u8[4] version_a` (1.13.8.1), `u8[4] version_b` (17.15.16.0), nine `u16` words (`0`, `1`, `2`, `13`, `0xabcd`, `2`, `2`, `13`, `0`); **words 3 and 7 are the model number** (13 = DiGiGrid D, 9 = IOC; table in §10.4), `u8 0`, `u8 len (22)`, `"Oct 30 2021, 22:04:56\0"`. The IOC's build string is longer and the reply is padded to 4 bytes. The UI shows `version_b` as the firmware version (17.15 → "1.17.15") | H (structure, model number), L (other words) |
| `svc16.op30` (svc 16, 30) | Reply: `u32 status`, `u32 0`, `u16 1`, `u16 1` | L |
| `ioc.op11` / `ioc.op12` (svc 6) | empty request with a status reply (`0x16` the first time) | L |

---

## 10. How a session comes up (from the captures)

1. The controller broadcasts `device.presence` at 5 Hz. Every node answers with `device.presence.reply`, giving its type name and whether it belongs to this controller.
2. Attach: `device.claim` + `device.list_services`, then `stream.get_caps`, `host.get_info` (driver) or `firmware.get_version` / `clock.op10` / `svc16.op30` (DiGiGrid D), then `sync.op04` and `discovery.op03`. These repeat (seen at 200 ms intervals) while the controller attaches.
3. Clock: `clock.set_master` / `clock.announce_master` set the master and rate on the hardware. The master then sends `sync.beacon` at 10 Hz (VLAN priority 7 from DiGiGrid D) and clock-only streams to each slave.
4. Driver only: `host.set_channels` sets its channel count, and `stream.get_caps` then reports the new counts.
5. `stream.set_config` sends the full routing table with a new random token. On DiGiGrid D, `stream.activate_config` follows. The controller reads the result back with `get_rx_table` / `get_tx_table`.
6. Audio flows as `stream.audio` packets that carry the token, a sample counter and a stream ID.
7. Steady state: `host.poll` + `stream.get_rx_status` (driver) or `clock.get_status` + `stream.get_rx_status` (hardware), at about 2.5–5 Hz.

Every routing change in the routing-change captures (one channel added at a time) is a new `stream.set_config` with a new token and one more channel. A new stream is opened when a stream would exceed 11 channels.


### 10.1 DiGiGrid D lifecycle (from the D power-up capture)

1. **At power-up the D is completely silent.** It sends no SoundGrid frames, no ARP, no LLDP and no IP. Its first frame ever is a `device.presence.reply` (`assigned = 0`) to the first controller beacon it hears.
2. +0.55 s: `device.claim` returns 0, and `list_services` returns {0,1,2,4,9,10,16}. From +0.59 s, its presence replies say `assigned = 1`.
3. +0.75 s: attach queries, repeated at 200 ms intervals: `get_caps`, `clock.op10`, `firmware.get_version`, `sync.op04`, `discovery.op03`, `svc16.op30`. Then `clock.property 0x20` (read, returns 1).
4. `device.set_state 2` (+3.1 s, and again at +23.2 s when LV1 added the device).
5. Polling starts (`clock.get_status` + `stream.get_rx_status`). The controller sends `discovery.op01(ff:ff:ff:ff:ff:ff)`, and the D answers by broadcasting `discovery.ping` (ctx 3). A second `device.claim` returns `0x17`.
6. Making the D master: `clock.set_master(D, class 1, prio 4, 48000)` returns `0x27` the first time, then 0, 0, then `0x14`, and each `0x14` is followed by `announce_master(D, 1, 2, 48000)`. **The D starts its 10 Hz `sync.beacon` 55 ms after the first `announce_master`.** Its sample counter is already running (≈284 s worth of samples), so the counter does not start at 0 at boot.
7. A rate-only `stream.set_config` (token 0, no streams) and an `activate_config` are both refused with `0x25`. This seems harmless.
8. First real config (token `0x27825c06`): the D sends a **clock-only stream (fpp 16, stream 0)** to the host. That stream keeps running with that same token through all later configs.
9. 4 channels D→host (token `0x88f5885d`): TX0 is 4 ch, fpp 32, stream 0, and TX1 is clock-only, fpp 32, stream 1. Next, 4 channels host→D (token `0xc836fbfa`) adds one RX entry with a (0,0)…(3,3) map. Every switch happens exactly at the `activation_sample_time`.
10. At +63.7 s the controller sent the first config (token `0x27825c06`) again, which tore down the 4-channel streams. Only the fpp-16 clock stream remained until the end of the capture.

### 10.2 DiGiGrid D as clock slave (from the D-as-slave capture, IOC is master)

1. Attach is the same as in 10.1, then `set_state 2`, `discovery.op01`, and a second claim (`0x17`).
2. `clock.announce_master(IOC, class 1, prio 3, 48000)`. From the next `clock.get_status` reply, the D reports **`clock_state 2`, `field_a 2`, `field_c 10`**: it is syncing, and `sample_time` is still its own counter.
3. Starting 0.26 s later, the D does **10 `sync.unicast` → `sync.03` exchanges at 10 Hz** with the IOC. `field_c` counts down the exchanges left (10, 8, 6, 4, 2).
4. After the 10th: **`clock_state 1`** (locked; the first reply still has `field_a 2`, then 0), `field_b` jitters between −1, 0 and +1, and `sample_time` is now **the master's counter** (within ±5 samples of the IOC's beacon). No more exchanges follow.
5. `set_config` arrives with no `activate_config` (only the clock master gets one). The D, the DSP server and the IOC start the new streams at the same sample, `align_up(master_now + 10240, 512)` from when `set_config` arrived (one observation: lead 10444).
6. RX streams with `stream_flags 0x0020` (from the DSP server) get set_config result 0, are listed by `get_rx_table` (the entry lists the map's stream channels, `0x0f00`–`0x0f03`), and get a `get_rx_status` record (`offset` 5–10). RX streams with `stream_flags 0x0380` (from a host driver, in 10.1) get result `0x0b` and are listed in neither.

### 10.3 IOC added to a session, routed, identified, removed (the IOC-session capture)

The IOC was already claimed by the controller, so the capture has no claim, `list_services` or firmware request. It is clock master throughout.

| Time | Event | Messages |
| ---: | --- | --- |
| 6.9 s | Added to the session | `device.set_state 2` |
| 13.2 s | | `ioc.op11` (empty, OK), then `discovery.op01` → the IOC broadcasts `discovery.ping` |
| 14.0 s | Routing | `set_config` (6 TX, 1 RX), then **`activate_config` to the IOC, because it is the clock master** |
| 19.8–42.1 s | Device panel open? | `clock.property 0x0c` read (`flags 0x0004`, `len 0x10`) polled at **17 Hz**. Every reply has different data: 10 changing u32 values, which look like meters or status, not a setting |
| 44.4 s | **Identify, probably** | `device.set_state 1` |
| 48.3 s | Identify ends, probably | `device.set_state 2`, 3.96 s later |
| 53.3 s | Removed from the session | `discovery.op01`, then a `set_config` that restores the config from before it was added (token `ff6f04a9`, **controller GUID `11111111…11`**, 3 clock-only TX streams to the controller, the DSP server and the other host), plus its `activate_config`. There is no `op0a` and no release. The IOC stays the clock master and keeps sending clock-only streams |

Other details:
- **Streams over 11 channels are split.** The IOC sent 22 channels to the controller as stream 0 (local channels 0–10) and stream 1 (11–21), each 11 channels at fpp 32 with `stream_flags 0x0380`, plus a clock-only stream 3. To the DSP server it sent one 10-channel stream at fpp 8 with `stream_flags 0`.
- `set_config` reply results are padded to a 4-byte boundary, and the IOC's pad bytes are stale (`d1 01`).
- `set_state` values seen: 2 = in session (and after identify), 1 = identify (probably).

### 10.4 IOC from power-on (the IOC power-on capture), and how devices identify themselves

Like the D, the IOC is silent until it hears a presence beacon (first reply at 49.97 s, `assigned 0`). The controller claims it 0.2 s later. Attach is the D's set plus **`ioc.op10`** (service 6, empty, OK), then `clock.property 0x0c`/`0x0b`, `ioc.op11`, `discovery.op01` and a second claim (`0x17`). The controller makes it master: `announce_master(IOC, 1, 2)` and the **first beacon goes out 1 ms later** (untagged, unlike the D's), then `set_master(IOC, 1, 4)` → 0, 0, `0x14`.

**Identity compared** (D from the D power-up capture):

| Field | DiGiGrid D | IOC |
| --- | --- | --- |
| Presence name | `DigiGridD` | `IOC ` |
| Services | 0, 1, 2, 4, 9, 10, 16 | 0, 1, 2, 4, **6**, 9, 10, 16 |
| Caps I/O (offset 30) | 4 × 4 | **64 × 64** |
| Caps words b, c, d | 8/32, 8/32, 16/496 | 4/512, 4/512, 8/1024 |
| Caps per rate (44.1–96k) | 4 in / 4 out | 64 in / 64 out |
| Firmware version_a | 1.13.**8**.1 | 1.13.**6**.1 |
| Firmware version_b | 17.15.16.0 | 17.28.26.0 |
| Firmware ID words | 0, **1**, 2, **13**, 0xabcd, 2, 2, **13**, **0** | 0, **26**, 2, **9**, 0xabcd, 2, 2, **9**, **1** |
| → model number (words 3, 7) | **13** | **9** |
| Build string | `Oct 30 2021, 22:04:56` | `Oct 28 2021, 01:18:07 (bs-linux15)`, reply padded to 4 bytes |

**The firmware ID words select the model.** A fake with the D's name, services and caps but the IOC's nine ID words (`fake_d.py --firmware-ids 0,26,2,9,0xabcd,2,2,9,1`) was treated as an IOC as soon as the controller read its firmware reply. It stopped reading the D's `clock.property 0x20` and instead read the IOC's properties `0x0c` and `0x0b` (the same 20-byte `0x0b` block it sends the real IOC). The fake did not implement `0x0b`, so the controller re-sent it about 15 times a second, never moved on to `set_state`, and **the device never appeared in the UI**. A device only shows up after its model-specific attach succeeds. It did *not* send `ioc.op10`, so the service list still decides which services are used. **The model number is the repeated word (words 3 and 7): 13 = DiGiGrid D, 9 = IOC.** Changing only those two words from 13 to 9 (`--firmware-ids 0,1,2,9,0xabcd,2,2,9,0`, everything else the D's) was enough for the controller to treat the fake as an IOC. Words 1 and 8 (1 → 26, 0 → 1) are not needed for this. Whether word 3 and word 7 differ in meaning (e.g. product and board) is untested. (H)

**Scan of model numbers 1–13** (`tools/scan_models.py`; the fake D with only words 3 and 7 changed, 20 s each). Every value was claimed and had its firmware read, and each model triggers its own `clock.property` read right after the firmware reply:

| Model | Shown in the UI as | First property read | Then | Result with the fake |
| ---: | --- | --- | --- | --- |
| 1 | **DiGiCo SD IO 32CH** (manufacturer DiGiCo) | `0x0e` | | added (`set_state`), red, `INT (48k)`, never clocked |
| 2 | **DiGiCo SD IO 64CH** (DiGiCo) | `0x0e` | | same |
| 3 | **MGB** (DiGiGrid) | `0x04` | | same |
| 6 | **MGO** (DiGiGrid) | `0x04` | | same |
| 4 | **DLI** ("SGP MODE") | `0x06`, re-read 5–7× | | same |
| 5 | **DLS** ("SGP MODE") | `0x06` | | same |
| 10 | **DMI** | `0x1e`, re-read 18× | | same |
| 7 | (never shown) | `0x08` | 20-byte block `0x07` | stuck on the block, never added |
| 8 | (never shown) | `0x0a` | 20-byte block `0x09`, re-sent 22× | stuck, never added |
| 9 | IOC (never shown) | `0x0c` | 20-byte block `0x0b`, re-sent 20× | stuck, never added |
| 11 | **Q** | `0x20` | | added, synced (green **"SOE (48k)"**), configured |
| 12 | **M** | `0x20` | | same |
| 13 | **D** | `0x20` | | same: the real DiGiGrid D |
| 14 | **DiGiCo** (manufacturer DiGiCo, model "DiGiCo") | `0x3e` | | added, never clocked |
| 15 | (never shown) | `0x08` | 20-byte block `0x07`, re-sent 45× | stuck like model 7 |
| 16, 17 | **"incompatible device: MGB"** dialog (a name the fake never sent) | `0x04` | | added, never clocked: known MGB-family models, but this controller has no compatible module |
| 18–30 | **"incompatible device: DigiGridD"** dialog: the fake's own presence name | **none** | | added, never clocked. No model-specific request at all: unregistered numbers handled generically, or models without a property (26 was not added within the 10 s window, probably just slower) |

**From 16 on, the controller reports the device as incompatible instead of showing it** (SoundGrid Studio 14.9.0.566): *"One or more of your devices is incompatible. Incompatible devices were found: <name>. Please install the device modules compatible with version 14.9.0.566 Build R 278927 and update the device(s) firmware."* So the controller maps each model number to an installed **device module**:
- 16 and 17: `<name>` = **"MGB"** (`screenshots/model16_17_incompatible_MGB.png`). The controller knows these models (MGB family) but has no compatible module.
- 18 and up: `<name>` = **"DigiGridD"**, the device's own presence name (`screenshots/model18plus_incompatible_presence_name.png`). These model numbers are unknown, so **the presence name is the fallback label for an unknown model.** **A new device needs both a registered model number and a device module installed in the controller.**

**Answering the model property makes a borrowed model work.** With `fake_d.py --firmware-ids 0,1,2,2,0xabcd,2,2,2,0 --prop-default 1` (model 2, DiGiCo SD IO 64CH, answering property `0x0e` with u32 1 in the same format as the D's `0x20`), the controller added the fake, announced the IOC as master **with priority 0** (the D gets 3, so the announced class/priority depends on the model), ran the 10 sync exchanges, and configured it. So `0x0e` = 1 is sufficient for model 2. The UI then shows it as "DiGiCo SD IO 64CH-1", green, with the clock label **"DIG (48k Hz)"** (DiGiCo models say DIG where DiGiGrid models say SOE; `screenshots/model02_fake_synced_DIG.png`). The firmware dialog offered an update from 1.17.15 to App 1.17.31; To match it, the fake must report `version_b` **17.31.16.0** (`fake_d.py --fw-version 17.31.16.0`): with **17.31.0.0** the controller only re-reads the firmware version, about 5 times a second, never proceeds, and **the device never appears in the UI** (reproduced on two fresh MACs). So the third byte of `version_b` must not be 0. The UI shows only the first two bytes. (H)

**Patching a 64 × 64 device** (`patch_session.log`: the model-2 fake, 13 configs in 2 minutes while patching in the UI). Every patch arrived as a new `stream.set_config` (no `activate_config`; the IOC master was not in these streams). Server → device: up to all 64 channels, **split at 45 channels per stream** (fpp 8: the most that fits the MTU), so 64 channels = stream 0 with 45 + stream 1 with 19. When channels are removed, the remaining ones are repacked, so a stream's map can be non-contiguous (e.g. local 0–20 and 39–62). The server's stream channel for local channel *n* was always `0x0f00 + 15 + n`. Device → server: one TX stream (`dst_stream_id` 1, fpp 8) with the patched local channels in order (20, then 24).

**The controller reads the model property only the first time it sees a MAC:** re-presenting models 14–16 on the same MACs gave no property reads at all. (Every row above is from a first contact.) So all of 1–17 are registered models (from 18 on the controller asks for no model property), and the model number alone sets the manufacturer, model name, picture and I/O shown in the UI. The first property read groups them into families. **"SOE" (green) is the UI's "synced over Ethernet"**; models whose property the fake could not answer stayed red on internal clock, because the controller never made them clock slaves. The UI's "Firmware version 1.17.15" is `1.` + the first two bytes of `version_b` (17.15.16.0); it is compared with the controller's bundled firmware (App 1.17.31). The fake answers unknown properties with no data, which is why the other models stall at that step. `device.op0a` arrived about 10 s after `set_state` for models 5, 10, 11, 12 and 13 (meaning not yet confirmed).

**Beacon `transition_state 5` announces a config start.** After `activate_config` (answer `0x00189a00`), the master's beacon carries `transition_state 5`, `transition_value 0x00189a00` while still showing the *old* token, and its streams start at exactly that sample. The D as master did the same (the D-and-IOC capture, value `0xbe821e00`). `transition_state 2` is a clock or rate change scheduled at `transition_value`; 1 is during the change. So a slave can take its start time from the master's beacon whenever the master is in the config; §10.2 (no `5` seen) is the case where it is not.

### 10.5 When a new routing starts, measured (the start-time capture)

The 64 × 64 fake ran with a header-only capture of its traffic while the routing was changed 4 times (IOC → fake audio, fpp 8). Compared with the first audio packet of each new token:

| Token | `set_config` + 10240, aligned to 512 | First packet | Difference |
| --- | --- | --- | --- |
| e66eab9b | 0x808c5e00 | 0x808c5c00 | −512 |
| e45d89ba | 0x80955e00 | 0x80955e00 | 0 |
| 9e512a55 | 0x809ed400 | 0x809ed200 | −512 |
| e45d89ba (reused) | 0x80a99800 | 0x80a99600 | −512 |

- **Every switch is seamless:** the old token's last packet ends exactly where the new token's first packet starts (gap 0), always on a 512-sample boundary.
- The sender picks the start about 9,900–10,500 samples after it received its own `set_config`. The controller sends each device its copy at slightly different times, so **a receiver cannot predict the start exactly** (the estimate was right 1 time in 4, otherwise one 512-block late).
- **So a receiver should switch when the first packet with the new token arrives** (use that packet's `sample_time`), and keep using the old routing until then. A sender picks its own start (`align_up(now + 10240, 512)` matches the D) and stamps packets with the new token from there.
- **Tokens are reused:** returning to an earlier routing brought back its token (`e45d89ba`). A token is not a unique ID.

### 10.6 Rate changes, master reboot, slave reboot (the rate-change capture, mirror on the IOC's port)

| Time | Event | On the wire |
| ---: | --- | --- |
| 4.8 s | Session reset | IOC gets the standalone config (GUID `1111…`), as in §10.3 |
| 12–14 s | Session reloaded | `set_state 2` to all devices, routing `set_config` + `activate_config` to the IOC |
| 19.2 s | **48k → 96k** | `set_master(IOC, 96000)` → beacon `transition_state 2` (scheduled, value = switch sample) → `1` → beacons report 96000 → `set_config` with a new token at 96 kHz (a rate-only `set_config` with the old token got `0x25`) + `activate_config` → **all audio stops for 1.7 s** |
| 25.1 s | **96k → 48k** | Same sequence, 1.4 s of silence; the old 48k token is reused |
| 27.5–66 s | **IOC (master) gone** | No presence replies for 23 s, no beacons, no audio |
| 66.0 s | IOC back | Claimed and attached from scratch, made master again. **Its sample counter restarted near 0** (`0x0017680c`). Routing resent with the same token, activated |
| 80.2 s | **D reboot** | The D re-attaches and runs the 10 `sync.unicast`/`sync.03` exchanges; its own counter was ~10 s old (`t1 = 0x00078b09`) |

- No slave exchanges were seen at the rate changes in this capture, but §10.7 shows that a clock slave **does** re-run them after every rate change; the D was probably not a clock slave here.
- **At 96 kHz, fpp doubles** (16 instead of 8 on the DSP server route), so the packet rate stays the same.
- **A rate change is a full routing restart:** new token, new `set_config`, about 1.5 s of silence.
- **After a master reboot, its sample counter starts again from about 0.** Slaves must accept a large jump in the master's time.
- The controller keeps polling devices it got stuck with: 2,754 `firmware.get_version` requests to three offline fakes that had reported firmware 17.31.0.0.
- Not visible here: what a *slave* reports while the master is gone (its replies to the controller were not mirrored).

### 10.7 Rate changes and master changes (the master-change capture, IOC's port mirrored)

Only traffic involving the IOC, plus broadcasts, is in this capture (the D's replies to the controller are missing). Events: 48k → 96k (7.1 s), 96k → 48k (13.2 s), master moved to the D (20.3 s), IOC released and re-claimed (21.5 s, 29.2 s), master moved back to the IOC (35.3 s).

- **A clock slave re-runs the 10 sync exchanges after every rate change:** the D started a round at 7.93 s and at 14.03 s, about 0.3 s after the beacons changed rate.
- **A master change triggers a new round too:** when the D became master the IOC (now slave) synced to the D (20.45 s, and again after its re-claim at 29.34 s); when the IOC became master again, the D synced to it (35.43 s).
- **Pacing varies:** the D sends one exchange per 100 ms; the IOC sends all 10 back to back within a few ms, and its status stayed `clock_state 1` (it never reported 2). So the 1 s "syncing" phase is the D's behaviour, not a requirement.
- **A master answers `sync.03` immediately:** the D as master answered with `t3 − t2` = 1 sample. Its `t2` equalled the IOC's `t1` exactly, because both were already on the same timebase: a master change keeps the existing timebase.
- **`device.op0a` = release:** right after `op0a` the IOC's presence reply switched to `assigned 0`; it was later claimed again (`assigned 1`).
- The D's beacons as master appear without a VLAN tag here, unlike in the D power-up capture (priority 7). The mirror may strip tags.

### 10.8 The D as slave through rate and master changes (the second rate-change capture, D and IOC ports mirrored)

With both ports mirrored, frames between the D and the IOC appear twice; counts below are de-duplicated.

- **Rate change (IOC master):** the controller first changes the master (`set_master(IOC, 96000)`; IOC beacons go to `transition_state 2`, `1`, then rate 96000). Then it sends the **slave** `announce_master(IOC, 1, 3, 96000)`. The D's next status already reports **rate 96000, `clock_state 2`, `field_c` 10**, and it runs the 10 exchanges (`field_c` counting down). Then `clock_state 1` with `field_a` 2 once, then 0. A `set_config` with the old token is refused (`0x25`); the new configs follow. Audio stops for 2.7 s. 96k → 48k is identical.
- **So every slave re-sync is triggered by `clock.announce_master`** (a new rate or a new master).
- **Master moved to the D:** the D answered the first `set_master(D)` with `0x27`, then `announce_master(D, 1, 2)` made it master; **its beacons started 50 ms later** and the IOC synced to it. As master the D received `activate_config` (answered, and announced with beacon `transition_state 5`), reported itself as master in its status, and started **clock-only streams to the software endpoints** (the controller's driver, the other host). The IOC stopped sending beacons while it was not master.
- **Master moved back:** `set_master(IOC)` to the D got 0, then `0x14`, then `announce_master(IOC, 1, 3)`; the D re-synced to the IOC.
- Still not observed: a slave whose master disappears (cable pulled) rather than being switched.

### 10.9 The master disappears (the master-unplugged capture, D and IOC ports mirrored)

The IOC (master, D synced to it) was unplugged and plugged back in.

| Time | Event |
| ---: | --- |
| 9.70 s | IOC unplugged (last beacon and presence reply) |
| 9.7–11.7 s | **The D keeps reporting `clock_state 1` locked to the IOC, unchanged**, free-running at the last rate |
| 11.68 s | **After 2 s the controller fails over:** `set_master(D)` → `0x27`, then `announce_master(D, 1, 2)`; **the D's beacons start 10 ms later and continue the same timebase** (a synced slave's counter already equals the master's) |
| 12.9 s | Routing resent with a new token + `activate_config` to the D; audio silent for 1.2–3.4 s |
| 25.70 s | IOC plugged back in: **it beacons on its own for 0.5 s** (still believing it is master); its free-running counter was only **5 samples** off the D's after 16 s |
| 25.75 s | The controller claims the IOC and announces the D as master to it; the IOC stops beaconing and syncs to the D. **The D stays master** (no switch back) |

- **A slave does not detect master loss:** it keeps reporting locked and free-runs; the controller fails over within about 2 s by promoting another device with `announce_master`.
- **Follow only the master the controller announced:** a returning ex-master beacons for about 0.5 s before it is told otherwise.
- A slave-only device that the controller tries to promote must refuse `set_master`/`announce_master` (`0x27`); the real D also answered the first `set_master` with `0x27`, then accepted `announce_master`. What the controller does when every candidate refuses is unknown.

### 10.10 The master disappears and no other device can be master (the master-gone capture)

Only the IOC (master) and software drivers (`SG driver`, which have no clock service) were in the system; the IOC's cable was pulled for about 24 s.

- **The controller sent no clock commands during the outage** (no `set_master`, no failover attempt) and **all audio stopped**, including the software driver's stream to the server: everything runs off the master's clock.
- **On reconnect the IOC resumed beacons and all its streams by itself,** on the same config and token, before the controller did anything. Its sample counter was exactly where it would have been (it kept counting).
- The controller then re-attached it: `claim` → `0x17` (**it kept its owner through the cable pull**), the attach queries, `announce_master(IOC)`, and the routing again with the same token → `0x25` (already active), `activate_config` → `0x25`.
- **So the controller only promotes devices that can be master** (it must judge this by model or services), and **a device that loses its link (without losing power) keeps its owner, config, token and timebase** and resumes immediately.

### 10.11 A master candidate that refuses (`fake_refuse.log`)

The fake (D model, slave-only) was synced to the IOC, then the IOC was unplugged. From 1 s after the beacons stopped, **the controller sent `set_master(fake)` + `announce_master(fake)` about 5 times a second for as long as the fake ran (171 of each in 34 s), all refused with `0x27`.** It never gave up, never tried another device, and apparently did not switch back to the IOC when it returned (the fake briefly heard its beacons again at about 15 s).

**So a device whose model the controller treats as master-capable must be able to become master; refusing can stall the whole system after a master failure.** A slave-only bridge needs either a model the controller does not treat as a master candidate, or at least a minimal master mode (free-run on its own clock, send beacons, answer `sync.03`, accept `activate_config`). **Model 2 (DiGiCo SD IO 64CH) is a master candidate too** (`testA.log`): 1 s after the IOC's beacons stopped, the controller sent it `set_master` + `announce_master(fake, 1, 0, …, 1)` (priority 0, last field 1 where the D gets 0) about 5 times a second, 79 refused in 15 s, and again did not switch back to the returning IOC. **`0x20` = 0 does not make a device slave-only** (`testC1.log`, `fake_d.py --prop 0x20=0`): the fake was added, synced and routed, but from the moment it was added the controller read `0x20` about **780 times a second** (14,502 reads in 23 s; with 1 it reads it a few times), so `0x20` looks like a ready/status flag the controller waits on. It was still a master candidate (56 refused promotions), and the controller even sent a routing config naming the refusing fake as clock master. In the UI the `0x20` = 0 device looked normal. **With `0x20` = 2 the controller reported a firmware error** for the device (it was added but never clocked or routed). So `0x20` is most likely a **firmware state** (1 = application running normally; 2 perhaps bootloader/update mode), not a clock capability. A device without the clock service whose model property *is* answered (`--services 0,1,4,9,10,16 --answer-property`) still never appears in the UI (`testB2.log`). **Conclusion: on a borrowed master-capable model a device cannot opt out of being master; a bridge needs at least a minimal master mode.** **The stall outlasts the refusing device:** after the fake was stopped, the controller still did not return to the IOC. **A device that does not list the clock service is not usable either:** the controller drops `clock.op10` from the attach but still reads the model property (`clock.property 0x20`, service 2); unanswered, the device never appears in the UI (`testB.log`).

### 10.12 Failover to a master-capable fake (`fake_master.log`)

The fake (D model) with master mode, synced to the IOC; the IOC was unplugged and later plugged back in:

| Time | Event |
| --- | --- |
| 14:33:56 | fake locked to the IOC as slave |
| 14:34:04 | IOC unplugged; the fake free-runs |
| 14:34:05 | the controller promotes the fake (`set_master` → `0x27`, `announce_master` → master); beacons start on the same timebase; clock switch scheduled |
| 14:34:06 | routing config naming the fake as clock master, `activate_config` answered with a 512-aligned start, announced in the beacon |
| 14:34:20 | another routing change, activated |
| 14:34:32 | the IOC is back and syncs to the fake as a slave (its `sync.unicast` requests answered at once) |

No refused promotions and no stalled controller: **a device with this master behaviour gets through a master failure.** Each request reached the fake twice through the mirrored switch port; a master should answer each `(slave, t1)` request once.

**Correction:** earlier versions of this map read `clock_state 2` as "locked to network". It means "syncing". `1` is locked, both for a master and for a synced slave.

What a device on the network has to do, in order (all of it is implemented in `tools/fake_d.py`):

1. Answer `device.presence` (with `assigned` = 1 for the owner), `claim` (0 the first time, `0x17` after that), and the attach queries (the D's recorded replies are reused as they are).
2. **As slave** (§10.2): on `announce_master`, do the 10 `sync.unicast`/`sync.03` exchanges with the master. Report `clock_state 2` with `field_c` = exchanges left, then `clock_state 1`, and from then on report the master's sample counter. Keep it on track from the master's 10 Hz beacon.
3. **As master** (§10.1, required because master candidates cannot refuse, §10.11). Implemented in `fake_d.py` and checked against the D power-up capture (all `set_master`/`announce_master` replies and 200/203 status replies match):
   - `set_master(us)` → `0x27` until `announce_master(us)`; that makes the device master and **beacons start at once (10 Hz, VLAN priority 7) on the timebase it was locked to**.
   - Then `set_master(us)` depends on the transition state: idle (0) → schedule a clock switch, `transition_state 2`, value `align_up(now + 11264, 512)`, answer 0; pending (2) → 0; switched (1) → `0x14`. **A new rate takes effect on `announce_master`**, not `set_master`. (The IOC differs: its `set_master` schedules the rate switch.)
   - Status: `clock_state 1`, itself as master (class/priority from the announce), event counter = transition state.
   - Answer slaves' `sync.unicast` at once with `sync.03` (`t2` = now, `t3` = `t2` + 1).
   - On `activate_config`, answer `align_up(now + 11264, 512)`, set beacon `transition_state 5` with that value, switch exactly there, then state 0. Send clock-only streams to the software endpoints the config lists (TX entries with no channels).
   - `announce_master(other)` → stop beaconing and sync to the new master.
4. `set_config`: store the routing, report per-RX results (`0x0b` for `0x0380` streams), and switch the `get_rx_status` token when the start time is reached.

Live check: with the controller and the IOC as master, the fake was claimed, synced (round trip 12 samples), and polled with `clock_state 1`, like the real D.

---

## 11. Corrections to the earlier `SG protocol.md`

| Old claim | What the bytes show |
| --- | --- |
| Header prefix "control family / command group / subgroup" | These are the protocol version, context ID, service version, src/dst port, opcode and message class (§2). |
| `13-22 = 00 00 44 33 22 11 88 77 66 55` "reserved" | `reserved_12` (2 bytes) plus the transaction cookie `0x11223344` / `0x55667788`, which is a fixed placeholder. |
| `ctrl_mode_set` "mode value A / mirror B" | `host.set_channels`: `u32 input_channels`, `u32 output_channels`. |
| `ctrl_rate_set_2002` bytes 23–28 "target MAC", 29–30 "subtype" | `clock_id`: MAC of the **master** (not necessarily the target), then class and priority bytes. |
| `ctrl_rate_set_1102` "companion rate set" | `clock.announce_master`, which has the same clock-ID layout. |
| `ctrl_status_1700 state_word_a/b` | `u16 reserved`, `u16 records_requested`, `u32 1` (§5.5). |
| `stream_token` in 1780 bytes 27–30 | The config token from `stream.set_config`. |
| data header bytes 13–18 "stream token block" | Bytes 14–17 hold the config token, and bytes 18–25 are zero. |
| data bytes 31–34 "subframe selector 20 00 01 00" | `u16 frames_per_packet` (0x20 = 32) and `u16 stream_id`. |
| "1456 + 688 pair", "1072 transition frames" | These are simply 11-, 5- and 8-channel streams (payload = 34 + 128·nch). |
| `data_frame_60` "timing frame, step +0x00200000" | A clock-only stream (0 channels, padded to 60 bytes). The old offsets 24–27 straddled the zero word and the real `sample_time` at offset 26, which is why a step of 0x20 showed up as `0x00200000`. |
| `app_keepalive_57 / 76` | `device.presence.reply` / `device.presence`. The 4 bytes that change every packet are a CRC-32 (§4.1). |
| `host_broadcast_84`, `vlan_broadcast_88` | `sync.beacon` from the clock master (IOC, or DiGiGrid D in a priority-7 tag). |
| ctrl_caps 1080 | `stream.get_caps` reply, including the per-rate channel table (§5.6). |

---

## 12. What is still unknown

- The meaning of several constant fields (all marked **L**): presence flags a–e, the caps words, the RX-status counters, `clock.get_status` fields a and d, `stream_flags 0x0380`, and the TX/RX `flags` bit that toggles between configs (probably a double-buffer or generation bit).
- How `session_tag` (end of presence) and `relay_value` are generated.
- The Protobuf schema of the message bus. The framing and encoding are known, but the field names are not.
- Opcodes seen only with constant or empty bodies: `device.set_state`, `clock.op10`, `sync.op04`, `discovery.op01/op03`, `ioc.op11/12`, `svc16.op30`. Captures of attaching/detaching a device and of switching ownership between controllers would help name these.
- RX map stream channels from the DSP server are `0x0fNN`: a constant high byte `0x0f` and the server channel in the low byte (`0x0f06`/`0x0f07`, and `0x0f0f`–`0x0f1e` for a 16-channel route). What `0x0f` means is unknown.

- The exact rule a sender uses for its start time (§10.5 shows it is about 9,900–10,500 samples after it receives `set_config`, on a 512 boundary). Receivers do not need it: they switch on the first packet with the new token.
- How the controller decides which devices are master candidates (model? service list?). It retries a refusing candidate forever (§10.11) and simply waits when there is none (§10.10). A slave re-runs the exchanges whenever the controller sends `announce_master` (new rate or new master, §10.7–10.8) and after its own reboot (§10.6); it does not react to the master disappearing (§10.9). The upper words of the `sync.03` timestamps (always 0 so far).
- **The model-specific properties.** Each model's first `clock.property` (D family `0x20` = 1; MGB/MGO `0x04`; DLI/DLS `0x06`; SD IO `0x0e`; DMI `0x1e`; IOC-type `0x0c` + 20-byte block `0x0b`, §10.4) and what values make the controller proceed. Only `0x20` (D) and `0x0b`/`0x0c` (IOC) have been seen from real hardware.
- Model numbers above 13, and what the controller does with an unregistered one (the bridge's case until Waves registers it): `scan_models.py --first 14 --last 40`.
- `device.set_state 1` as identify (seen once, §10.3). Why the controller released the scanned models (`device.release`, about 10 s after `set_state`). Whether words 3 and 7 of the firmware reply differ in meaning.

Suggested captures to close these: several routing changes with a slave whose master is not in the config; unplug the clock master; change only the latency/buffer setting; one fixed routing change at 44.1 vs 48 kHz; a real MGB/MGO (the closest products to a bridge) from power-on.

---

## 13. Tools

```bash
python3 tools/sg_decode.py capture.pcapng --summary
```

```bash
python3 tools/sg_decode.py capture.pcapng --skip-audio --hex --max 50
```

```bash
python3 tools/sg_decode.py capture.pcapng --filter 'set_config|set_channels'
```

```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -X lua_script:wireshark/soundgrid.lua -r capture.pcapng -Y 'soundgrid && soundgrid.opcode != 0'
```

Fake DiGiGrid D (clock slave, control plane only). `--state-file` writes the routing, token and stream start time as JSON for the audio side:

```bash
python3 tools/fake_d.py --iface en13 --state-file d.json -v
```

Replay a capture and compare every reply with the real D's. The D-as-slave capture matches 223/223 `clock.get_status` and 223/223 `get_rx_status` replies, and every other reply. On the D power-up capture (D as master) only the clock-master replies differ, by design:

```bash
python3 tools/fake_d.py --selftest capture.pcapng
```

Present the fake as another model or name (§10.4), or with other channel counts (§5.6):

```bash
python3 tools/fake_d.py --iface en13 --firmware-ids 0,1,2,9,0xabcd,2,2,9,0 --mac 00:1c:d1:00:00:0e --state-file fw9.json -v
```

```bash
python3 tools/fake_d16.py --iface en13 -v
```

Step through model numbers (default 1–13, 20 s each; summary in `scan_models.log`):

```bash
python3 tools/scan_models.py --iface en13
```

To use the dissector in the Wireshark GUI, copy `wireshark/soundgrid.lua` into the Personal Lua Plugins folder (Wireshark → About → Folders) and reload Lua plugins (⇧⌘L).
