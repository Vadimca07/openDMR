# openDMR

<p align="center">
  <img src="https://raw.githubusercontent.com/github/explore/main/topics/cpp/cpp.png" alt="C++ Logo" width="80" height="80" />
</p>

<p align="center">
  <b>openDMR</b> — A cross-platform C++ Digital Mobile Radio (DMR) master/server for repeater linking, talkgroup routing, authentication, APRS, and SMS.
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/C%2B%2B-17-blue.svg" alt="C++17"></a>
  <a href="#"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
  <a href="https://github.com/Rikku2000/openDMR/"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platforms"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Educational-green.svg" alt="License"></a>
  <a href="https://github.com/Rikku2000/openDMR/graphs/contributors"><img src="https://img.shields.io/github/contributors/openDMR/openDMR.svg?color=blueviolet" alt="Contributors"></a>
</p>

---

## 🧭 Overview

**openDMR** is a lightweight, cross-platform DMR master server that:
- Links repeaters and routes digital voice/data traffic.
- Authenticates nodes using SHA-256 challenge/response.
- Handles talkgroups, parrot playback, and optional APRS/SMS.
- Logs traffic and events to console or SQLite3 database.

---

## ✨ Features

- **UDP repeater protocol support** (`DMRD`, `RPTL`, `RPTK`, `RPTC`, `RPTPING`, etc.)
- **SHA-256 authentication** and per-node authorization
- **Dynamic talkgroup routing** and scanner group (`TG 777`)
- **Parrot echo test** (`TG 9990`)
- **Optional modules:** APRS, DMR-SMS, and SQLite3 logging
- **Cross-platform:** Linux & Windows
- **Compact core:** minimal dependencies, single-binary deployment

---

## ⚙️ Build & Install

### Linux

```bash
g++ -O2 -std=c++17 server.cpp -o dmr -lpthread
./dmr
```

With SQLite + APRS:

```bash
g++ -O2 -std=c++17 server.cpp -DUSE_SQLITE3 -DHAVE_APRS -lsqlite3 -lpthread -o dmr
```

### Windows (MinGW)

```bash
g++ -O2 -std=c++17 server.cpp -lws2_32 -o dmr.exe
dmr.exe
```

---

## 🧩 Configuration

openDMR includes a minimal built-in INI parser.

```ini
[Server]
Port=62031
Password=changeme
Debug=1

[Auth]
Enabled=1
File=auth.txt
ReloadSecs=300
UnknownDefault=0
```

### Defaults

| Parameter | Default | Description |
|------------|----------|-------------|
| UDP Port | 62031 | Main DMR network port |
| Parrot TG | 9990 | Echo test |
| APRS TG | 900999 | Heard report |
| Scanner TG | 777 | Monitor group |
| Unsubscribe TG | 4000 | Removes TG subscriptions |

---

## 🧠 Architecture

```
┌────────────────────┐
│   DMR Repeaters    │
└────────┬───────────┘
         │ UDP
┌────────▼───────────┐
│   openDMR Core     │
│ - Packet Parser    │
│ - Node Registry    │
│ - Talkgroups       │
│ - Logging          │
└────────┬───────────┘
         │
 ┌───────┴────────┐
 │ APRS / SMS / DB│
 └────────────────┘
```

- Event-driven UDP loop
- Worker threads for timing, parrot playback, APRS/SMS tasks
- Uses non-blocking I/O and simple linked structures for routing

---

## 📡 DMR Protocol Summary

| Type | Magic | Description |
|------|--------|-------------|
| `DMRD` | Voice/Data | Main traffic frame (55 bytes) |
| `RPTL` / `RPTACK` | Login | Initial handshake |
| `RPTK` | Auth | Challenge/response |
| `RPTC` / `RPTO` | Config | Apply static TGs |
| `RPTPING` / `MSTPONG` | Keepalive | Node heartbeat |
| `RPTCL` | Logout | Node disconnect |
| `/STAT` | Local Command | Dumps runtime info |

### Talkgroups

| TG | Function |
|----|-----------|
| `4000` | Unsubscribe all |
| `777` | Scanner |
| `9990` | Parrot (echo) |
| `900999` | APRS heard trigger |

---

## 🧮 Core Components

| Component | Purpose |
|------------|----------|
| `node` | Represents connected repeater |
| `slot` | TDMA slot abstraction |
| `talkgroup` | Linked list of subscribers |
| `memfile` | Memory buffer (parrot, SMS) |
| `config_file` | Lightweight INI parser |

---

## 🔐 Authentication

- SHA-256 challenge/response (`salt + password`)
- Node passwords in `auth.txt`
- `UnknownDefault` controls unknown node policy

---

## 📚 API Overview (from `server.h`)

| Function | Description |
|-----------|--------------|
| `init_process()` | Initialize runtime |
| `open_udp(port)` | Create and bind UDP socket |
| `make_sha256_hash()` | Compute auth hash |
| `auth_load_initial()` | Load auth file |
| `aprs_send_heard()` | APRS heard report |
| `sms_emit_udp()` | Forward SMS |
| `obp_forward_dmrd()` | Forward DMRD frames |

---

## 🧵 Threading Model

| Thread | Purpose |
|---------|----------|
| Main | UDP I/O loop |
| Timer | Updates tick/sec counters |
| Parrot Playback | Replays buffered audio |
| APRS / SMS | Optional background tasks |

---

## 🧰 Runtime

```bash
./dmr
```

Check server status:

```bash
echo "/STAT" | nc -u 127.0.0.1 62031
```

---

## 🧾 Logging

- **Console:** color-coded live output  
- **SQLite3 (optional):** persistent log table (`DATE, RADIO, TG, SLOT, NODE, ACTIVE, CONNECT, TIME`)

---

## 🤝 Contributing

1. Fork the repo and create a feature branch:  
   `feat/<topic>` or `fix/<scope>`
2. Follow existing style (C++17, RAII, no extra deps)
3. Keep PRs small, focused, and well-documented
4. Test on both Linux and Windows
5. Avoid new runtime dependencies — keep it lean

> 💡 **Tip:** Include a short design note for any change that affects network or TG behavior.

---

## 📜 License

Licensed for **educational and amateur radio experimentation**.  
Ensure compliance with regional DMR and spectrum regulations.

---

## 🌐 Documentation

The full developer documentation, including protocol specs, API reference tables, and architecture diagram, is available as:

👉 **[readme.html](./readme.html)**  

---

<p align="center">
  <img src="https://img.shields.io/github/stars/openDMR/openDMR?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/openDMR/openDMR?style=social" alt="Forks">
</p>
