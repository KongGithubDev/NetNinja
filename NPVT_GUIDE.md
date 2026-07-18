# 📘 คู่มือการทำงานกับไฟล์ NPVT สำหรับ NPV TUNNEL

**NPVT** (NapsternetV/NPV Tunnel) เป็นไฟล์คอนฟิกสำหรับแอป **NPV TUNNEL** บน Android
ไฟล์นี้เก็บการตั้งค่า SSH/V2Ray/Trojan ต่างๆ โดยเข้ารหัสด้วย **White-box AES-CTR**

---

## 📖 สารบัญ

1. [โครงสร้างไฟล์ NPVT1](#-โครงสร้างไฟล์-npvt1)
2. [การถอดรหัส (Decrypt)](#-การถอดรหัส-decrypt)
3. [การเข้ารหัส (Encrypt / สร้างไฟล์ใหม่)](#-การเข้ารหัส-encrypt--สร้างไฟล์ใหม่)
4. [คู่มือการใช้งาน Scripts](#-คู่มือการใช้งาน-scripts)
5. [ตัวอย่างการสร้างไฟล์ .npvt สำหรับ SSH](#-ตัวอย่างการสร้างไฟล์-npvt-สำหรับ-ssh)
6. [การแก้ปัญหา (Troubleshooting)](#-การแก้ปัญหา-troubleshooting)
7. [ภาคผนวก: JSON Config Fields](#-ภาคผนวก-json-config-fields)

---

## 🔍 โครงสร้างไฟล์ NPVT1

ไฟล์ `.npvt` มีโครงสร้างง่ายๆ ดังนี้:

```
NPVT1
<Field1_Base64>,<Field2_Base64>,<Field3_Base64>
```

| ส่วน | ขนาด | คำอธิบาย |
|:-----|:-----|:---------|
| **บรรทัด 1** | `NPVT1` | เวอร์ชันฟอร์แมต |
| **Field 1** | 17 bytes (→ ~24 chars Base64) | `1 byte type` + `16 bytes UUID` |
| **Field 2** | 918-1049 bytes (→ ~1224-1400 chars Base64) | ข้อมูลคอนฟิกที่เข้ารหัสแล้ว |
| **Field 3** | 213 bytes (→ ~284 chars Base64) | ลายเซ็น/Checksum |

### Field 1: Type Byte

| Type | ความหมาย |
|:----|:---------|
| `'c'` (0x63) | **SSH + Cloudflare CDN** — ใช้ Cloudflare เป็นตัวกลาง |
| `'v'` (0x76) | **SSH + WebSocket** — ต่อตรงผ่าน WebSocket |

### ตัวอย่าง Field 1

```
ไฟล์ AIS_NOPRO_SSH_CF:  63 f8ad83468fc03b23abb5c772bfc52814
                        │  └─────────── UUID (16 bytes) ───────────┘
                        └ type='c' (Cloudflare)

ไฟล์ AIS_NOPRO_SSH_WS:  76 b797aac00e830737c2243d2b5b0ecaff
                        │  └─────────── UUID (16 bytes) ───────────┘
                        └ type='v' (WebSocket)
```

---

## 🔐 การถอดรหัส (Decrypt)

### วิธีการทำงานของ White-box AES-CTR

```
┌─────────────────────────────────────────────────────────────┐
│  Field 2 Base64 Decode                                       │
│       ↓                                                      │
│  [IV 16 bytes] [Ciphertext ...]                             │
│       │                                                     │
│  ┌────┴────┐            ┌─────────────────────────┐         │
│  │ IV(0)   │───▶ Whitebox_AES ──▶ Keystream[0:15] │         │
│  └────┬────┘            └──────────┬──────────────┘         │
│       │                            │                        │
│  ┌────┴────┐            ┌──────────┴──────────────┐         │
│  │ IV+1    │───▶ Whitebox_AES ──▶ Keystream[16:31]│         │
│  └────┬────┘            └──────────┬──────────────┘         │
│       │                            │                        │
│      ...                          ...                      │
│                                            │                │
│   Keystream ⊕ Ciphertext = Plaintext (JSON) │               │
└─────────────────────────────────────────────────────────────┘
```

### สคริปต์ถอดรหัส: `npvt_tool.py`

```bash
# ดูข้อมูลไฟล์ .npvt (ไม่ถอดรหัส)
python npvt_tool.py "01-AIS_NOPRO_SSH_CF (1).npvt" --info

# ถอดรหัสอัตโนมัติ (ใช้ White-box AES จาก NPVTUNNEL.py)
python npvt_tool.py "01-AIS_NOPRO_SSH_CF (1).npvt" --decrypt
```

### สคริปต์ถอดรหัส: `NPVTUNNEL.py`

```bash
# ใช้ Python REPL
python -c "
import NPVTUNNEL
with open('config.npvt', 'rb') as f:
    result = NPVTUNNEL.run(f.read())
print(result)
"
```

**Output:** JSON ที่อ่านได้:
```json
{
    "name": "My-Config",
    "address": "server.com:443",
    "type": "SSH",
    "sshConfig": {
        "sshHost": "server.com",
        "sshPort": 443,
        "sshUsername": "user",
        "sshPassword": "pass",
        "httpProxy": "proxy.com:8080",
        "payload": "GET / HTTP/1.1\r\nHost: [host]..."
    },
    "lockConfig": {
        "isLocked": false
    }
}
```

---

## 🔑 การเข้ารหัส (Encrypt / สร้างไฟล์ใหม่)

### วิธีการสร้างไฟล์ .npvt

```
┌───────────────────────────────────────────────┐
│  JSON Config                                   │
│       ↓                                        │
│  JSON → UTF-8 Bytes                           │
│       ↓                                        │
│  สุ่ม IV 16 bytes                              │
│       ↓                                        │
│  For each 16-byte block:                      │
│    Keystream = Whitebox_AES(IV_counter)       │
│    Ciphertext = Plaintext ⊕ Keystream         │
│    IV_counter++                               │
│       ↓                                        │
│  [IV + Ciphertext] → Base64 → Field 2        │
│       ↓                                        │
│  สร้าง Field 1 (type_byte + UUID)             │
│  สร้าง Field 3 (signature placeholder)        │
│       ↓                                        │
│  NPVT1<newline><F1>,<F2>,<F3>                │
└───────────────────────────────────────────────┘
```

### สคริปต์สร้างไฟล์: `npvt_encoder.py`

```bash
# สร้างไฟล์จาก JSON string
python npvt_encoder.py --generate myconfig.npvt \
    '{"name":"My Server","address":"host:443","type":"SSH","sshConfig":{"sshHost":"host","sshPort":443,"sshUsername":"user","sshPassword":"pass"}}'

# สร้างไฟล์จากไฟล์ JSON
python npvt_encoder.py --generate myconfig.npvt --config-file myconfig.json

# สร้างไฟล์ตัวอย่าง (แล้วแก้ไขค่าทีหลัง)
python npvt_encoder.py --generate myconfig.npvt --example

# เลือกประเภท Cloudflare หรือ WebSocket
python npvt_encoder.py --generate ws_config.npvt --type v --example
```

---

## 🛠 คู่มือการใช้งาน Scripts

### 1. `npvt_tool.py` — ดูข้อมูลและถอดรหัส

```bash
# ดูข้อมูลไฟล์
python npvt_tool.py config.npvt --info

# ถอดรหัส
python npvt_tool.py config.npvt --decrypt

# ถอดรหัสแบบละเอียด
python npvt_tool.py config.npvt --key <32_hex_chars> --delta <delta>
```

### 2. `NPVTUNNEL.py` — ถอดรหัส (จาก ENIGMATIC-MAN)

```bash
python -c "
import NPVTUNNEL

# ถอดรหัสไฟล์เดียว
with open('config.npvt', 'rb') as f:
    result = NPVTUNNEL.run(f.read())
print(result)

# ถอดรหัสหลายไฟล์
import os
for f in os.listdir('.'):
    if f.endswith('.npvt'):
        with open(f, 'rb') as fh:
            r = NPVTUNNEL.run(fh.read())
        print(f'\\n=== {f} ===')
        print(r)
"
```

### 3. `npvt_encoder.py` — สร้างไฟล์ .npvt ใหม่

```bash
# ต้องมี NPVTUNNEL.py อยู่ในโฟลเดอร์เดียวกันเสมอ!
python npvt_encoder.py --generate myvpn.npvt --example
```

---

## 📝 ตัวอย่างการสร้างไฟล์ .npvt สำหรับ SSH

### ขั้นตอนที่ 1: สร้างไฟล์ JSON

```json
{
    "name": "Netninja-SSH",
    "address": "your-vps.com:443",
    "type": "SSH",
    "sshConfig": {
        "sshConfigType": "SSH-Proxy-Payload",
        "remarks": "Netninja-SSH",
        "sshHost": "your-vps.com",
        "sshPort": 443,
        "sshUsername": "vps-user",
        "sshPassword": "vps-password",
        "sni": "",
        "tlsVersion": "DEFAULT",
        "httpProxy": "",
        "authenticateProxy": false,
        "proxyUsername": "",
        "proxyPassword": "",
        "payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]",
        "dnsTTMode": "UDP",
        "dnsServer": "",
        "nameserver": "",
        "publicKey": "",
        "udpgwPort": 7300,
        "udpgwTransparentDNS": true
    },
    "lockConfig": {
        "version": 1,
        "isLocked": false,
        "password": "",
        "onlyMobileNetwork": false,
        "blockRootedAndJailbroken": false,
        "onlyOfficialStores": false,
        "expiryDate": "",
        "deviceIds": "",
        "message": "",
        "customServerMessage": ""
    }
}
```

### ขั้นตอนที่ 2: สร้างไฟล์ .npvt

```bash
python npvt_encoder.py --generate netninja.npvt --config-file config.json
```

### ขั้นตอนที่ 3: นำเข้าใน NPV TUNNEL

1. ส่งไฟล์ `.npvt` ไปยังโทรศัพท์ (Line/SHAREit/AirDrop/SD Card)
2. เปิดแอป **NPV TUNNEL**
3. กดปุ่ม **+** มุมขวาล่าง
4. เลือก **Import Config**
5. เลือกไฟล์ `.npvt`
6. ตรวจสอบและแก้ไขค่าต่างๆ
7. กด **Connect**

### การตั้งค่า Payload สำหรับ SSH

#### สำหรับ Cloudflare (type='c'):

```
POST / HTTP/1.1
Host: prd-static-file.aws.clicxbank.com
User-Agent: [ua] [crlf][crlf]
[instant_split]
[split]- /@- HTTP/1.1
Host: [host]
User-Agent: [ua] [crlf][crlf]
GET /ssh HTTP/1.1
Host: [host]
Connection: Upgrade
User-Agent: [ua]
Upgrade: websocket [crlf][crlf]
```

#### สำหรับ WebSocket (type='v'):

```
POST / HTTP/1.1
Host: search.ais.co.th
User-Agent: [ua][crlf][crlf]
[instant_split]
PATCH / HTTP/1.1
Host: [host]
Connection: Upgrade
User-Agent: [ua]
Upgrade: websocket[crlf][crlf]
```

**คำอธิบาย Payload:**
- `[host]` — ถูกแทนที่ด้วย SSH Host โดยอัตโนมัติ
- `[ua]` — ถูกแทนที่ด้วย User-Agent จริง
- `[crlf]` — Carriage Return + Line Feed (\r\n)
- `[instant_split]` — จุดแบ่งระหว่างส่วนหัว HTTP และ SSH tunnel
- `[split]` — จุด Split เพิ่มเติม

---

## ❓ การแก้ปัญหา (Troubleshooting)

### ปัญหา: Import แล้ว "Invalid File" / "ไม่สามารถอ่านไฟล์ได้"
- ✅ ตรวจสอบว่าใช้ `npvt_encoder.py` (ไม่ใช่ `npvt_tool.py`)
- ✅ ต้องมีไฟล์ `NPVTUNNEL.py` อยู่ในโฟลเดอร์เดียวกับ `npvt_encoder.py`
- ✅ ตรวจสอบว่าไฟล์ขึ้นต้นด้วย `NPVT1` (ไม่ใช่ `NPVTSUB1`)
- ✅ ตรวจสอบว่า JSON Format ถูกต้อง

### ปัญหา: Import แล้วแต่ Config ว่างเปล่า
- ✅ ตรวจสอบว่า JSON Config มี key ครบถ้วน
- ✅ ใช้ `--example` เพื่อสร้างไฟล์ตัวอย่างก่อน แล้วค่อยแก้ไข
- ✅ ลองเปลี่ยน Type เป็น `c` หรือ `v`

### ปัญหา: เชื่อมต่อไม่ได้ (Connection Failed)
- ✅ ตรวจสอบ SSH Host/Port/Username/Password ให้ถูกต้อง
- ✅ ตรวจสอบว่า Payload ถูกต้อง
- ✅ ลองเปลี่ยน HTTP Proxy หรือใช้ค่าว่าง
- ✅ ตรวจสอบ Firewall ที่ Server

### ปัญหา: "Locked Config" / ต้องใช้ Password
- ✅ ตั้งค่า `"isLocked": false` ใน `lockConfig`
- ✅ หรือลบ `lockConfig` ออกจาก JSON

---

## 📋 ภาคผนวก: JSON Config Fields

### โครงสร้างหลัก (Root)

| ฟิลด์ | ประเภท | คำอธิบาย |
|:------|:-------|:---------|
| `name` | string | ชื่อ Config |
| `address` | string | `host:port` สำหรับแสดงผล |
| `type` | string | `"SSH"`, `"V2Ray"`, `"Trojan"`, ฯลฯ |
| `sshConfig` | object | การตั้งค่า SSH |
| `lockConfig` | object | การล็อค/ป้องกัน Config |

### sshConfig

| ฟิลด์ | ประเภท | ค่าเริ่มต้น | คำอธิบาย |
|:------|:-------|:----------|:---------|
| `sshConfigType` | string | `"SSH-Proxy-Payload"` | ประเภท SSH Config |
| `remarks` | string | — | ชื่อสำหรับแสดง |
| `sshHost` | string | — | SSH Server (IP/โดเมน) |
| `sshPort` | number | 22 | SSH Port |
| `sshUsername` | string | — | ชื่อผู้ใช้ SSH |
| `sshPassword` | string | — | รหัสผ่าน SSH |
| `sni` | string | `""` | SNI สำหรับ TLS |
| `tlsVersion` | string | `"DEFAULT"` | เวอร์ชัน TLS |
| `httpProxy` | string | `""` | HTTP Proxy (`host:port`) |
| `authenticateProxy` | bool | false | ใช้ Proxy Auth |
| `proxyUsername` | string | `""` | ชื่อผู้ใช้ Proxy |
| `proxyPassword` | string | `""` | รหัสผ่าน Proxy |
| `payload` | string | — | SSH Payload |
| `dnsTTMode` | string | `"UDP"` | โหมด DNS Tunnel |
| `dnsServer` | string | `""` | DNS Server |
| `nameserver` | string | `""` | Nameserver |
| `publicKey` | string | `""` | Public Key |
| `udpgwPort` | number | 7300 | UDP Gateway Port |
| `udpgwTransparentDNS` | bool | true | UDPGW DNS โปร่งใส |

### lockConfig

| ฟิลด์ | ประเภท | ค่าเริ่มต้น | คำอธิบาย |
|:------|:-------|:----------|:---------|
| `version` | number | 1 | เวอร์ชัน Lock Config |
| `isLocked` | bool | false | ล็อค Config หรือไม่ |
| `password` | string | `""` | รหัสผ่านปลดล็อค |
| `onlyMobileNetwork` | bool | false | ใช้ได้เฉพาะ Mobile Network |
| `blockRootedAndJailbroken` | bool | false | บล็อคเครื่อง Root |
| `onlyOfficialStores` | bool | false | ใช้ได้เฉพาะจาก Store |
| `expiryDate` | string | `""` | วันที่หมดอายุ |
| `deviceIds` | string | `""` | จำกัดเฉพาะ Device ID |
| `message` | string | `""` | ข้อความแจ้งเตือน |
| `customServerMessage` | string | `""` | ข้อความจาก Server |

---

## 📦 รวมคำสั่งทั้งหมด

```bash
# === ดูข้อมูลไฟล์ ===
python npvt_tool.py "config.npvt" --info

# === ถอดรหัส (decrypt) ===
python npvt_tool.py "config.npvt" --decrypt

# ถอดรหัสด้วย NPVTUNNEL.py
python -c "import NPVTUNNEL; print(NPVTUNNEL.run(open('config.npvt','rb').read()))"

# === สร้างไฟล์ (encrypt) ===
python npvt_encoder.py --generate output.npvt --example
python npvt_encoder.py --generate output.npvt --config-file settings.json
python npvt_encoder.py --generate output.npvt '{"name":"Test","address":"x:22","type":"SSH","sshConfig":{"sshHost":"x","sshPort":22,"sshUsername":"u","sshPassword":"p"}}'
```

---

## 📄 License & เครดิต

- สคริปต์ถอดรหัส: **NPVTUNNEL.py** — โดย [ENIGMATIC-MAN](https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS)
- สคริปต์เข้ารหัสและ GUI: **npvt_encoder.py**, **npvt_tool.py** — โดยผู้พัฒนา Netninja
- White-box AES state: extracted from NPV TUNNEL APK

---

*สร้างเมื่อ: กรกฎาคม 2026*
