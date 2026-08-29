# NetNinja Proxy - Troubleshooting: iPad ช้าหลัง 5 นาที

## สรุปปัญหา

Proxy ทำงานปกติช่วงแรก แต่หลังใช้งาน ~5 นาที จะเริ่มช้า/ตัด connection จนต้อง toggle WiFi บน iPad

## สาเหตุหลัก: True Corp CGNAT

```
iPad (184.82.167.218)
  → Home Router NAT
    → True Corp ISP (CGNAT)
      → International Transit
        → Azure Malaysia (VM)
          → Proxy (port 443)
```

**True Corp CGNAT ตัด TCP connection ที่ idle > ~5 นาที สำหรับ international traffic**

### หลักฐาน

1. **Thai VPS ใช้ได้** - traffic ในประเทศ (Thailand → Thailand) ไม่ผ่าน CGNAT ที่โหด
2. **Azure ใช้ไม่ได้** - international traffic (Thailand → Malaysia) ผ่าน True Corp CGNAT
3. **Server test 300/300 OK** - proxy ฝั่ง server ทำงานปกติ (test จาก localhost ไม่ผ่าน CGNAT)
4. **Logs แสดง connection reset by peer** - CGNAT ตัด mapping → iPad ส่ง RST กลับมา

### Timeline ที่เกิดปัญหา

```
t=0s     : iPad เชื่อม proxy ผ่าน Azure
t=0-240s : Data ไหลปกติ (YouTube, Facebook)
t=240s+  : True Corp CGNAT ลบ NAT mapping (idle timeout ~5 min)
t=240s+  : Azure ส่ง keepalive probe → CGNAT drop (ไม่มี mapping)
t=240s+  : iPad ส่ง data → CGNAT ไม่รู้ mapping → ส่ง RST
t=240s+  : iPad เห็น "connection reset by peer" → cache "proxy broken"
t=240s+  : iOS หยุดใช้ proxy จนกว่าจะ toggle WiFi
```

## ทำไมแก้จาก server ไม่ได้

### TCP Keepalive ไม่ช่วย

เราตั้ง TCP keepalive ทุก 10 วินาที ผ่าน syscall:

```go
syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 10)
syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
```

**ปัญหา**: CGNAT ไม่นับ TCP keepalive ACK packets เป็น "data traffic"
- Keepalive probes มี payload = 0 หรือ 1 byte (garbage)
- CGNAT บางตัวนับเฉพาะ data ที่มี payload จริง
- Keepalive probes ถูกเมิน → idle timer ไม่ reset → connection ตาย

### Inject Data เข้า CONNECT Tunnel ไม่ได้

CONNECT tunnel เป็น TCP pipe โปร่งใส:
```
iPad ←TLS→ Proxy ←TCP→ YouTube
```

ถ้าเราเขียน data เพิ่มเข้าไปใน tunnel:
- iPad จะตีความว่าเป็น TLS data → TLS error → connection ตาย
- ไม่มี way ไหนที่จะส่ง data ผ่าน tunnel โดยไม่ break TLS

### Azure LB ไม่ใช่ปัญหาหลัก

VM metadata แสดงว่ามี Azure LB:
```json
{"loadbalancer":{"publicIpAddresses":[{"frontendIpAddress":"85.211.183.237"}]}}
```

แต่ **ไม่มี LB resource ใน Azure Portal** - เป็น implicit LB ที่ Azure สร้างอัตโนมัติ
- inboundRules: [] (ไม่มี rule)
- outboundRules: [] (ไม่มี rule)

ปัญหาหลักคือ **True Corp CGNAT** ไม่ใช่ Azure LB

## ทางออกที่วิเคราะห์แล้ว

### ทางที่ 1: IPv6 (แนะนำสุด — ไม่ต้องลงแอพ/VPN บน iPad)

**หลักการ**: IPv6 ไม่มี NAT → ไม่มี idle timeout

```
เดิม (IPv4):
iPad → IPv4 → True CGNAT → Azure IPv4  ← CGNAT ตัด connection

ใหม่ (IPv6):
iPad → IPv6 → Azure IPv6  ← ไม่มี NAT, ไม่มี idle timeout
```

**วิธี**:
1. เพิ่ม IPv6 address บน Azure VM
2. Proxy listen บน IPv6
3. iPad proxy settings ใส่ IPv6 address ของ Azure VM
4. True Corp WiFi ต้องรองรับ IPv6 (ตรวจสอบด้วย `test-ipv6.com` บน iPad)

**ข้อดี**:
- ไม่ต้องลงแอพ/VPN บน iPad
- ไม่มี CGNAT (IPv6 ไม่ใช้ NAT)
- ไม่ต้องย้าย server
- แก้ root cause จริงๆ

**ข้อจำกัด**:
- True Corp WiFi ต้องมี native IPv6
- Azure VM ต้องเพิ่ม IPv6 interface

**สถานะ**: Azure VM ยังไม่มี IPv6 (มีแค่ link-local `fe80::`) — ต้องเพิ่มใน Azure Portal

---

### ทางที่ 2: Deploy บน Thai VPS

**วิธี**: ย้าย proxy ไป Thai VPS
- iPad เปลี่ยน proxy address → Thai VPS IP (แค่แก้ settings, ไม่ต้องลงแอพ)
- Domestic traffic ไม่ผ่าน CGNAT ที่โหด
- เหมือนเดิมที่เคยใช้ได้

**ข้อเสีย**: ต้องมี Thai VPS (~200 บาท/เดือน)

---

### ทางที่ 3: WireGuard VPN บน Azure VM

**วิธี**: ติดตั้ง WireGuard server บน Azure VM → iPad ต่อ VPN
- WireGuard ใช้ UDP + keepalive ทุก 25s → CGNAT mapping ไม่หาย
- ต้องติดตั้ง WireGuard app บน iPad

**ข้อเสีย**: ต้องลงแอพ VPN บน iPad

---

### ทางที่ 4: Cloudflare Tunnel (cloudflared)

**วิธี**: ติดตั้ง cloudflared บน Azure VM → tunnel ไป Cloudflare edge
- iPad เชื่อม Cloudflare domain → forward ไป Azure
- Cloudflare edge ส่ง HTTP/2 PING frames → CGNAT นับเป็น data

**ข้อเสีย**: ต้องเปลี่ยน proxy address บน iPad, ต้องมี Cloudflare account

---

### ทางที่ 5: Cloudflare WARP

**วิธี**: ติดตั้ง WARP app บน iPad → เปิดใช้เมื่อใช้ proxy
- WARP tunnel ผ่าน Cloudflare network → CGNAT bypass

**ข้อเสีย**: ต้องลงแอพ VPN บน iPad

## ทางออกที่วิเคราะห์แล้วว่าไม่ work

### ❌ HTTP/2 หรือ HTTP/3 proxy

น่าสนใจทาง protocol แต่ iPadOS system proxy ไม่ได้เปิดช่องให้บังคับว่า proxy connection จะต้องใช้ HTTP/3/QUIC → ไม่ใช่ drop-in fix สำหรับ iPad Settings Proxy

### ❌ Connection pool / multiplexing proxy (mqproxy)

ช่วยเฉพาะ Azure → upstream แต่ iPad → Azure ยังเป็น TCP ผ่าน CGNAT → ไม่แก้ root cause

### ❌ Reverse relay

ถ้า iPad ยังต่อ TCP ตรง → iPad → True CGNAT → Relay → Azure ยังมีปัญหาเดิม

### ❌ PAC สำหรับ short-lived connections

PAC ไม่สามารถสั่งให้ iOS recycle HTTP CONNECT ทุก 4 นาทีได้ → ช่วยได้เฉพาะบาง traffic

### ❌ CDN/edge endpoint

CDN ทั่วไปไม่ได้เป็น generic TCP CONNECT proxy → client ต้องรองรับ protocol นั้นด้วย

## การแก้ไขที่ทำไปแล้ว

| Fix | สถานะ | ผลลัพธ์ |
|-----|--------|---------|
| REAP disabled | Done | ✅ Tunnel ไม่ถูกตัดโดย proxy |
| TCP keepalive 10s (syscall) | Done | ❌ CGNAT เมิน keepalive probes |
| tcp_slow_start_after_idle=0 | Done | ✅ Throughput ไม่ตกหลัง idle |
| sysctl tcp_keepalive_time=600 | Done | ❌ ไม่ช่วยเพราะ CGNAT |
| Empty URL scheme fix | Done | ✅ iOS ส่ง request ได้ |
| CONNECT rate limit 50 | Done | ✅ ป้องกัน abuse |
| PAC DIRECT speedtest | Done | ✅ Speedtest ไม่ผ่าน proxy |
| PAC DIRECT server IP | Done | ✅ Dashboard bypass proxy |
| Conservative REAP (3.5 min) | Done | ⏳ กำลังทดสอบ — ส่ง FIN ก่อน CGNAT timeout |
| Suppress favicon.ico spam | Done | ✅ ไม่ log favicon.ico อีก |
| Suppress context canceled | Done | ✅ ไม่ log benign client disconnect |

## Conservative REAP — วิธีทำงาน

```
เดิม (REAP disabled):
iPad ←idle 5 min→ Proxy
CGNAT → RST → iPad เห็น "proxy broken" → cache

ใหม่ (Conservative REAP):
iPad ←idle 3.5 min→ Proxy → ส่ง FIN (graceful close)
iOS เห็น FIN → เปิด tunnel ใหม่ → ทำงานต่อ
```

**กลไก**:
- ทุก tunnel มี goroutine เช็ค idle time ทุก 30 วินาที
- ถ้า idle >= 210 วินาที (3.5 นาที) → ส่ง TCP FIN ทั้ง client + dest
- FIN = graceful close (ไม่ใช่ RST) → iOS ควรรับได้ดีกว่า RST
- ใช้ `sync.Once` ป้องกัน double-close panic

## สรุป

```
ปัญหา: True Corp CGNAT ตัด international TCP connection หลัง ~5 นาที
สาเหตุ: CGNAT ไม่นับ TCP keepalive เป็น "data" → idle timeout ไม่ reset

ทางแก้ที่ดีทสุด: IPv6 (ไม่ต้องลงแอพ/VPN บน iPad)
  - ต้อง: เพิ่ม IPv6 บน Azure VM + True Corp WiFi ต้องรองรับ IPv6
  - ไม่ต้อง: ย้าย server, ลงแอพ, ตั้ง VPN

ทางแก้สำรอง: Deploy บน Thai VPS (domestic traffic ไม่ผ่าน CGNAT โหด)

ทางแก้ชั่วคราว: Conservative REAP (ส่ง FIN ก่อน CGNAT timeout)
  - สถานะ: กำลังทดสอบ
  - ข้อจำกัด: iOS อาจ cache "proxy broken" จาก FIN ด้วย
```
