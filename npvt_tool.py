#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                  NPVT1 Tool - NPV TUNNEL Config              ║
║     Parse, Decrypt, and View .npvt configuration files      ║
╚═══════════════════════════════════════════════════════════════╝

NPVT1 file format (reverse engineered):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Line 1:  NPVT1                    ← version marker
  Line 2:  <F1_b64>,<F2_b64>,<F3_b64>  ← 3 comma-separated fields

  Field 1 (17 bytes): 1-byte type ('c'/'v') + 16-byte UUID
    'c' = Cloudflare CDN  |  'v' = WebSocket (direct)

  Field 2 (variable): Encrypted config payload
    White-box AES-CTR encryption (IV:16 + ciphertext)

  Field 3 (213 bytes): Signature/Checksum

Usage:
  python npvt_tool.py <file.npvt>               # Show file info + decrypt
  python npvt_tool.py <file.npvt> --info         # Show info only
  python npvt_tool.py <file.npvt> --decrypt      # Decrypt and show config
"""
import base64
import json
import sys


# ═══════════════════════════════════════════════════════════════
#  Whitebox AES (from NPVTUNNEL.py)
# ═══════════════════════════════════════════════════════════════

try:
    from NPVTUNNEL import load_whitebox_state, whitebox_encrypt_block
    _HAS_WHITEBOX = True
except Exception as e:
    _HAS_WHITEBOX = False
    _WB_ERROR = str(e)


def whitebox_decrypt(payload_b64):
    """
    Decrypt NPVT field 2 using Whitebox AES-CTR.
    
    Args:
        payload_b64: Base64 string of IV(16) + ciphertext
    Returns:
        Decrypted JSON string, or None on failure
    """
    if not _HAS_WHITEBOX:
        print("Error: NPVTUNNEL.py not found or whitebox state failed to load")
        if '_WB_ERROR' in dir():
            print(f"  Details: {_WB_ERROR}")
        return None
    
    try:
        p2, p3, p4, p5 = load_whitebox_state()
        raw_bytes = list(base64.b64decode(payload_b64))
        iv = bytearray(raw_bytes[:16])
        ciphertext = raw_bytes[16:]
        decrypted = bytearray()
        keystream = None
        
        for j in range(len(ciphertext)):
            block_offset = j % 16
            if block_offset == 0:
                keystream = whitebox_encrypt_block(bytes(iv), p2, p3, p4, p5)
                for k in range(15, -1, -1):
                    iv[k] = (iv[k] + 1) & 0xFF
                    if iv[k] != 0:
                        break
            decrypted.append(ciphertext[j] ^ keystream[block_offset])
        
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════
#  NPVT1 PARSER
# ═══════════════════════════════════════════════════════════════

class NPVT1File:
    """Parsed NPVT1 configuration file."""
    
    def __init__(self):
        self.version = "NPVT1"
        self.type_byte = '?'
        self.config_uuid = None
        self.payload_b64 = None
        self.signature_hex = None
        self.decrypted = None  # JSON string if decrypted
    
    @property
    def uuid_str(self):
        if not self.config_uuid:
            return None
        h = self.config_uuid.hex()
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    
    @property
    def protocol(self):
        return {'c': 'SSH + Cloudflare', 'v': 'SSH + WebSocket'}.get(
            self.type_byte, "Unknown (%s)" % self.type_byte)
    
    @classmethod
    def parse(cls, filepath):
        with open(filepath, 'r') as f:
            content = f.read().strip()
        
        lines = content.split('\n')
        if len(lines) < 2:
            raise ValueError("File too short")
        
        version = lines[0].strip()
        if version not in ('NPVT1', 'NPVT2'):
            raise ValueError(f"Unknown version: '{version}'")
        
        fields = lines[1].split(',')
        if len(fields) < 3:
            raise ValueError(f"Expected 3 fields, got {len(fields)}")
        
        result = cls()
        result.version = version
        
        f1 = base64.b64decode(fields[0])
        if len(f1) < 1:
            raise ValueError("Field 1 is empty")
        result.type_byte = chr(f1[0]) if 32 <= f1[0] <= 126 else '?'
        # Pad UUID to 16 bytes if shorter
        uuid_part = f1[1:]
        if len(uuid_part) < 16:
            uuid_part = uuid_part.ljust(16, b'\x00')
        result.config_uuid = uuid_part[:16]
        
        result.payload_b64 = fields[1]
        result.signature_hex = base64.b64decode(fields[2]).hex()[:64] + "..."
        
        return result
    
    def decrypt(self):
        """Decrypt payload using Whitebox AES."""
        result = whitebox_decrypt(self.payload_b64)
        if result:
            try:
                parsed = json.loads(result)
                if isinstance(parsed, list) and len(parsed) > 0:
                    parsed = parsed[0]
                self.decrypted = json.dumps(parsed, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                self.decrypted = result
        return self.decrypted is not None


# ═══════════════════════════════════════════════════════════════
#  DISPLAY
# ═══════════════════════════════════════════════════════════════

def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='NPVT1 Tool - ดูและถอดรหัสไฟล์ .npvt สำหรับ NPV TUNNEL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ตัวอย่าง:
  python npvt_tool.py config.npvt              # ดูข้อมูล + ถอดรหัส
  python npvt_tool.py config.npvt --info       # ดูข้อมูลอย่างเดียว
  python npvt_tool.py config.npvt --decrypt    # ถอดรหัสอย่างเดียว
  
สร้างไฟล์ .npvt ใหม่:
  python npvt_encoder.py --generate out.npvt --example
        """
    )
    
    parser.add_argument('file', help='ไฟล์ .npvt')
    parser.add_argument('--info', action='store_true',
                        help='แสดงข้อมูลไฟล์อย่างเดียว')
    parser.add_argument('--decrypt', action='store_true',
                        help='ถอดรหัสและแสดง JSON config')
    
    args = parser.parse_args()
    
    # Parse file
    try:
        npvt = NPVT1File.parse(args.file)
    except Exception as e:
        print(f"Error parsing file: {e}")
        sys.exit(1)
    
    # Show file info
    print_header(f"NPVT1 File: {args.file}")
    print(f"  Version:   {npvt.version}")
    print(f"  Type:      '{npvt.type_byte}' → {npvt.protocol}")
    print(f"  UUID:      {npvt.uuid_str}")
    
    payload_size = len(base64.b64decode(npvt.payload_b64)) if npvt.payload_b64 else 0
    print(f"  Payload:   {payload_size} bytes (Whitebox AES-CTR)")
    print(f"  Signature: {npvt.signature_hex}")
    
    if args.info:
        return
    
    # Decrypt
    print_header("Decrypting...")
    
    if not _HAS_WHITEBOX:
        print(f"\n⚠️  ต้องมีไฟล์ NPVTUNNEL.py อยู่ในโฟลเดอร์เดียวกัน")
        print(f"   Error: {_WB_ERROR}")
        print(f"\n📥 ดาวน์โหลดได้ที่:")
        print(f"   https://raw.githubusercontent.com/ENIGMATIC-MAN/")
        print(f"   DECRYPTION_SCRIPTS/main/NPVTUNNEL.py")
        sys.exit(1)
    
    if npvt.decrypt():
        print("\n✅ Decrypted successfully!\n")
        print(npvt.decrypted)
        
        # Summary
        try:
            data = json.loads(npvt.decrypted)
            print_header("Summary")
            print(f"  Name:     {data.get('name', 'N/A')}")
            print(f"  Server:   {data.get('address', 'N/A')}")
            print(f"  Protocol: {data.get('type', 'N/A')}")
            if 'sshConfig' in data:
                sc = data['sshConfig']
                print(f"  SSH User: {sc.get('sshUsername', 'N/A')}")
                print(f"  SSH Pass: {'****' if sc.get('sshPassword') else '(none)'}")
                if sc.get('httpProxy'):
                    print(f"  Proxy:    {sc['httpProxy']}")
        except:
            pass
    else:
        print("\n❌ ถอดรหัสไม่สำเร็จ")
        print("   ตรวจสอบว่า NPVTUNNEL.py อยู่ในโฟลเดอร์เดียวกัน")


if __name__ == '__main__':
    main()
