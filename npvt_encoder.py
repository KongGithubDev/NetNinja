#!/usr/bin/env python3
"""
NPVT Encoder - สร้างไฟล์ .npvt ที่ใช้กับ NPV TUNNEL ได้

วิธีใช้:
  python npvt_encoder.py --generate config.npvt '{"name":"test","address":"host:443","type":"SSH","sshConfig":{...}}'
  python npvt_encoder.py --generate config.npvt --config-file myconfig.json
  python npvt_encoder.py --generate config.npvt --example  # สร้าง config ตัวอย่าง
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import uuid as uuid_mod

# ═══════════════════════════════════════════════════════════════
#  IMPORT Whitebox AES from NPVTUNNEL
# ═══════════════════════════════════════════════════════════════
try:
    from NPVTUNNEL import (
        load_whitebox_state,
        whitebox_encrypt_block,
    )
    _WHITEBOX_LOADED = True
except Exception as e:
    print("Warning: Could not load NPVTUNNEL whitebox state:", e)
    print("Make sure NPVTUNNEL.py is in the same directory")
    _WHITEBOX_LOADED = False


# ═══════════════════════════════════════════════════════════════
#  NPVT ENCRYPTION (reverse of NPVTUNNEL.decrypt_logic)
# ═══════════════════════════════════════════════════════════════

def npvt_encrypt(plaintext, p2, p3, p4, p5):
    """
    Encrypt plaintext to NPVT-compatible ciphertext.
    
    Uses AES-CTR mode with Whitebox AES keystream generation.
    
    Args:
        plaintext: UTF-8 encoded config bytes
        p2, p3, p4, p5: Whitebox AES state tables
    Returns:
        base64-encoded string: IV(16 bytes) + ciphertext
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate random 16-byte IV
    iv = bytearray(os.urandom(16))
    original_iv = bytes(iv)  # Save for prepending
    
    # Encrypt byte by byte using AES-CTR
    ciphertext = bytearray()
    keystream = None
    
    for j in range(len(plaintext)):
        block_offset = j % 16
        if block_offset == 0:
            # Generate new keystream block
            keystream = whitebox_encrypt_block(bytes(iv), p2, p3, p4, p5)
            # Increment IV (big-endian counter)
            for k in range(15, -1, -1):
                iv[k] = (iv[k] + 1) & 0xFF
                if iv[k] != 0:
                    break
        # XOR plaintext byte with keystream
        ciphertext.append(plaintext[j] ^ keystream[block_offset])
    
    # Combine IV + ciphertext and base64 encode
    result = base64.b64encode(original_iv + bytes(ciphertext)).decode()
    return result


# ═══════════════════════════════════════════════════════════════
#  NPVT1 FILE GENERATOR
# ═══════════════════════════════════════════════════════════════

def generate_npvt1(config_data, config_type='c', existing_uuid=None):
    """
    Generate a complete NPVT1 file content.
    
    Args:
        config_data: JSON config (string or dict)
        config_type: 'c' for Cloudflare, 'v' for WebSocket
        existing_uuid: Optional existing UUID (16 bytes)
    Returns:
        (NPVT1 file content as string, UUID string)
    """
    if isinstance(config_data, dict):
        config_data = json.dumps(config_data, separators=(',', ':'), ensure_ascii=False)
    
    # Load whitebox state
    p2, p3, p4, p5 = load_whitebox_state()
    
    # Generate UUID if not provided
    config_uuid = existing_uuid or uuid_mod.uuid4().bytes
    
    # Encrypt config data
    encrypted_b64 = npvt_encrypt(config_data, p2, p3, p4, p5)
    
    # Field 1: type byte (1) + UUID (16)
    field1 = bytes([ord(config_type)]) + config_uuid[:16]
    field1_b64 = base64.b64encode(field1).decode()
    
    # Field 2: encrypted config data (already base64)
    field2_b64 = encrypted_b64
    
    # Field 3: Signature (213 bytes)
    # The actual signature algorithm is unknown, so we use HMAC-SHA256
    # expanded/repeated to 213 bytes as a placeholder
    signer = hmac.new(
        config_uuid[:16],
        field1 + base64.b64decode(field2_b64),
        hashlib.sha256
    )
    sig = signer.digest()
    # Expand to 213 bytes
    field3 = (sig * (213 // len(sig) + 1))[:213]
    field3_b64 = base64.b64encode(field3).decode()
    
    # Build NPVT1 file
    content = f"NPVT1\n{field1_b64},{field2_b64},{field3_b64}\n"
    
    uuid_str = config_uuid.hex()
    uuid_formatted = f"{uuid_str[0:8]}-{uuid_str[8:12]}-{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:32]}"
    
    return content, uuid_formatted


# ═══════════════════════════════════════════════════════════════
#  EXAMPLE CONFIGS
# ═══════════════════════════════════════════════════════════════

def create_example_config(protocol='ssh'):
    """Create an example SSH config."""
    if protocol == 'ssh':
        return {
            "name": "My-Netninja-Server",
            "address": "your-server.com:443",
            "type": "SSH",
            "sshConfig": {
                "sshConfigType": "SSH-Proxy-Payload",
                "remarks": "My-Netninja-Server",
                "sshHost": "your-server.com",
                "sshPort": 443,
                "sshUsername": "username",
                "sshPassword": "password",
                "sni": "",
                "tlsVersion": "DEFAULT",
                "httpProxy": "",
                "authenticateProxy": False,
                "proxyUsername": "",
                "proxyPassword": "",
                "payload": (
                    "GET / HTTP/1.1[crlf]"
                    "Host: [host][crlf]"
                    "User-Agent: [ua][crlf]"
                    "Upgrade: websocket[crlf]"
                    "Connection: Keep-Alive[crlf][crlf]"
                ),
                "dnsTTMode": "UDP",
                "dnsServer": "",
                "nameserver": "",
                "publicKey": "",
                "udpgwPort": 7300,
                "udpgwTransparentDNS": True
            },
            "lockConfig": {
                "version": 1,
                "isLocked": False,
                "password": "",
                "onlyMobileNetwork": False,
                "blockRootedAndJailbroken": False,
                "onlyOfficialStores": False,
                "expiryDate": "",
                "deviceIds": "",
                "message": "",
                "customServerMessage": ""
            }
        }


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='NPVT Encoder - สร้างไฟล์ .npvt สำหรับ NPV TUNNEL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ตัวอย่าง:
  python npvt_encoder.py --generate server.npvt --example
  python npvt_encoder.py --generate server.npvt --config-file myconfig.json
  python npvt_encoder.py --generate server.npvt '{"name":"test","address":"host:443","type":"SSH","sshConfig":{"sshHost":"host"}}'
  python npvt_encoder.py --type v --generate ws_config.npvt --example
        """
    )
    
    parser.add_argument('--generate', metavar='OUTPUT.npvt', required=True,
                        help='สร้างไฟล์ .npvt')
    parser.add_argument('--config', nargs='?', const=None,
                        help='JSON config string')
    parser.add_argument('--config-file',
                        help='JSON config file path')
    parser.add_argument('--example', action='store_true',
                        help='สร้าง config ตัวอย่าง (แก้ไขค่าทีหลัง)')
    parser.add_argument('--type', '-t', default='c', choices=['c', 'v'],
                        help='ประเภท: c=Cloudflare, v=WebSocket')
    parser.add_argument('--info', action='store_true',
                        help='แสดงข้อมูลไฟล์ .npvt ที่มีอยู่')
    
    args = parser.parse_args()
    
    if not _WHITEBOX_LOADED:
        print("Error: NPVTUNNEL.py not found or whitebox state failed to load")
        sys.exit(1)
    
    # Load config data
    config_data = None
    
    if args.example:
        config_data = create_example_config()
        print("✓ สร้าง config ตัวอย่าง (แก้ไขค่าตามต้องการ)")
    elif args.config_file:
        with open(args.config_file, 'r') as f:
            content = f.read()
        try:
            config_data = json.loads(content)
        except:
            config_data = content
        print("✓ โหลด config จากไฟล์: %s" % args.config_file)
    elif args.config:
        try:
            config_data = json.loads(args.config)
        except:
            config_data = args.config
    else:
        print("Error: ต้องระบุ --config, --config-file หรือ --example")
        sys.exit(1)
    
    # Generate NPVT1 file
    content, uuid_str = generate_npvt1(config_data, config_type=args.type)
    
    # Save to file
    with open(args.generate, 'w') as f:
        f.write(content)
    
    print("\n✅ สร้างไฟล์สำเร็จ: %s" % args.generate)
    print("   UUID: %s" % uuid_str)
    print("   Type: '%s'" % args.type)
    print("\n📋 ขั้นตอนถัดไป:")
    print("   1. ส่งไฟล์ %s ไปยังโทรศัพท์" % args.generate)
    print("   2. เปิดแอป NPV TUNNEL")
    print("   3. กด + → Import Config → เลือกไฟล์")
    print("   4. แก้ไข SSH Host/Port/Username/Password")
    print("   5. Connect!")
    
    # Print config preview
    if isinstance(config_data, dict):
        print("\n📄 ตัวอย่าง config ที่สร้าง:")
        print(json.dumps(config_data, indent=2, ensure_ascii=False)[:500])


if __name__ == '__main__':
    main()
