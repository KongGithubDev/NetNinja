#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys

from NPVTUNNEL import load_whitebox_state, whitebox_encrypt_block


def npvt_encrypt(plaintext, p2, p3, p4, p5):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    iv = bytearray(os.urandom(16))
    original_iv = bytes(iv)
    ciphertext = bytearray()
    keystream = None
    for j in range(len(plaintext)):
        bo = j % 16
        if bo == 0:
            keystream = whitebox_encrypt_block(bytes(iv), p2, p3, p4, p5)
            for k in range(15, -1, -1):
                iv[k] = (iv[k] + 1) & 0xFF
                if iv[k] != 0:
                    break
        ciphertext.append(plaintext[j] ^ keystream[bo])
    return base64.b64encode(original_iv + bytes(ciphertext)).decode()


def npvt_decrypt(payload_b64, p2, p3, p4, p5):
    raw = list(base64.b64decode(payload_b64))
    iv = bytearray(raw[:16])
    ct = raw[16:]
    decrypted = bytearray()
    keystream = None
    for j in range(len(ct)):
        bo = j % 16
        if bo == 0:
            keystream = whitebox_encrypt_block(bytes(iv), p2, p3, p4, p5)
            for k in range(15, -1, -1):
                iv[k] = (iv[k] + 1) & 0xFF
                if iv[k] != 0:
                    break
        decrypted.append(ct[j] ^ keystream[bo])
    return decrypted.decode('utf-8')


def read_npvt(filepath):
    with open(filepath, 'r') as f:
        content = f.read().strip()
    lines = content.split('\n')
    version = lines[0].strip()
    fields = lines[1].split(',')
    return version, fields


def main():
    parser = argparse.ArgumentParser(description='Modify .npvt file, preserve UUID')
    parser.add_argument('input', help='ไฟล์ .npvt ต้นทาง')
    parser.add_argument('output', help='ไฟล์ .npvt ปลายทาง')
    parser.add_argument('--config', help='JSON config file')
    parser.add_argument('--set', nargs=2, action='append', metavar=('KEY', 'VALUE'),
                        help='เปลี่ยนค่าใน config เช่น --set sshHost my.host.com --set sshPort 443')
    parser.add_argument('--type', choices=['c', 'v'], help='ประเภท (c=CF, v=WS)')
    parser.add_argument('--show', action='store_true', help='แสดง config ปัจจุบัน')

    args = parser.parse_args()
    version, fields = read_npvt(args.input)
    f1 = base64.b64decode(fields[0])
    uuid = f1[1:17]
    orig_type = chr(f1[0])

    p2, p3, p4, p5 = load_whitebox_state()

    if args.config or args.set or args.show:
        if not args.config:
            decrypted = npvt_decrypt(fields[1], p2, p3, p4, p5)
            existing = json.loads(decrypted)
            if isinstance(existing, list):
                existing = existing[0]
        else:
            existing = {}

        if args.show:
            print(json.dumps(existing if not args.config else json.load(open(args.config)), indent=2, ensure_ascii=False))
            return

        if args.config:
            with open(args.config, 'r') as f:
                new_config = json.load(f)
        else:
            new_config = existing.copy()
            if args.set:
                for k, v in args.set:
                    parts = k.split('.')
                    obj = new_config
                    for p in parts[:-1]:
                        obj = obj.setdefault(p, {})
                    if v.lower() in ('true', 'false'):
                        v = v.lower() == 'true'
                    elif v.isdigit():
                        v = int(v)
                    elif v.startswith('"') and v.endswith('"'):
                        v = v[1:-1]
                    obj[parts[-1]] = v

        config_str = json.dumps(new_config, separators=(',', ':'), ensure_ascii=False)
        encrypted_b64 = npvt_encrypt(config_str, p2, p3, p4, p5)
    else:
        encrypted_b64 = fields[1]

    t = args.type or orig_type
    new_f1 = base64.b64encode(bytes([ord(t)]) + uuid).decode()
    signer = hmac.new(uuid, base64.b64decode(new_f1) + base64.b64decode(encrypted_b64), hashlib.sha256)
    new_f3 = base64.b64encode((signer.digest() * 14)[:213]).decode()

    result = f"NPVT1\n{new_f1},{encrypted_b64},{new_f3}\n"
    with open(args.output, 'w', newline='\n') as f:
        f.write(result)
    print("Saved: " + args.output)
    print("UUID: " + uuid.hex() + " (unchanged)")


if __name__ == '__main__':
    main()
