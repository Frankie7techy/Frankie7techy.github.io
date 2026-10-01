"""Reconstruct the exfiltrated file from base64-encoded DNS query names."""
import base64
import struct
import zipfile
import io

PCAP_PATH = r"C:\Users\frank\Downloads\chall.pcap"


def read_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels)


def main():
    with open(PCAP_PATH, "rb") as f:
        raw = f.read()

    magic = raw[:4]
    endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    offset = 24
    chunks = []

    while offset + 16 <= len(raw):
        _, _, incl_len, _ = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        offset += 16
        pkt = raw[offset:offset + incl_len]
        offset += incl_len
        if len(pkt) < 14 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
            continue
        ip = pkt[14:]
        if len(ip) < 20 or ip[9] != 17:
            continue
        udp = ip[(ip[0] & 0x0F) * 4:]
        if len(udp) < 8:
            continue
        src_port, dst_port, udp_len, _ = struct.unpack(">HHHH", udp[:8])
        if dst_port != 53:
            continue  # only queries (client -> server), in packet order
        dns = udp[8:udp_len]
        if len(dns) < 12:
            continue
        qd = struct.unpack(">H", dns[4:6])[0]
        if qd < 1:
            continue
        name = read_name(dns, 12)
        # strip the exfil domain, rejoin remaining base64 labels
        if name.endswith(".hackerman.com"):
            b64 = name[: -len(".hackerman.com")].replace(".", "")
            chunks.append(b64)

    payload = base64.b64decode("".join(chunks))
    print(f"Reassembled {len(payload)} bytes")
    print("First bytes:", payload[:16])

    zf = zipfile.ZipFile(io.BytesIO(payload))
    for info in zf.infolist():
        print(f"\n=== {info.filename} ({info.file_size} bytes) ===")
        print(zf.read(info.filename).decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
