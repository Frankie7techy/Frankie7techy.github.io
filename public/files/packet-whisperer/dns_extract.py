"""Extract DNS queries/responses from a pcap file (classic pcap format)."""
import struct
import sys
import base64

PCAP_PATH = r"C:\Users\frank\Downloads\chall.pcap"


def read_name(data, offset, depth=0):
    """Read a DNS name starting at offset. Returns (name, new_offset)."""
    if depth > 20:
        return "<loop>", offset
    labels = []
    jumped = False
    orig_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            pointed, _ = read_name(data, ptr, depth + 1)
            labels.append(pointed)
            offset += 2
            jumped = True
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("latin-1"))
            offset += length
    return ".".join(labels), offset


def parse_dns(data):
    """Parse a DNS message, return list of (direction, name, type, extra)."""
    results = []
    if len(data) < 12:
        return results
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    qr = (flags >> 15) & 1
    offset = 12

    qtype_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
                 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}

    for _ in range(qd):
        name, offset = read_name(data, offset)
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        results.append(("Q", name, qtype_map.get(qtype, str(qtype)), ""))

    for _ in range(an):
        name, offset = read_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        tname = qtype_map.get(rtype, str(rtype))
        if rtype == 1 and rdlen == 4:
            extra = ".".join(str(b) for b in rdata)
        elif rtype == 16:  # TXT
            txts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                txts.append(rdata[i + 1:i + 1 + ln].decode("latin-1"))
                i += 1 + ln
            extra = " ".join(txts)
        elif rtype in (2, 5, 12):
            extra, _ = read_name(data, offset - rdlen)
        else:
            extra = rdata.hex()
        results.append(("R" if qr else "Q", name, tname, extra))

    return results


def main():
    with open(PCAP_PATH, "rb") as f:
        raw = f.read()

    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    else:
        print("Unknown magic:", magic.hex())
        return

    offset = 24
    pkt_num = 0
    dns_count = 0
    while offset + 16 <= len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        offset += 16
        pkt = raw[offset:offset + incl_len]
        offset += incl_len
        pkt_num += 1

        # Ethernet (14 bytes) - check ethertype
        if len(pkt) < 14:
            continue
        ethertype = struct.unpack(">H", pkt[12:14])[0]
        if ethertype != 0x0800:  # IPv4
            continue
        ip = pkt[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        if proto != 17:  # UDP
            continue
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        src_port, dst_port, udp_len, _ = struct.unpack(">HHHH", udp[:8])
        if src_port != 53 and dst_port != 53:
            continue
        dns_payload = udp[8:udp_len]
        direction = "->" if dst_port == 53 else "<-"
        for direction_kind, name, rtype, extra in parse_dns(dns_payload):
            dns_count += 1
            print(f"pkt#{pkt_num} {direction} [{direction_kind}] {name}  {rtype}  {extra}")

    print(f"\nTotal packets: {pkt_num}, DNS entries: {dns_count}")


if __name__ == "__main__":
    main()
