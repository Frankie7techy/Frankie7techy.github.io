#!/usr/bin/env python3
"""Dead Reckoning (SkyTrack-7 FDR) — ghost-entry filter via chain dead reckoning.

Reconstructs the true flight path from a corrupted flight data recorder log:
each entry is predicted from the LAST authentic fix using the spherical-Earth
DR formula, then accepted only if it lands inside the physics envelope.

Criteria (from the aircraft performance manual):
  - standard sample interval: 300 s, max deviation ±30 s per entry   (§4.5)
  - authentic fix predicts the next authentic fix with error < 1.0 km (§4.5)
  - accumulated DR position error over a 5-min cruise segment < 0.4 km (§4.3)
  - deviations beyond ~1.5 km are suspect                             (§4.5)
"""

import struct
import math

R = 6371.0          # spherical Earth radius (km) — manual §4.4
HEADER_SIZE = 26
ENTRY_SIZE = 28


def parse_fdr(path):
    with open(path, 'rb') as f:
        data = f.read()
    ver, = struct.unpack('>H', data[4:6])
    aircraft = data[6:14]
    base, = struct.unpack('>q', data[14:22])
    n, = struct.unpack('>I', data[22:26])
    print(f"magic {data[:4].hex()}  ver {ver}  id {aircraft}  base {base}  n {n}")

    entries = []
    for i in range(n):
        off = HEADER_SIZE + i * ENTRY_SIZE
        t, la, lo, alt, h10, spd, fl = struct.unpack('>iiiHHHH', data[off:off + 20])
        ie, = struct.unpack('>d', data[off + 20:off + 28])
        entries.append(dict(i=i, t=t, lat=la / 1e6, lon=lo / 1e6, alt=alt,
                            hdg=h10 / 10.0, spd=spd, gps=bool(fl & 1), ie=ie))
    return entries


def dr_predict(e0, dt):
    """Predict position after dt seconds flying heading/speed of fix e0 (manual §4.4)."""
    d = e0['spd'] * 1.852 * dt / 3600.0
    p1, l1 = math.radians(e0['lat']), math.radians(e0['lon'])
    th = math.radians(e0['hdg'])
    p2 = math.asin(math.sin(p1) * math.cos(d / R) + math.cos(p1) * math.sin(d / R) * math.cos(th))
    l2 = l1 + math.atan2(math.sin(th) * math.sin(d / R) * math.cos(p1),
                         math.cos(d / R) - math.sin(p1) * math.sin(p2))
    return math.degrees(p2), math.degrees(l2)


def dist_km(lat1, lon1, lat2, lon2):
    """Great-circle distance (spherical Earth, R = 6371 km)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def main():
    entries = parse_fdr('fdr.bin')

    # Sequential chain filtering: every candidate is predicted from the LAST
    # authentic fix — ghosts never pollute the reference track.
    authentic = [entries[0]]
    ghosts = []
    for e in entries[1:]:
        prev = authentic[-1]
        dt = e['t'] - prev['t']
        plat, plon = dr_predict(prev, dt)
        dev = dist_km(plat, plon, e['lat'], e['lon'])
        interval_ok = 270 <= dt <= 330          # 300 s ± 30 s
        ok = (dev <= 1.0) and interval_ok
        tag = 'AUTH' if ok else 'GHOST'
        print(f"{e['i']:3d} t={e['t']:6d} dt={dt:5d} pos=({e['lat']:9.4f},{e['lon']:9.4f}) "
              f"hdg={e['hdg']:6.1f} spd={e['spd']:3d} alt={e['alt']:5d} gps={int(e['gps'])} "
              f"ie={e['ie']:6.1f} dev={dev:8.2f}km {tag}")
        if ok:
            authentic.append(e)
        else:
            ghosts.append(e)

    print()
    print(f"total={len(entries)} authentic={len(authentic)} ghosts={len(ghosts)}")
    print("ghost indices:", [g['i'] for g in ghosts])


if __name__ == '__main__':
    main()
