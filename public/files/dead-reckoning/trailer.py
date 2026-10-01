# SkyTrack-7 FDR trailer reader — the operator NOTE field (and its planted fake)
data = open('fdr.bin', 'rb').read()
tr = data[26 + 39 * 28:]          # 26-byte header + 39 28-byte entries
print('trailer len:', len(tr))
print(repr(tr))
