#!/usr/bin/env python3
"""Rewrite an lpatch delta (.lpd) so it builds a new result from the same stock source.

usage: retarget-delta.py <in.lpd> <old result> <new result> <out.lpd>

<old result> is what <in.lpd> builds now, <new result> the file it should build
instead; both must be the same size (an in-place edit, e.g. a few bytecode
bytes plus the dex header). The stock source is not needed: each output byte is
either an `extra` byte (replaced) or a `diff` byte added to a source byte (the
difference is added to the diff byte). The new delta is checked against the old
one on a stand-in source: their outputs must differ exactly where the two
results differ.
"""
import hashlib, struct, sys, zlib

def unpack(d):
    if d[:4] != b'LPD1':
        sys.exit('not an lpatch delta')
    comp, plen = struct.unpack('<II', d[44:52])
    body = zlib.decompress(d[52:52 + plen], -15) if comp == 1 else d[52:52 + plen]
    n = struct.unpack('<I', body[:4])[0]; p = 4
    ctrl = [struct.unpack('<iii', body[p + 12*i:p + 12*i + 12]) for i in range(n)]; p += 12 * n
    dl = struct.unpack('<I', body[p:p+4])[0]; diff = bytearray(body[p+4:p+4+dl]); p += 4 + dl
    el = struct.unpack('<I', body[p:p+4])[0]; extra = bytearray(body[p+4:p+4+el])
    return ctrl, diff, extra

def pack(hdr, ctrl, diff, extra, out_md5):
    body = struct.pack('<I', len(ctrl)) + b''.join(struct.pack('<iii', *c) for c in ctrl)
    body += struct.pack('<I', len(diff)) + bytes(diff) + struct.pack('<I', len(extra)) + bytes(extra)
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    payload = c.compress(body) + c.flush()
    return hdr[:28] + out_md5 + struct.pack('<II', 1, len(payload)) + payload

def apply(src, ctrl, diff, extra):
    out = bytearray(); op = dp = ep = 0
    for x, y, z in ctrl:
        for k in range(x):
            v = diff[dp + k]; o = op + k
            if 0 <= o < len(src): v = (v + src[o]) & 255
            out.append(v)
        op += x; dp += x
        out += extra[ep:ep + y]; ep += y; op += z
    return bytes(out)

def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    d = open(sys.argv[1], 'rb').read()
    old, new = open(sys.argv[2], 'rb').read(), open(sys.argv[3], 'rb').read()
    srclen, outlen = struct.unpack('<I', d[4:8])[0], struct.unpack('<I', d[24:28])[0]
    if d[28:44] != hashlib.md5(old).digest() or len(old) != outlen:
        sys.exit('the delta does not build <old result>')
    if len(new) != len(old):
        sys.exit('<new result> must be the same size as <old result>')
    ctrl, diff, extra = unpack(d)
    ndiff, nextra = bytearray(diff), bytearray(extra)
    pos = dp = ep = 0
    for x, y, z in ctrl:
        for k in range(x):
            if old[pos + k] != new[pos + k]:
                ndiff[dp + k] = (ndiff[dp + k] + new[pos + k] - old[pos + k]) & 255
        pos += x; dp += x
        for k in range(y):
            if old[pos + k] != new[pos + k]:
                nextra[ep + k] = new[pos + k]
        pos += y; ep += y
    if pos != outlen:
        sys.exit('delta control does not cover the result')
    stand_in = bytes((i * 131 + 7) & 255 for i in range(srclen))
    a, b = apply(stand_in, ctrl, diff, extra), apply(stand_in, ctrl, ndiff, nextra)
    for i in range(outlen):
        if (b[i] - a[i]) & 255 != (new[i] - old[i]) & 255:
            sys.exit('self-check failed at %d' % i)
    out = pack(d, ctrl, ndiff, nextra, hashlib.md5(new).digest())
    if unpack(out) != (ctrl, ndiff, nextra):
        sys.exit('self-check failed: repacked delta differs')
    open(sys.argv[4], 'wb').write(out)
    print('%s  %d bytes (result md5 %s, %d bytes changed)' % (
        sys.argv[4], len(out), hashlib.md5(new).hexdigest(), sum(1 for i in range(outlen) if old[i] != new[i])))

if __name__ == '__main__':
    main()
