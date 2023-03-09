// Curve25519 signatures (and also key agreement)
// like in the early Axolotl.
//
// Ported to Go by Miguel Sandro Lucero. miguel.sandro@gmail.com. 2017.11.03
// You can use it under MIT or CC0 license.
//
// Curve25519 signatures idea and math by Trevor Perrin
// https://moderncrypto.org/mail-archive/curves/2014/000205.html
//
// Derived from axlsign.js written by Dmitry Chestnykh. https://github.com/wavesplatform/curve25519-js

// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';

import 'constants.dart';

// var _0 = List<int>.filled(16, 0);

int _ushr(int v) {
  int re = v.toUnsigned(32);
  return re;
}

Uint8List _ts64(Uint8List x, int i, int h, int l) {
  x[i] = ((h >> 24) & 0xff).toUnsigned(8);
  x[i + 1] = ((h >> 16) & 0xff).toUnsigned(8);
  x[i + 2] = ((h >> 8) & 0xff).toUnsigned(8);
  x[i + 3] = (h & 0xff).toUnsigned(8);
  x[i + 4] = ((l >> 24) & 0xff).toUnsigned(8);
  x[i + 5] = ((l >> 16) & 0xff).toUnsigned(8);
  x[i + 6] = ((l >> 8) & 0xff).toUnsigned(8);
  x[i + 7] = (l & 0xff).toUnsigned(8);
  return x;
}

int _vn(Uint8List x, int xi, Uint8List y, int yi, int n) {
  int d = 0;
  for (var i = 0; i < n; i++) {
    d = d | (x[xi + i] ^ y[yi + i]);
  }
  return ((1 & (_ushr(d - 1) >> 8)) - 1);
}

int _cryptoVerify_32(Uint8List x, int xi, Uint8List y, int yi) {
  return _vn(x, xi, y, yi, 32);
}

List<int> _set25519(List<int> a) {
  List<int> r = List<int>.filled(16, 0);
  for (var i = 0; i < 16; i++) {
    r[i] = a[i] | 0;
  }
  return r;
}

List<int> _car25519(List<int> o) {
  int v;
  var c = 1;
  for (var i = 0; i < 16; i++) {
    v = o[i] + c + 65535;
    c = (v / 65536.0).floor();
    o[i] = v - (c * 65536);
  }
  o[0] += (c - 1 + 37 * (c - 1));
  return o;
}

void _sel25519(List<int> p, List<int> q, int b) {
  int t;
  var c = 0xffffffffffffffff ^ (b - 1);
  for (var i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] = p[i] ^ t;
    q[i] = q[i] ^ t;
  }
}

Uint8List _pack25519(Uint8List o, List<int> n) {
  int b;
  var m = gf(null);
  var t = gf(null);

  for (var i = 0; i < 16; i++) {
    t[i] = n[i];
  }
  _car25519(t);
  _car25519(t);
  _car25519(t);

  for (var c = 0; c < 2; c++) {
    m[0] = t[0] - 0xffed;
    for (var i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] = m[i - 1] & 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] = m[14] & 0xffff;
    _sel25519(t, m, (1 - b));
  }

  for (var i = 0; i < 16; i++) {
    o[2 * i] = (t[i] & 0xff);
    o[2 * i + 1] = (t[i] >> 8);
  }
  return o;
}

int _neq25519(List<int> a, List<int> b) {
  var c = Uint8List(32);
  var d = Uint8List(32);
  _pack25519(c, a);
  _pack25519(d, b);
  return _cryptoVerify_32(c, 0, d, 0);
}

int _par25519(List<int> a) {
  var d = Uint8List(32);
  _pack25519(d, a);
  return (d[0]) & 1;
}

List<int> _unpack25519(List<int> o, Uint8List n) {
  for (var i = 0; i < 16; i++) {
    o[i] = (n[2 * i]) + ((n[2 * i + 1]) << 8);
  }
  o[15] = o[15] & 0x7fff;
  return o;
}

List<int> _A(List<int> o, List<int> a, List<int> b) {
  for (var i = 0; i < 16; i++) {
    o[i] = a[i] + b[i];
  }
  return o;
}

List<int> _Z(List<int> o, List<int> a, List<int> b) {
  for (var i = 0; i < 16; i++) {
    o[i] = a[i] - b[i];
  }
  return o;
}

// optimized by Miguel
List<int> _M(List<int> o, List<int> a, List<int> b) {
  var at = List<int>.filled(32, 0);
  var ab = List<int>.filled(16, 0);

  for (var i = 0; i < 16; i++) {
    ab[i] = b[i];
  }

  int v;
  for (var i = 0; i < 16; i++) {
    v = a[i];
    for (var j = 0; j < 16; j++) {
      at[j + i] += v * ab[j];
    }
  }

  for (var i = 0; i < 15; i++) {
    at[i] += 38 * at[i + 16];
  }
  // t15 left as is

  // first car
  int c = 1;
  for (var i = 0; i < 16; i++) {
    v = at[i] + c + 65535;
    c = ((v) / 65536.0).floor();
    at[i] = v - c * 65536;
  }
  at[0] += c - 1 + 37 * (c - 1);

  // second car
  c = 1;
  for (var i = 0; i < 16; i++) {
    v = at[i] + c + 65535;
    c = (((v) / 65536.0).floor());
    at[i] = v - c * 65536;
  }
  at[0] += c - 1 + 37 * (c - 1);

  for (var i = 0; i < 16; i++) {
    o[i] = at[i];
  }
  return o;
}

List<int> _S(List<int> o, List<int> a) {
  return _M(o, a, a);
}

List<int> _inv25519(List<int> o, List<int> i) {
  var c = gf(null);
  for (var a = 0; a < 16; a++) {
    c[a] = i[a];
  }

  for (var a = 253; a >= 0; a--) {
    _S(c, c);
    if (a != 2 && a != 4) {
      _M(c, c, i);
    }
  }
  for (var a = 0; a < 16; a++) {
    o[a] = c[a];
  }
  return o;
}

List<int> _pow2523(List<int> o, List<int> i) {
  var c = gf(null);
  for (var a = 0; a < 16; a++) {
    c[a] = i[a];
  }
  for (var a = 250; a >= 0; a--) {
    _S(c, c);
    if (a != 1) {
      _M(c, c, i);
    }
  }
  for (var a = 0; a < 16; a++) {
    o[a] = c[a];
  }
  return o;
}

int _cryptoScalarmult(Uint8List q, Uint8List n, Uint8List p) {
  var z = Uint8List(32);
  var x = List<int>.filled(80, 0);
  int r;

  var a = gf(null);
  var b = gf(null);
  var c = gf(null);
  var d = gf(null);
  var e = gf(null);
  var f = gf(null);

  for (var i = 0; i < 31; i++) {
    z[i] = n[i];
  }
  z[31] = (n[31] & 127) | 64;
  z[0] = z[0] & 248;

  _unpack25519(x, p);

  for (var i = 0; i < 16; i++) {
    b[i] = x[i];
    d[i] = 0;
    a[i] = 0;
    c[i] = 0;
  }
  a[0] = 1;
  d[0] = 1;

  for (var i = 254; i >= 0; i--) {
    r = (((z[i >> (3)]) >> (i & 7).toUnsigned(64)) & 1);

    _sel25519(a, b, r);
    _sel25519(c, d, r);

    _A(e, a, c);
    _Z(a, a, c);
    _A(c, b, d);
    _Z(b, b, d);
    _S(d, e);
    _S(f, a);
    _M(a, c, a);
    _M(c, b, e);
    _A(e, a, c);
    _Z(a, a, c);
    _S(b, a);
    _Z(c, d, f);

    _M(a, c, under121665);
    _A(a, a, d);
    _M(c, c, a);
    _M(a, d, f);
    _M(d, b, x);
    _S(b, e);

    _sel25519(a, b, r);
    _sel25519(c, d, r);
  }

  for (var i = 0; i < 16; i++) {
    x[i + 16] = a[i];
    x[i + 32] = c[i];
    x[i + 48] = b[i];
    x[i + 64] = d[i];
  }

  var x32 = x.sublist(32);
  var x16 = x.sublist(16);

  _inv25519(x32, x32);

  _M(x16, x16, x32);

  _pack25519(q, x16);

  return 0;
}

int _cryptoScalarmultBase(Uint8List q, Uint8List n) {
  return _cryptoScalarmult(q, n, under9);
}

// optimized by miguel
int _cryptoHashblocksHl(List<int> hh, List<int> hl, Uint8List m, int n) {
  var wh = List<int>.filled(16, 0);
  var wl = List<int>.filled(16, 0);

  var bh = List<int>.filled(8, 0);
  var bl = List<int>.filled(8, 0);

  int th;
  int tl;
  int h;
  int l;
  int a;
  int b;
  int c;
  int d;

  var ah = List<int>.filled(8, 0);
  var al = List<int>.filled(8, 0);
  for (var i = 0; i < 8; i++) {
    ah[i] = hh[i];
    al[i] = hl[i];
  }

  var pos = 0;
  while (n >= 128) {
    for (var i = 0; i < 16; i++) {
      var j = 8 * i + pos;
      wh[i] = ((m[j + 0]) << 24) |
          ((m[j + 1]) << 16) |
          ((m[j + 2]) << 8) |
          (m[j + 3]);
      wl[i] = ((m[j + 4]) << 24) |
          ((m[j + 5]) << 16) |
          ((m[j + 6]) << 8) |
          (m[j + 7]);
    }

    for (var i = 0; i < 80; i++) {
      for (var j = 0; j < 7; j++) {
        bh[j] = ah[j];
        bl[j] = al[j];
      }

      // add
      h = ah[7];
      l = al[7];

      a = l & 0xffff;
      b = _ushr(l) >> 16;
      c = h & 0xffff;
      d = _ushr(h) >> 16;

      // Sigma1
      h = ((_ushr(ah[4]) >> 14) | (al[4] << (32 - 14))) ^
          ((_ushr(ah[4]) >> 18) | (al[4] << (32 - 18))) ^
          ((_ushr(al[4]) >> (41 - 32)) | (ah[4] << (32 - (41 - 32))));
      l = ((_ushr(al[4]) >> 14) | (ah[4] << (32 - 14))) ^
          ((_ushr(al[4]) >> 18) | (ah[4] << (32 - 18))) ^
          ((_ushr(ah[4]) >> (41 - 32)) | (al[4] << (32 - (41 - 32))));

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      // Ch
      h = (ah[4] & ah[5]) ^ ((0xffffffffffffffff ^ ah[4]) & ah[6]);
      l = (al[4] & al[5]) ^ ((0xffffffffffffffff ^ al[4]) & al[6]);

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      // K
      h = K[i * 2].toSigned(32);
      l = K[i * 2 + 1].toSigned(32);

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      // w
      h = wh[i % 16];
      l = wl[i % 16];

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      b += _ushr(a) >> 16;
      c += _ushr(b) >> 16;
      d += _ushr(c) >> 16;

      // *** R
      // th = c & 0xffff | ( d << 16 )
      // tl = a & 0xffff | ( b << 16 )
      th = c & 0xffff | d << 16;
      tl = a & 0xffff | b << 16;

      // add
      h = th;
      l = tl;

      a = l & 0xffff;
      b = _ushr(l) >> 16;
      c = h & 0xffff;
      d = _ushr(h) >> 16;

      // Sigma0
      h = ((_ushr(ah[0]) >> 28) | (al[0] << (32 - 28))) ^
          ((_ushr(al[0]) >> (34 - 32)) | (ah[0] << (32 - (34 - 32)))) ^
          ((_ushr(al[0]) >> (39 - 32)) | (ah[0] << (32 - (39 - 32))));
      l = ((_ushr(al[0]) >> 28) | (ah[0] << (32 - 28))) ^
          ((_ushr(ah[0]) >> (34 - 32)) | (al[0] << (32 - (34 - 32)))) ^
          ((_ushr(ah[0]) >> (39 - 32)) | (al[0] << (32 - (39 - 32))));

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      // Maj
      h = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
      l = (al[0] & al[1]) ^ (al[0] & al[2]) ^ (al[1] & al[2]);

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      b += _ushr(a) >> 16;
      c += _ushr(b) >> 16;
      d += _ushr(c) >> 16;

      bh[7] = (c & 0xffff) | (d << 16);
      bl[7] = (a & 0xffff) | (b << 16);

      // add
      h = bh[3];
      l = bl[3];

      a = l & 0xffff;
      b = _ushr(l) >> 16;
      c = h & 0xffff;
      d = _ushr(h) >> 16;

      h = th;
      l = tl;

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      b += _ushr(a) >> 16;
      c += _ushr(b) >> 16;
      d += _ushr(c) >> 16;

      bh[3] = (c & 0xffff) | (d << 16);
      bl[3] = (a & 0xffff) | (b << 16);

      for (var j = 0; j < 8; j++) {
        var k = (j + 1) % 8;
        ah[k] = bh[j];
        al[k] = bl[j];
      }

      if (i % 16 == 15) {
        for (var j = 0; j < 16; j++) {
          // add
          h = wh[j];
          l = wl[j];

          a = l & 0xffff;
          b = _ushr(l) >> 16;
          c = h & 0xffff;
          d = _ushr(h) >> 16;

          h = wh[(j + 9) % 16];
          l = wl[(j + 9) % 16];

          a += l & 0xffff;
          b += _ushr(l) >> 16;
          c += h & 0xffff;
          d += _ushr(h) >> 16;

          // sigma0
          th = wh[(j + 1) % 16];
          tl = wl[(j + 1) % 16];

          h = ((_ushr(th) >> 1) | (tl << (32 - 1))) ^
              ((_ushr(th) >> 8) | (tl << (32 - 8))) ^
              (_ushr(th) >> 7);
          l = ((_ushr(tl) >> 1) | (th << (32 - 1))) ^
              ((_ushr(tl) >> 8) | (th << (32 - 8))) ^
              ((_ushr(tl) >> 7) | (th << (32 - 7)));

          a += l & 0xffff;
          b += _ushr(l) >> 16;
          c += h & 0xffff;
          d += _ushr(h) >> 16;

          // sigma1
          th = wh[(j + 14) % 16];
          tl = wl[(j + 14) % 16];

          h = ((_ushr(th) >> 19) | (tl << (32 - 19))) ^
              ((_ushr(tl) >> (61 - 32)) | (th << (32 - (61 - 32)))) ^
              (_ushr(th) >> 6);
          l = ((_ushr(tl) >> 19) | (th << (32 - 19))) ^
              ((_ushr(th) >> (61 - 32)) | (tl << (32 - (61 - 32)))) ^
              ((_ushr(tl) >> 6) | (th << (32 - 6)));

          a += l & 0xffff;
          b += _ushr(l) >> 16;
          c += h & 0xffff;
          d += _ushr(h) >> 16;

          b += _ushr(a) >> 16;
          c += _ushr(b) >> 16;
          d += _ushr(c) >> 16;

          wh[j] = ((c & 0xffff) | (d << 16));
          wl[j] = ((a & 0xffff) | (b << 16));
        }
      }
    }

    // add
    a = 0;
    b = 0;
    c = 0;
    d = 0;
    for (var k = 0; k < 8; k++) {
      if (k == 0) {
        h = ah[0];
        l = al[0];
        a = l & 0xffff;
        b = _ushr(l) >> 16;
        c = h & 0xffff;
        d = _ushr(h) >> 16;
      }

      h = hh[k];
      l = hl[k];

      a += l & 0xffff;
      b += _ushr(l) >> 16;
      c += h & 0xffff;
      d += _ushr(h) >> 16;

      b += _ushr(a) >> 16;
      c += _ushr(b) >> 16;
      d += _ushr(c) >> 16;

      hh[k] = (c & 0xffff) | (d << 16);
      ah[k] = (c & 0xffff) | (d << 16);

      hl[k] = (a & 0xffff) | (b << 16);
      al[k] = (a & 0xffff) | (b << 16);

      if (k < 7) {
        h = ah[k + 1];
        l = al[k + 1];

        a = l & 0xffff;
        b = _ushr(l) >> 16;
        c = h & 0xffff;
        d = _ushr(h) >> 16;
      }
    }

    pos += 128;
    n -= 128;
  }

  return n;
}

List<int> _toIntArray(List<int> o) {
  var v = List<int>.filled(o.length, 0);
  for (var i = 0; i < (o.length); i++) {
    v[i] = ((o[i].toSigned(32)));
    // v[i] = int( o[i] )
  }
  return v;
}

int _cryptoHash(Uint8List out, Uint8List m, int n) {
  var hh = _toIntArray(HH);
  var hl = _toIntArray(HL);
  var x = Uint8List(256);
  var b = n;

  _cryptoHashblocksHl(hh, hl, m, n);

  n %= 128;

  for (var i = 0; i < n; i++) {
    x[i] = m[b - n + i];
  }
  x[n] = 128;

  if (n < 112) {
    n = 256 - 128 * 1;
  } else {
    n = 256 - 128 * 0;
  }
  x[n - 9] = 0;

  _ts64(x, n - 8, (b ~/ 0x20000000 | 0), (b << 3));

  _cryptoHashblocksHl(hh, hl, x, n);

  for (var i = 0; i < 8; i++) {
    _ts64(out, 8 * i, hh[i], hl[i]);
  }

  return 0;
}

void _add(List<List<int>> p, List<List<int>> q) {
  var a = gf(null);
  var b = gf(null);
  var c = gf(null);
  var d = gf(null);
  var e = gf(null);
  var f = gf(null);
  var g = gf(null);
  var h = gf(null);
  var t = gf(null);

  _Z(a, p[1], p[0]);
  _Z(t, q[1], q[0]);
  _M(a, a, t);
  _A(b, p[0], p[1]);
  _A(t, q[0], q[1]);
  _M(b, b, t);
  _M(c, p[3], q[3]);
  _M(c, c, D2);
  _M(d, p[2], q[2]);
  _A(d, d, d);
  _Z(e, b, a);
  _Z(f, d, c);
  _A(g, d, c);
  _A(h, b, a);

  _M(p[0], e, f);
  _M(p[1], h, g);
  _M(p[2], g, f);
  _M(p[3], e, h);
}

void _cswap(List<List<int>> p, List<List<int>> q, int b) {
  for (var i = 0; i < 4; i++) {
    _sel25519(p[i], q[i], b);
  }
}

void _pack(Uint8List r, List<List<int>> p) {
  var tx = gf(null);
  var ty = gf(null);
  var zi = gf(null);

  _inv25519(zi, p[2]);

  _M(tx, p[0], zi);
  _M(ty, p[1], zi);

  _pack25519(r, ty);

  r[31] = r[31] ^ (_par25519(tx) << 7);
}

void _scalarmult(List<List<int>> p, List<List<int>> q, Uint8List s) {
  int b;

  p[0] = _set25519(gf0);
  p[1] = _set25519(gf1);
  p[2] = _set25519(gf1);
  p[3] = _set25519(gf0);

  for (var i = 255; i >= 0; i--) {
    b = (s[(i ~/ 8) | 0] >> (i & 7)) & 1;
    _cswap(p, q, b);
    _add(q, p);
    _add(p, p);
    _cswap(p, q, b);
  }
}

void _scalarbase(List<List<int>> p, Uint8List s) {
  var q = [gf(null), gf(null), gf(null), gf(null)];
  q[0] = _set25519(X);
  q[1] = _set25519(Y);
  q[2] = _set25519(gf1);
  _M(q[3], X, Y);
  _scalarmult(p, q, s);
}

void _modL(Uint8List r, List<int> x) {
  int carry;

  for (var i = 63; i >= 32; i--) {
    carry = 0;
    var j = i - 32;
    var k = i - 12;
    while (j < k) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry * 256;
      j += 1;
    }
    x[j] += carry;
    x[i] = 0;
  }

  carry = 0;
  for (var j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] = x[j] & 255;
  }

  for (var j = 0; j < 32; j++) {
    x[j] -= carry * L[j];
  }

  for (var i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    r[i] = (x[i] & 255).toUnsigned(8);
  }
}

void _reduce(Uint8List r) {
  var x = List<int>.filled(64, 0);
  for (var i = 0; i < 64; i++) {
    x[i] = (r[i]);
  }
  for (var i = 0; i < 64; i++) {
    r[i] = 0;
  }
  _modL(r, x);
}

// Like crypto_sign, but uses secret key directly in hash.
int _cryptoSignDirect(Uint8List sm, Uint8List m, int n, Uint8List sk) {
  var h = Uint8List(64);
  var r = Uint8List(64);
  var x = List<int>.filled(64, 0);
  var p = [gf(null), gf(null), gf(null), gf(null)];

  for (var i = 0; i < n; i++) {
    sm[64 + i] = m[i];
  }

  for (var i = 0; i < 32; i++) {
    sm[32 + i] = sk[i];
  }

  _cryptoHash(r, sm.sublist(32), n + 32);

  _reduce(r);

  _scalarbase(p, r);

  _pack(sm, p);

  for (var i = 0; i < 32; i++) {
    sm[i + 32] = sk[32 + i];
  }

  _cryptoHash(h, sm, n + 64);
  _reduce(h);

  for (var i = 0; i < 64; i++) {
    x[i] = 0;
  }

  for (var i = 0; i < 32; i++) {
    x[i] = (r[i]);
  }

  for (var i = 0; i < 32; i++) {
    for (var j = 0; j < 32; j++) {
      x[i + j] += (h[i]) * (sk[j]);
    }
  }

  var tmp = sm.sublist(32);
  _modL(tmp, x);
  for (var i = 0; i < tmp.length; i++) {
    sm[32 + i] = tmp[i];
  }

  return n + 64;
}

// Note: sm must be n+128.
int _cryptoSignDirectRnd(
    Uint8List sm, Uint8List m, int n, Uint8List sk, Uint8List rnd) {
  var h = Uint8List(64);
  var r = Uint8List(64);
  var x = List<int>.filled(64, 0);
  var p = [gf(null), gf(null), gf(null), gf(null)];

  // Hash separation.
  sm[0] = 0xfe;
  for (var i = 1; i < 32; i++) {
    sm[i] = 0xff;
  }

  // Secret key.
  for (var i = 0; i < 32; i++) {
    sm[32 + i] = sk[i];
  }

  // Message.
  for (var i = 0; i < n; i++) {
    sm[64 + i] = m[i];
  }

  // Random suffix.
  for (var i = 0; i < 64; i++) {
    sm[n + 64 + i] = rnd[i];
  }

  _cryptoHash(r, sm, n + 128);

  _reduce(r);
  _scalarbase(p, r);
  _pack(sm, p);

  for (var i = 0; i < 32; i++) {
    sm[i + 32] = sk[32 + i];
  }

  _cryptoHash(h, sm, n + 64);
  _reduce(h);

  // Wipe out random suffix.
  for (var i = 0; i < 64; i++) {
    sm[n + 64 + i] = 0;
  }

  for (var i = 0; i < 64; i++) {
    x[i] = 0;
  }

  for (var i = 0; i < 32; i++) {
    x[i] = (r[i]);
  }

  for (var i = 0; i < 32; i++) {
    for (var j = 0; j < 32; j++) {
      x[i + j] += (h[i]) * (sk[j]);
    }
  }

  var tmp = sm.sublist(32);
  _modL(tmp, x);
  for (var i = 0; i < tmp.length; i++) {
    sm[32 + i] = tmp[i];
  }

  return n + 64;
}

int _curve25519Sign(
    Uint8List sm, Uint8List m, int n, Uint8List sk, Uint8List? optRnd) {
  // If opt_rnd is provided, sm must have n + 128,
  // otherwise it must have n + 64 bytes.

  // Convert Curve25519 secret key into Ed25519 secret key (includes pub key).
  var edsk = Uint8List(64);
  var p = [gf(null), gf(null), gf(null), gf(null)];

  for (var i = 0; i < 32; i++) {
    edsk[i] = sk[i];
  }

  // Ensure key is in the correct format.
  edsk[0] = edsk[0] & 248;
  edsk[31] = edsk[31] & 127;
  edsk[31] = edsk[31] | 64;

  _scalarbase(p, edsk);

  var tmp = edsk.sublist(32);
  _pack(tmp, p);
  for (var i = 0; i < tmp.length; i++) {
    edsk[32 + i] = tmp[i];
  }

  // Remember sign bit.
  var signBit = edsk[63] & 128;
  int smlen;

  if (optRnd == null || optRnd.isEmpty) {
    smlen = _cryptoSignDirect(sm, m, n, edsk);
  } else {
    smlen = _cryptoSignDirectRnd(sm, m, n, edsk, optRnd);
  }

  // Copy sign bit from public key into signature.
  sm[63] = sm[63] | signBit;

  return smlen;
}

int _unpackneg(List<List<int>> r, Uint8List p) {
  var t = gf(null);
  var chk = gf(null);
  var num = gf(null);
  var den = gf(null);
  var den2 = gf(null);
  var den4 = gf(null);
  var den6 = gf(null);

  r[2] = _set25519(gf1);
  r[1] = _unpack25519(r[1], p);

  _S(num, r[1]);
  _M(den, num, D);
  _Z(num, num, r[2]);
  _A(den, r[2], den);

  _S(den2, den);
  _S(den4, den2);
  _M(den6, den4, den2);
  _M(t, den6, num);
  _M(t, t, den);

  _pow2523(t, t);
  _M(t, t, num);
  _M(t, t, den);
  _M(t, t, den);
  _M(r[0], t, den);

  _S(chk, r[0]);
  _M(chk, chk, den);

  if (_neq25519(chk, num) != 0) {
    _M(r[0], r[0], I);
  }

  _S(chk, r[0]);
  _M(chk, chk, den);

  if (_neq25519(chk, num) != 0) {
    return -1;
  }

  if (_par25519(r[0]) == ((p[31]) >> 7)) {
    _Z(r[0], gf0, r[0]);
  }

  _M(r[3], r[0], r[1]);

  return 0;
}

int _cryptoSignOpen(Uint8List m, Uint8List sm, int n, Uint8List pk) {
  var t = Uint8List(32);
  var h = Uint8List(64);
  var p = [gf(null), gf(null), gf(null), gf(null)];
  var q = [gf(null), gf(null), gf(null), gf(null)];

  var mlen = -1;
  if (n < 64) {
    return mlen;
  }

  if (_unpackneg(q, pk) != 0) {
    return mlen;
  }

  for (var i = 0; i < n; i++) {
    m[i] = sm[i];
  }

  for (var i = 0; i < 32; i++) {
    m[i + 32] = pk[i];
  }

  _cryptoHash(h, m, n);

  _reduce(h);
  _scalarmult(p, q, h);

  _scalarbase(q, sm.sublist(32));
  _add(p, q);
  _pack(t, p);

  n -= 64;
  if (_cryptoVerify_32(sm, 0, t, 0) != 0) {
    for (var i = 0; i < n; i++) {
      m[i] = 0;
    }
    return -1;
  }

  for (var i = 0; i < n; i++) {
    m[i] = sm[i + 64];
  }

  mlen = n;
  return mlen;
}

// Converts Curve25519 public key back to Ed25519 public key.
// edwardsY = (montgomeryX - 1) / (montgomeryX + 1)
Uint8List _convertPublicKey(Uint8List pk) {
  var z = Uint8List(32);
  var x = gf(null);
  var a = gf(null);
  var b = gf(null);

  _unpack25519(x, pk);

  _A(a, x, gf1);
  _Z(b, x, gf1);
  _inv25519(a, a);
  _M(a, a, b);

  _pack25519(z, a);
  return z;
}

int _curve25519SignOpen(Uint8List m, Uint8List sm, int n, Uint8List pk) {
  // Convert Curve25519 public key into Ed25519 public key.
  var edpk = _convertPublicKey(pk);

  // Restore sign bit from signature.
  edpk[31] = edpk[31] | (sm[63] & 128);

  // Remove sign bit from signature.
  var sm0 = sm;

  sm0[63] = sm0[63] & 127;

  // Verify signed message.
  return _cryptoSignOpen(m, sm0, n, edpk);
}

/* AxlSign */
class Curve25519 {
  static Uint8List sharedKey(Uint8List secretKey, Uint8List publicKey) {
    var sharedKey = Uint8List(32);
    _cryptoScalarmult(sharedKey, secretKey, publicKey);
    return sharedKey;
  }

  static Uint8List signMessage(
      Uint8List secretKey, Uint8List msg, Uint8List optRandom) {
    if (optRandom.isNotEmpty) {
      var buf = Uint8List(128 + msg.length);
      _curve25519Sign(buf, msg, msg.length, secretKey, optRandom);
      return buf.sublist(0, 64 + msg.length);
    } else {
      var signedMsg = Uint8List(64 + msg.length);
      _curve25519Sign(signedMsg, msg, msg.length, secretKey, null);
      return signedMsg;
    }
  }

  static List<int> openMessage(Uint8List publicKey, Uint8List signedMsg) {
    var tmp = Uint8List(signedMsg.length);
    var mlen = _curve25519SignOpen(tmp, signedMsg, signedMsg.length, publicKey);
    if (mlen < 0) {
      return [];
    }
    var m = List<int>.filled(mlen, 0);
    for (var i = 0; i < m.length; i++) {
      m[i] = tmp[i];
    }
    return m;
  }

// add by Miguel
  static String openMessageStr(Uint8List publicKey, Uint8List signedMsg) {
    var m = openMessage(publicKey, signedMsg);
    return m.toString();
  }

  static Uint8List sign(
      Uint8List secretKey, Uint8List msg, Uint8List optRandom) {
    var len = 64;
    if (optRandom.isNotEmpty) {
      len = 128;
    }
    var buf = Uint8List(len + msg.length); // make([]uint8, _len + msg.length)

    _curve25519Sign(buf, msg, msg.length, secretKey, optRandom);

    var signature = Uint8List(64);
    for (var i = 0; i < (signature.length); i++) {
      signature[i] = buf[i];
    }
    return signature;
  }

  static int verify(Uint8List publicKey, Uint8List msg, Uint8List signature) {
    Uint8List sm = Uint8List(64 + msg.length);
    Uint8List m = Uint8List(64 + msg.length);

    for (var i = 0; i < 64; i++) {
      sm[i] = signature[i];
    }

    for (var i = 0; i < msg.length; i++) {
      sm[i + 64] = msg[i];
    }

    if (_curve25519SignOpen(m, sm, sm.length, publicKey) >= 0) {
      return 1;
    } else {
      return 0;
    }
  }
}

class Curve25519KeyPair {
  Curve25519KeyPair({required this.privateKey, required this.publicKey});

  final Uint8List publicKey;
  final Uint8List privateKey;

  factory Curve25519KeyPair.fromSeed(Uint8List seed) {
    var sk = Uint8List(32);
    var pk = Uint8List(32);

    for (var i = 0; i < 32; i++) {
      sk[i] = seed[i];
    }

    _cryptoScalarmultBase(pk, sk);

    // Turn secret key into the correct format.
    sk[0] = sk[0] & 248;
    sk[31] = sk[31] & 127;
    sk[31] = sk[31] | 64;

    // Remove sign bit from public key.
    pk[31] = pk[31] & 127;

    return Curve25519KeyPair(privateKey: sk, publicKey: pk);
  }
}



/*
func debugA8(t string, a []uint8) {
	fmt.Printf(t + " [%d] ", len(a))
	var sum = 0
	for i := 0; i< len(a); i++ {
		sum += int(a[i])
		fmt.Printf("%d ", a[i])
	}
	fmt.Printf(" - suma: %d\n\n", sum)
}
*/
