import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  ByteSource,
  parseZipIndex,
  readUint64LE,
  ZipParseError,
  toSafeNumber,
} from '../src/index.js';

// ---------- byte builders ----------

class B extends Uint8Array {
  constructor(size: number) {
    super(size);
  }
  #view(): DataView {
    return new DataView(this.buffer, this.byteOffset, this.byteLength);
  }
  w16(o: number, v: number) {
    this.#view().setUint16(o, v & 0xffff, true);
  }
  w32(o: number, v: number) {
    this.#view().setUint32(o, v >>> 0, true);
  }
  w32b(o: number, v: bigint) {
    this.#view().setUint32(o, Number(v & 0xffffffffn), true);
  }
  w64(o: number, v: bigint) {
    this.#view().setUint32(o, Number(v & 0xffffffffn), true);
    this.#view().setUint32(o + 4, Number(v >> 32n), true);
  }
  put(o: number, x: Uint8Array) {
    this.set(x, o);
  }
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_Z64_EOCD = 0x06064b50;
const SIG_Z64_LOC = 0x07064b50;

function localHeader(name: string): B {
  const nb = Buffer.from(name);
  const b = new B(30 + nb.length);
  b.w32(0, SIG_LOCAL);
  b.w16(4, 20);
  b.w16(26, nb.length);
  b.put(30, nb);
  return b;
}

type CentralOpts = {
  compressedSize?: number | bigint;
  uncompressedSize?: number | bigint;
  localOffset?: number | bigint;
  extra?: Uint8Array;
  comment?: Uint8Array;
  diskStart?: number;
  sig?: number;
};

function centralHeader(name: string, o: CentralOpts = {}): B {
  const nb = Buffer.from(name);
  const extra = o.extra ?? new B(0);
  const comment = o.comment ?? new B(0);
  const b = new B(46 + nb.length + extra.length + comment.length);
  b.w32(0, o.sig ?? SIG_CENTRAL);
  b.w16(4, 45);
  b.w16(6, 20);
  b.w32b(20, BigInt(o.compressedSize ?? 0));
  b.w32b(24, BigInt(o.uncompressedSize ?? 0));
  b.w16(28, nb.length);
  b.w16(30, extra.length);
  b.w16(32, comment.length);
  b.w16(34, o.diskStart ?? 0);
  b.w32b(42, BigInt(o.localOffset ?? 0));
  b.put(46, nb);
  b.put(46 + nb.length, extra);
  b.put(46 + nb.length + extra.length, comment);
  return b;
}

type EocdOpts = {
  diskNumber?: number;
  cdDisk?: number;
  entriesDisk?: number | bigint;
  totalEntries?: number | bigint;
  cdSize?: number | bigint;
  cdOffset?: number | bigint;
  comment?: Uint8Array;
  sig?: number;
};

function eocd(o: EocdOpts = {}): B {
  const comment = o.comment ?? new B(0);
  const b = new B(22 + comment.length);
  b.w32(0, o.sig ?? SIG_EOCD);
  b.w16(4, o.diskNumber ?? 0);
  b.w16(6, o.cdDisk ?? 0);
  b.w16(8, Number(BigInt(o.entriesDisk ?? 0)) & 0xffff);
  b.w16(10, Number(BigInt(o.totalEntries ?? 0)) & 0xffff);
  b.w32b(12, BigInt(o.cdSize ?? 0));
  b.w32b(16, BigInt(o.cdOffset ?? 0));
  b.w16(20, comment.length);
  b.put(22, comment);
  return b;
}

function zip64Eocd(o: {
  entriesDisk: bigint;
  totalEntries: bigint;
  cdSize: bigint;
  cdOffset: bigint;
  diskNumber?: number;
  cdDisk?: number;
  recordSize?: bigint;
}): B {
  const b = new B(56);
  b.w32(0, SIG_Z64_EOCD);
  b.w64(4, o.recordSize ?? 44n);
  b.w32(16, o.diskNumber ?? 0);
  b.w32(20, o.cdDisk ?? 0);
  b.w64(24, o.entriesDisk);
  b.w64(32, o.totalEntries);
  b.w64(40, o.cdSize);
  b.w64(48, o.cdOffset);
  return b;
}

function zip64Locator(eocd64Offset: bigint, diskNumber = 0, totalDisks = 1): B {
  const b = new B(20);
  b.w32(0, SIG_Z64_LOC);
  b.w32(4, diskNumber);
  b.w64(8, eocd64Offset);
  b.w32(16, totalDisks);
  return b;
}

function zip64Extra(fields: { size?: bigint; compressed?: bigint; offset?: bigint }): B {
  const present = [fields.size, fields.compressed, fields.offset].filter((v) => v !== undefined).length;
  const b = new B(4 + present * 8);
  b.w16(0, 0x0001);
  b.w16(2, present * 8);
  let p = 4;
  for (const v of [fields.size, fields.compressed, fields.offset]) {
    if (v === undefined) continue;
    b.w64(p, v);
    p += 8;
  }
  return b;
}

function concat(...parts: Uint8Array[]): B {
  const out = new B(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.put(o, p);
    o += p.length;
  }
  return out;
}

// Virtual sparse archive: addresses are arbitrary bigints; gaps read zero.
type Block = { offset: bigint; data: Uint8Array };
class SparseSource implements ByteSource {
  readonly byteLength: bigint;
  readonly #blocks: Block[];
  constructor(byteLength: bigint, blocks: Block[]) {
    this.byteLength = byteLength;
    this.#blocks = [...blocks].sort((a, b) => (a.offset < b.offset ? -1 : 1));
  }
  #blockAt(offset: bigint, length: number): Block | undefined {
    return this.#blocks.find(
      (b) => offset >= b.offset && offset + BigInt(length) <= b.offset + BigInt(b.data.length),
    );
  }
  readByte(offset: bigint): number {
    const b = this.#blockAt(offset, 1);
    return b ? b.data[Number(offset - b.offset)] : 0;
  }
  readBytes(offset: bigint, length: number): Uint8Array {
    const b = this.#blockAt(offset, length);
    if (!b) throw new ZipParseError('sparse.gap', offset, `no contiguous backing bytes for ${length}-byte read`);
    const start = Number(offset - b.offset);
    return b.data.slice(start, start + length);
  }
}

// ---------- assertion helper ----------

function expectParseError(fn: () => unknown, field: string, offset?: bigint): ZipParseError {
  let err: unknown;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  expect(err, 'expected parseZipIndex to throw').toBeInstanceOf(ZipParseError);
  const z = err as ZipParseError;
  expect(z.field).toBe(field);
  if (offset !== undefined) expect(z.offset).toBe(offset);
  expect(z.message).toContain(field);
  expect(z.message).toMatch(/0x[0-9a-f]+/);
  if (offset !== undefined) expect(z.message).toContain(`0x${offset.toString(16)}`);
  return z;
}

// ---------- readUint64LE ----------

describe('readUint64LE', () => {
  it('reads 64 bits straight from raw bytes', () => {
    expect(readUint64LE(Uint8Array.from([1, 0, 0, 0, 1, 0, 0, 0]))).toBe(4294967297n);
  });

  it('reads the maximum unsigned value', () => {
    expect(readUint64LE(new Uint8Array(8).fill(0xff))).toBe(0xffffffffffffffffn);
  });

  it('does not silently coerce truncated fields with ?? 0', () => {
    expectParseError(() => readUint64LE(Uint8Array.from([1, 2, 3, 4, 5, 6, 7])), 'uint64', 0n);
  });
});

describe('toSafeNumber', () => {
  it('rejects values beyond MAX_SAFE_INTEGER', () => {
    expectParseError(() => toSafeNumber(2n ** 53n, 'count', 9n), 'count', 9n);
    expect(toSafeNumber(2n ** 53n - 1n, 'count')).toBe(Number.MAX_SAFE_INTEGER);
  });
});

// ---------- ordinary archives ----------

describe('ordinary ZIP', () => {
  function buildSmall(name = 'hello.txt'): B {
    const local = localHeader(name);
    const central = centralHeader(name, { localOffset: 0 });
    const cdOffset = local.length;
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: central.length,
      cdOffset,
    });
    return concat(local, central, end);
  }

  it('parses a normal small archive entirely without ZIP64', () => {
    const zip = buildSmall();
    const idx = parseZipIndex(zip);
    expect(idx.list()).toHaveLength(1);
    const e = idx.find('hello.txt');
    expect(e?.size).toBe(0n);
    expect(e?.offset).toBe(0n);
    expect(e?.extra).toHaveLength(0);
  });

  it('parses an empty archive (EOCD only)', () => {
    const idx = parseZipIndex(eocd());
    expect(idx.list()).toHaveLength(0);
  });

  it('accepts 0xfffffffe classic values as ordinary values, never as ZIP64', () => {
    // Both size and local-header offset sit one below the sentinel.  There is
    // no locator and no ZIP64 extra; these must be taken literally.
    const name = 'edge.bin';
    const local = localHeader(name); // real backing bytes in the virtual gap
    const central = centralHeader(name, {
      uncompressedSize: 0xfffffffe,
      compressedSize: 0xfffffffe,
      localOffset: 0xfffffffe,
    });
    // The entry declares size and local-header offset of 0xfffffffe, i.e.
    // exactly one below the sentinel.  No locator and no ZIP64 extra exist,
    // so these must be taken literally as classic values.  The backing
    // local-header block is mapped at the declared address and fits.
    const localOffset = 0xfffffffen;
    const cdOffset = 0x100n;
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: BigInt(central.length),
      cdOffset,
    });
    // EOCD must sit at the virtual EOF and past the local block.
    const eocdOffset = localOffset + BigInt(local.length) + 8n;
    const src = new SparseSource(eocdOffset + BigInt(end.length), [
      { offset: localOffset, data: local },
      { offset: cdOffset, data: central },
      { offset: eocdOffset, data: end },
    ]);
    const idx = parseZipIndex(src);
    const e = idx.find(name)!;
    expect(e.size).toBe(0xfffffffen);
    expect(e.offset).toBe(0xfffffffen);
  });

  it('rejects a trailing comment whose length does not reach EOF', () => {
    // Correct signature, wrong comment length: a random EOCD-looking record
    // must not be accepted just because "PK\005\006" matched.
    const d = new B(50);
    d.w32(5, SIG_EOCD);
    d.w16(5 + 20, 0xffff);
    d.w32(28, SIG_EOCD);
    d.w16(28 + 20, 3); // claims 3 comment bytes, but none follow to EOF
    expectParseError(() => parseZipIndex(d), 'eocd');
  });

  it('does not scan backwards for a stray locator signature', () => {
    // A locator-looking record sits in the middle of the file, but nothing
    // is located immediately before the classic EOCD.  The sentinel cdOffset
    // must therefore be an error rather than triggering a fallback search.
    const buf = new B(100);
    buf.w32(30, SIG_Z64_LOC); // decoy, far from the EOCD
    const end = eocd({ entriesDisk: 1, totalEntries: 1, cdOffset: 0xffffffff });
    buf.put(78, end);
    expectParseError(() => parseZipIndex(buf), 'eocd.cdOffset', 78n + 16n);
  });

  it('rejects a classic 0xffffffff sentinel without a locator', () => {
    const end = eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff });
    expectParseError(() => parseZipIndex(end), 'eocd.entriesOnDisk', 8n);
  });
});

// ---------- ZIP64 ----------

describe('ZIP64', () => {
  it('parses >4GB offsets and an exact 0xffffffff size via bigint', () => {
    const name = 'big.bin';
    const local = localHeader(name);
    const extra = zip64Extra({
      size: 0xffffffffn, // exactly the sentinel value as a *real* size
      compressed: 0xffffffffn,
      offset: 0x100000010n, // beyond 4 GiB
    });
    const central = centralHeader(name, {
      uncompressedSize: 0xffffffff,
      compressedSize: 0xffffffff,
      localOffset: 0xffffffff,
      extra,
    });
    const localOffset = 0x100000010n;
    const cdOffset = 0x100001000n;
    const z64Offset = 0x100010000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;

    const z64 = zip64Eocd({
      entriesDisk: 1n,
      totalEntries: 1n,
      cdSize: BigInt(central.length),
      cdOffset,
    });
    const locator = zip64Locator(z64Offset);
    const end = eocd({
      entriesDisk: 0xffffffff,
      totalEntries: 0xffffffff,
      cdSize: 0xffffffff,
      cdOffset: 0xffffffff,
    });
    const src = new SparseSource(classicOffset + BigInt(end.length), [
      { offset: localOffset, data: local },
      { offset: cdOffset, data: central },
      { offset: z64Offset, data: z64 },
      { offset: locatorOffset, data: locator },
      { offset: classicOffset, data: end },
    ]);

    const idx = parseZipIndex(src);
    const e = idx.list()[0];
    expect(e.name).toBe(name);
    expect(e.size).toBe(0xffffffffn);
    expect(e.offset).toBe(0x100000010n);
  });

  it('locates the central directory itself beyond 4 GiB', () => {
    const name = 'far.bin';
    const localOffset = 0x100000010n;
    const local = localHeader(name);
    const extra = zip64Extra({ offset: localOffset });
    const central = centralHeader(name, { localOffset: 0xffffffff, extra });
    const cdOffset = 0x100002000n;
    const z64Offset = 0x200000000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;

    const z64 = zip64Eocd({
      entriesDisk: 1n,
      totalEntries: 1n,
      cdSize: BigInt(central.length),
      cdOffset,
    });
    const end = eocd({
      entriesDisk: 0xffffffff,
      totalEntries: 0xffffffff,
      cdSize: 0xffffffff,
      cdOffset: 0xffffffff,
    });
    const src = new SparseSource(classicOffset + BigInt(end.length), [
      { offset: localOffset, data: local },
      { offset: cdOffset, data: central },
      { offset: z64Offset, data: z64 },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      { offset: classicOffset, data: end },
    ]);
    expect(parseZipIndex(src).find(name)?.offset).toBe(0x100000010n);
  });

  it('errors when the locator points at the wrong ZIP64 EOCD offset', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = 0x2000n;
    const classicOffset = locatorOffset + 20n;
    const locator = zip64Locator(123n); // deliberately wrong
    const end = eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff });
    const src = new SparseSource(classicOffset + BigInt(end.length), [
      { offset: z64Offset, data: zip64Eocd({ entriesDisk: 1n, totalEntries: 1n, cdSize: 0n, cdOffset: 0n }) },
      { offset: locatorOffset, data: locator },
      { offset: classicOffset, data: end },
    ]);
    expectParseError(() => parseZipIndex(src), 'zip64Locator.eocdOffset', locatorOffset + 8n);
  });

  it('rejects multi-disk markers in the locator', () => {
    const classicOffset = 0x300n;
    const locatorOffset = classicOffset - 20n;
    const src = new SparseSource(classicOffset + 22n, [
      { offset: locatorOffset, data: zip64Locator(0n, 1) },
      { offset: classicOffset, data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff }) },
    ]);
    expectParseError(() => parseZipIndex(src), 'zip64Locator.diskNumber', locatorOffset + 4n);
  });

  it('rejects totalDisks != 1 in the locator', () => {
    const classicOffset = 0x300n;
    const locatorOffset = classicOffset - 20n;
    const src = new SparseSource(classicOffset + 22n, [
      { offset: locatorOffset, data: zip64Locator(0n, 0, 2) },
      { offset: classicOffset, data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff }) },
    ]);
    expectParseError(() => parseZipIndex(src), 'zip64Locator.totalDisks', locatorOffset + 16n);
  });

  it('rejects multi-disk ZIP64 EOCD disk numbers', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      {
        offset: z64Offset,
        data: zip64Eocd({
          entriesDisk: 1n,
          totalEntries: 1n,
          cdSize: 0n,
          cdOffset: 0n,
          diskNumber: 1,
        }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      { offset: classicOffset, data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff }) },
    ]);
    expectParseError(() => parseZipIndex(src), 'zip64Eocd.diskNumber', z64Offset + 16n);
  });

  it('cross-checks classic and ZIP64 entry counts', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const end = eocd({
      entriesDisk: 0xffffffff,
      totalEntries: 2, // non-sentinel, disagrees with the ZIP64 count of 1
      cdSize: 0xffffffff,
      cdOffset: 0xffffffff,
    });
    const src = new SparseSource(classicOffset + 22n, [
      {
        offset: z64Offset,
        data: zip64Eocd({ entriesDisk: 1n, totalEntries: 1n, cdSize: 0n, cdOffset: 0n }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      { offset: classicOffset, data: end },
    ]);
    expectParseError(() => parseZipIndex(src), 'eocd.totalEntries', classicOffset + 10n);
  });

  it('rejects entry-count disagreement (disk vs total)', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      {
        offset: z64Offset,
        data: zip64Eocd({ entriesDisk: 2n, totalEntries: 3n, cdSize: 0n, cdOffset: 0n }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      { offset: classicOffset, data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff }) },
    ]);
    expectParseError(() => parseZipIndex(src), 'zip64Eocd.entriesOnDisk', z64Offset + 24n);
  });

  it('rejects a central directory range that runs into the EOCD chain', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      {
        offset: z64Offset,
        data: zip64Eocd({ entriesDisk: 1n, totalEntries: 1n, cdSize: 0x10000n, cdOffset: 0n }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      {
        offset: classicOffset,
        data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff, cdSize: 0xffffffff, cdOffset: 0xffffffff }),
      },
    ]);
    expectParseError(() => parseZipIndex(src), 'eocd.cdOffset', classicOffset + 16n);
  });

  it('refuses entry counts that are not safe integers', () => {
    const z64Offset = 0x1000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      {
        offset: z64Offset,
        data: zip64Eocd({ entriesDisk: 2n ** 60n, totalEntries: 2n ** 60n, cdSize: 0n, cdOffset: 0n }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      {
        offset: classicOffset,
        data: eocd({ totalEntries: 0xffffffff, entriesDisk: 0xffffffff, cdSize: 0xffffffff, cdOffset: 0xffffffff }),
      },
    ]);
    const err = expectParseError(() => parseZipIndex(src), 'eocd.totalEntries', classicOffset + 10n);
    expect(err.message).toMatch(/safe number/);
  });

  it('errors on a missing ZIP64 extra value for a sentinel entry field', () => {
    const name = 'ghost.bin';
    const local = localHeader(name);
    // extra carries an unrelated field (0x5455 extended timestamp), no 0x0001
    const foreign = new B(5);
    foreign.w16(0, 0x5455);
    foreign.w16(2, 1);
    foreign[4] = 1;
    const central = centralHeader(name, {
      uncompressedSize: 0xffffffff,
      compressedSize: 0xffffffff,
      localOffset: 0xffffffff,
      extra: foreign,
    });
    const cdOffset = 0x1000n;
    const z64Offset = 0x4000n;
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      { offset: 0n, data: local },
      { offset: cdOffset, data: central },
      {
        offset: z64Offset,
        data: zip64Eocd({
          entriesDisk: 1n,
          totalEntries: 1n,
          cdSize: BigInt(central.length),
          cdOffset,
        }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      {
        offset: classicOffset,
        data: eocd({
          totalEntries: 0xffffffff,
          entriesDisk: 0xffffffff,
          cdSize: BigInt(central.length),
          cdOffset,
        }),
      },
    ]);
    const extraFieldOffset = cdOffset + 46n + BigInt(name.length);
    expectParseError(
      () => parseZipIndex(src),
      'zip64Extra.uncompressedSize',
      extraFieldOffset,
    );
  });
});

// ---------- corrupted / truncated records ----------

describe('record validation', () => {
  it('rejects multi-disk classic EOCD markers', () => {
    const zip = new B(100);
    zip.put(78, eocd({ diskNumber: 1, cdDisk: 1, totalEntries: 1, entriesDisk: 1 }));
    expectParseError(() => parseZipIndex(zip), 'eocd.diskNumber', 78n + 4n);
  });

  it('rejects an archive shorter than the EOCD', () => {
    expectParseError(() => parseZipIndex(new B(10)), 'eocd', 10n);
  });

  it('rejects a truncated central record that overruns cdSize', () => {
    // nameLength claims 10 bytes but the declared central directory ends
    // right after the 46-byte fixed header
    const name = 'ab';
    const local = localHeader(name);
    const central = centralHeader(name, { localOffset: 0 });
    central.w16(28, 10); // lie about the name length
    const cdOffset = local.length;
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: BigInt(central.length),
      cdOffset: BigInt(cdOffset),
    });
    const zip = concat(local, central, end);
    expectParseError(() => parseZipIndex(zip), 'centralEntry.commentLength', BigInt(cdOffset) + 32n);
  });

  it('rejects a bad central file signature at the declared offset', () => {
    const name = 'x';
    const local = localHeader(name);
    const central = centralHeader(name, { localOffset: 0, sig: 0xdeadbeef });
    const cdOffset = local.length;
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: BigInt(central.length),
      cdOffset: BigInt(cdOffset),
    });
    expectParseError(() => parseZipIndex(concat(local, central, end)), 'centralEntry.signature', BigInt(cdOffset));
  });

  it('rejects a wrong local file signature without scanning for another', () => {
    const name = 'x';
    // Central record says the local header is at 0, where there is no
    // signature; the parser must fail there rather than hunt for "PK\003\004".
    const prefix = new B(60);
    const cdOffset = 60;
    const central = centralHeader(name, { localOffset: 0 });
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: BigInt(central.length),
      cdOffset: BigInt(cdOffset),
    });
    expectParseError(() => parseZipIndex(concat(prefix, central, end)), 'localHeader.signature', 0n);
  });

  it('rejects a local header offset outside the archive', () => {
    const name = 'x';
    const cdOffset = 0;
    const central = centralHeader(name, { localOffset: 0xfffffff0 });
    const end = eocd({
      entriesDisk: 1,
      totalEntries: 1,
      cdSize: BigInt(central.length),
      cdOffset: BigInt(cdOffset),
    });
    expectParseError(
      () => parseZipIndex(concat(central, end)),
      'centralEntry.localHeaderOffset',
      BigInt(cdOffset) + 42n,
    );
  });

  it('rejects when entries consume fewer bytes than declared cdSize', () => {
    const name = 'a';
    const local = localHeader(name);
    const central = centralHeader(name, { localOffset: 0 });
    const cdOffset = local.length;
    const end = eocd({
      entriesDisk: 2,
      totalEntries: 2,
      cdSize: BigInt(central.length),
      cdOffset: BigInt(cdOffset),
    });
    expectParseError(() => parseZipIndex(concat(local, central, end)), 'eocd.totalEntries');
  });

  it('rejects a truncated ZIP64 extra field header', () => {
    const name = 'a';
    const local = localHeader(name);
    const extra = new B(3);
    extra.w16(0, 0x0001); // claims a ZIP64 field but only 3 bytes exist
    const central = centralHeader(name, {
      localOffset: 0xffffffff,
      uncompressedSize: 0xffffffff,
      compressedSize: 0xffffffff,
      extra,
    });
    const cdOffset = local.length;
    const z64Offset = BigInt(cdOffset + central.length + 64);
    const locatorOffset = z64Offset + 56n;
    const classicOffset = locatorOffset + 20n;
    const src = new SparseSource(classicOffset + 22n, [
      { offset: 0n, data: concat(local, central) },
      {
        offset: z64Offset,
        data: zip64Eocd({
          entriesDisk: 1n,
          totalEntries: 1n,
          cdSize: BigInt(central.length),
          cdOffset: BigInt(cdOffset),
        }),
      },
      { offset: locatorOffset, data: zip64Locator(z64Offset) },
      {
        offset: classicOffset,
        data: eocd({
          totalEntries: 0xffffffff,
          entriesDisk: 0xffffffff,
          cdSize: BigInt(central.length),
          cdOffset: BigInt(cdOffset),
        }),
      },
    ]);
    const extraFieldOffset = BigInt(cdOffset) + 46n + BigInt(name.length);
    expectParseError(() => parseZipIndex(src), 'centralEntry.extra', extraFieldOffset);
  });
});
