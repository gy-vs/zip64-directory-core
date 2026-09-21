import { describe, expect, it } from 'vitest';
import { ZipFormatError, locateCentralDirectory, readCentralDirectory, readUint64LE } from '../src/index.js';

// --- little-endian builders -------------------------------------------------

const u16 = (n: number): number[] => [n & 0xff, (n >>> 8) & 0xff];
const u32 = (n: number): number[] => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const u64 = (v: bigint): number[] => {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
  return out;
};
const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0));

function localHeader(name: string, size: number): number[] {
  return [
    ...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(size), ...u32(size), ...u16(name.length), ...u16(0), ...ascii(name),
  ];
}

interface EntrySpec {
  name: string;
  size?: number;
  compressed?: number;
  localOffset?: number;
  extra?: number[];
  diskStart?: number;
}

function centralEntry(spec: EntrySpec): number[] {
  const name = ascii(spec.name);
  const extra = spec.extra ?? [];
  return [
    ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(spec.compressed ?? spec.size ?? 0), ...u32(spec.size ?? 0),
    ...u16(name.length), ...u16(extra.length), ...u16(0),
    ...u16(spec.diskStart ?? 0), ...u16(0), ...u32(0), ...u32(spec.localOffset ?? 0),
    ...name, ...extra,
  ];
}

interface EocdSpec {
  disk?: number;
  cdDisk?: number;
  diskEntries?: number;
  totalEntries?: number;
  cdSize: number;
  cdOffset: number;
  comment?: number[];
}

function eocd(spec: EocdSpec): number[] {
  const comment = spec.comment ?? [];
  const total = spec.totalEntries ?? 0;
  return [
    ...u32(0x06054b50), ...u16(spec.disk ?? 0), ...u16(spec.cdDisk ?? 0),
    ...u16(spec.diskEntries ?? total), ...u16(total),
    ...u32(spec.cdSize), ...u32(spec.cdOffset), ...u16(comment.length), ...comment,
  ];
}

interface Eocd64Spec {
  diskEntries: bigint;
  totalEntries: bigint;
  cdSize: bigint;
  cdOffset: bigint;
  disk?: number;
  cdDisk?: number;
  recordSize?: bigint;
}

function eocd64(spec: Eocd64Spec): number[] {
  return [
    ...u32(0x06064b50), ...u64(spec.recordSize ?? 44n), ...u16(45), ...u16(45),
    ...u32(spec.disk ?? 0), ...u32(spec.cdDisk ?? 0),
    ...u64(spec.diskEntries), ...u64(spec.totalEntries), ...u64(spec.cdSize), ...u64(spec.cdOffset),
  ];
}

function locator64(eocd64Offset: bigint, opts: { disk?: number; totalDisks?: number } = {}): number[] {
  return [...u32(0x07064b50), ...u32(opts.disk ?? 0), ...u64(eocd64Offset), ...u32(opts.totalDisks ?? 1)];
}

function zip64Extra(...values: bigint[]): number[] {
  const body = values.flatMap(u64);
  return [...u16(0x0001), ...u16(body.length), ...body];
}

/** Builds [local data][central directory][eocd] for the given files. */
function simpleArchive(
  files: Array<{ name: string; data?: number[]; spec?: Partial<EntrySpec> }>,
  comment: number[] = [],
): Uint8Array {
  const out: number[] = [];
  const offsets: number[] = [];
  for (const file of files) {
    offsets.push(out.length);
    out.push(...localHeader(file.name, file.data?.length ?? 0), ...(file.data ?? []));
  }
  const cdOffset = out.length;
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    out.push(...centralEntry({ name: file.name, size: file.data?.length ?? 0, localOffset: offsets[i], ...file.spec }));
  }
  const cdSize = out.length - cdOffset;
  out.push(...eocd({ totalEntries: files.length, cdSize, cdOffset, comment }));
  return Uint8Array.from(out);
}

interface Zip64ArchiveOpts {
  eocd64?: Partial<Eocd64Spec>;
  locatorOffset?: bigint;
  locator?: { disk?: number; totalDisks?: number };
  classic?: Partial<EocdSpec>;
}

/** Builds [local data][central directory][zip64 eocd][locator][eocd with sentinels]. */
function zip64Archive(opts: Zip64ArchiveOpts = {}) {
  const out: number[] = [];
  out.push(...localHeader('x', 4), 1, 2, 3, 4);
  const cdOffset = out.length;
  out.push(...centralEntry({ name: 'x', size: 4, localOffset: 0 }));
  const cdSize = out.length - cdOffset;
  const eocd64At = out.length;
  out.push(...eocd64({
    diskEntries: 1n, totalEntries: 1n, cdSize: BigInt(cdSize), cdOffset: BigInt(cdOffset), ...opts.eocd64,
  }));
  const locatorAt = out.length;
  out.push(...locator64(opts.locatorOffset ?? BigInt(eocd64At), opts.locator));
  const eocdAt = out.length;
  out.push(...eocd({
    diskEntries: 0xffff, totalEntries: 0xffff, cdSize: 0xffffffff, cdOffset: 0xffffffff, ...opts.classic,
  }));
  return { archive: Uint8Array.from(out), cdOffset, cdSize, eocd64At, locatorAt, eocdAt };
}

function catchErr(fn: () => unknown): ZipFormatError {
  try {
    fn();
  } catch (error) {
    if (error instanceof ZipFormatError) return error;
    throw error;
  }
  throw new Error('expected a ZipFormatError');
}

// --- tests ------------------------------------------------------------------

describe('readUint64LE', () => {
  it('reads 64 bits', () => expect(readUint64LE(Uint8Array.from([1, 0, 0, 0, 1, 0, 0, 0]))).toBe(4294967297n));

  it('reads exact boundary values', () => {
    expect(readUint64LE(Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]))).toBe(0xffffffffn);
    expect(readUint64LE(Uint8Array.from([0, 0, 0, 0, 1, 0, 0, 0]))).toBe(0x100000000n);
    expect(readUint64LE(Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toBe(0xffffffffffffffffn);
  });
});

describe('readCentralDirectory', () => {
  it('parses a small classic archive', () => {
    const archive = simpleArchive(
      [
        { name: 'a.txt', data: ascii('hello') },
        { name: 'dir/b.bin', data: [1, 2, 3] },
      ],
      ascii('hi'),
    );
    const cd = readCentralDirectory(archive);
    expect(cd.zip64).toBe(false);
    expect(cd.offset).toBe(82n);
    expect(cd.size).toBe(106n);
    expect(cd.entryCount).toBe(2n);
    expect(cd.entries.list()).toHaveLength(2);
    const a = cd.entries.find('a.txt');
    expect(a?.size).toBe(5n);
    expect(a?.offset).toBe(0n);
    const b = cd.entries.find('dir/b.bin');
    expect(b?.size).toBe(3n);
    expect(b?.offset).toBe(40n);
    expect(cd.entries.find('missing')).toBeUndefined();
  });

  it('treats values just below the sentinel as literals, not zip64 markers', () => {
    const archive = simpleArchive([
      { name: 'big', spec: { size: 0xfffffffe, compressed: 0xfffffffd, localOffset: 0 } },
    ]);
    const cd = readCentralDirectory(archive);
    expect(cd.zip64).toBe(false);
    expect(cd.entries.find('big')?.size).toBe(4294967294n);
  });

  it('resolves 0xffffffff/0xffff sentinels through the zip64 eocd', () => {
    const { archive, cdOffset, cdSize } = zip64Archive();
    const cd = readCentralDirectory(archive);
    expect(cd.zip64).toBe(true);
    expect(cd.offset).toBe(BigInt(cdOffset));
    expect(cd.size).toBe(BigInt(cdSize));
    expect(cd.entryCount).toBe(1n);
    expect(cd.entries.find('x')?.size).toBe(4n);
  });

  it('ignores zip64 structures when no classic field holds a sentinel', () => {
    // A bogus zip64 eocd (offset 9999) sits in the file, but the classic
    // fields are not sentinels, so it must not be consulted.
    const { archive, cdOffset, cdSize } = zip64Archive({
      eocd64: { cdOffset: 9999n },
      classic: { diskEntries: 1, totalEntries: 1, cdSize: 47, cdOffset: 35 },
    });
    const cd = readCentralDirectory(archive);
    expect(cd.zip64).toBe(false);
    expect(cd.offset).toBe(BigInt(cdOffset));
    expect(cd.size).toBe(BigInt(cdSize));
    expect(cd.entries.find('x')?.size).toBe(4n);
  });

  it('reads entry zip64 extras only for fields holding the sentinel', () => {
    const archive = simpleArchive([
      { name: 'x', spec: { size: 0xffffffff, compressed: 0xffffffff, localOffset: 0xffffffff, extra: zip64Extra(5n, 3n, 9n) } },
      { name: 'y', spec: { size: 0xffffffff, compressed: 7, localOffset: 0, extra: zip64Extra(6n) } },
    ]);
    const cd = readCentralDirectory(archive);
    const x = cd.entries.find('x');
    expect(x?.size).toBe(5n);
    expect(x?.offset).toBe(9n);
    const y = cd.entries.find('y');
    expect(y?.size).toBe(6n);
    expect(y?.offset).toBe(0n);
  });

  it('rejects a sentinel size without a zip64 extra field', () => {
    const archive = simpleArchive([{ name: 'x', spec: { size: 0xffffffff } }]);
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 extra field');
    // local header is 31 bytes, entry header 46, name 1 -> extra starts at 78.
    expect(err.offset).toBe(78n);
    expect(err.message).toContain('zip64 extra field');
    expect(err.message).toContain('78');
  });

  it('rejects a truncated zip64 extra field', () => {
    const archive = simpleArchive([
      { name: 'x', spec: { size: 0xffffffff, extra: [...u16(0x0001), ...u16(4), 9, 9, 9, 9] } },
    ]);
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 extra uncompressed size');
  });

  it('rejects sentinel fields when the zip64 locator is missing', () => {
    const archive = simpleArchive([{ name: 'x' }]);
    archive.set(u32(0xffffffff), archive.length - 22 + 16); // classic cd offset -> sentinel
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 locator signature');
    expect(err.offset).toBe(BigInt(archive.length - 22 - 20));
  });

  it('rejects a locator pointing at the wrong offset', () => {
    const { archive, eocd64At, locatorAt } = zip64Archive();
    archive.set(u64(BigInt(eocd64At - 4)), locatorAt + 8); // points into the central directory
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 eocd signature');
    expect(err.offset).toBe(BigInt(eocd64At - 4));
  });

  it('rejects a locator pointing outside the file', () => {
    const { archive, locatorAt } = zip64Archive();
    archive.set(u64(0x100000000n), locatorAt + 8);
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 eocd offset');
    expect(err.offset).toBe(BigInt(locatorAt + 8));
    expect(err.message).toContain('outside the buffered range');
  });

  it('rejects offsets beyond the safe integer range', () => {
    const { archive, locatorAt } = zip64Archive();
    archive.set(u64(9007199254740993n), locatorAt + 8); // 2**53 + 1
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('zip64 eocd offset');
    expect(err.message).toContain('safe integer range');
  });

  it('rejects multi-disk markers', () => {
    const cases: Array<[string, () => Uint8Array, string]> = [
      ['eocd disk number', () => {
        const a = simpleArchive([{ name: 'x' }]);
        a[a.length - 22 + 4] = 1;
        return a;
      }, 'eocd disk number'],
      ['eocd split entry counts', () => {
        const a = simpleArchive([{ name: 'x' }]);
        a[a.length - 22 + 8] = 0; // entries on this disk != total entries
        return a;
      }, 'eocd entries on this disk'],
      ['entry disk start', () => simpleArchive([{ name: 'x', spec: { diskStart: 1 } }]), 'central directory entry disk start'],
      ['locator total disks', () => zip64Archive({ locator: { totalDisks: 2 } }).archive, 'zip64 locator total disks'],
      ['zip64 eocd disk number', () => zip64Archive({ eocd64: { disk: 3 } }).archive, 'zip64 eocd disk number'],
    ];
    for (const [name, build, field] of cases) {
      const err = catchErr(() => readCentralDirectory(build()));
      expect(err.field, name).toBe(field);
      expect(err.message, name).toContain('multi-disk');
    }
  });

  it('rejects truncated records', () => {
    const cases: Array<[string, () => Uint8Array, string]> = [
      ['eocd cut short', () => {
        const a = simpleArchive([{ name: 'x' }]);
        return a.slice(0, a.length - 5);
      }, 'eocd signature'],
      ['entry name length overruns the directory', () => {
        const a = simpleArchive([{ name: 'x' }]);
        a[31 + 28] = 200; // name length of the single entry at offset 31
        return a;
      }, 'central directory entry'],
      ['zip64 record size overruns the locator', () =>
        zip64Archive({ eocd64: { recordSize: 1000n } }).archive,
      'zip64 eocd record size'],
      ['more entries declared than present', () => {
        const a = simpleArchive([{ name: 'x' }]);
        a[a.length - 22 + 8] = 2; // entries on this disk
        a[a.length - 22 + 10] = 2; // total entries
        return a;
      }, 'central directory entry'],
    ];
    for (const [name, build, field] of cases) {
      const err = catchErr(() => readCentralDirectory(build()));
      expect(err.field, name).toBe(field);
    }
  });

  it('rejects mismatched classic and zip64 values', () => {
    const { archive } = zip64Archive({
      eocd64: { diskEntries: 2n, totalEntries: 2n },
      classic: { diskEntries: 1, totalEntries: 1 },
    });
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('eocd total entries');
    expect(err.message).toContain('disagrees');
  });

  it('rejects entries that do not consume the declared central directory', () => {
    const archive = simpleArchive([{ name: 'a' }, { name: 'b' }]);
    archive[archive.length - 22 + 8] = 1; // entries on this disk
    archive[archive.length - 22 + 10] = 1; // total entries
    const err = catchErr(() => readCentralDirectory(archive));
    expect(err.field).toBe('central directory entry count');
  });

  it('refuses to fall back to an earlier signature after a bad candidate', () => {
    const good = simpleArchive([{ name: 'x', data: [1] }]);
    // Garbage that looks like an EOCD signature but is inconsistent; a
    // fallback scanner would skip it and accept the real EOCD before it.
    const junk = [...u32(0x06054b50), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    const poisoned = Uint8Array.from([...good, ...junk]);
    const err = catchErr(() => readCentralDirectory(poisoned));
    expect(err.field).toBe('eocd comment length');
  });
});

describe('locateCentralDirectory', () => {
  const tail = (cdOffset: bigint): Uint8Array =>
    Uint8Array.from([
      ...eocd64({ diskEntries: 0n, totalEntries: 0n, cdSize: 0n, cdOffset }),
      ...locator64(cdOffset),
      ...eocd({ diskEntries: 0xffff, totalEntries: 0xffff, cdSize: 0xffffffff, cdOffset: 0xffffffff }),
    ]);

  it('keeps offsets beyond 4 GiB exact as bigint', () => {
    const base = 0x100000100n; // 4 GiB + 256; 32-bit truncation would turn this into 256
    const location = locateCentralDirectory(tail(base), base);
    expect(location.offset).toBe(4294967552n);
    expect(location.entryCount).toBe(0n);
    expect(location.zip64).toBe(true);
  });

  it('keeps a real 0xffffffff offset exact', () => {
    const base = 0xffffffffn; // a genuine 4 GiB - 1 offset, not the sentinel
    const location = locateCentralDirectory(tail(base), base);
    expect(location.offset).toBe(4294967295n);
  });
});
