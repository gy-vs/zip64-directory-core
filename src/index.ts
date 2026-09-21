// ZIP central directory parser.
//
// All structural offsets are kept as 64-bit unsigned bigints end to end.
// A classic (non-ZIP64) field is only replaced by its ZIP64 extra-field
// counterpart when the classic field holds the canonical sentinel
// (0xffffffff); any other value, including 0xfffffffe, is authoritative.

export type ZipEntry = {
  name: string;
  size: bigint;
  offset: bigint;
  extra: Uint8Array;
};

export class ZipIndex {
  #entries: ZipEntry[] = [];
  add(entry: ZipEntry) {
    this.#entries.push(entry);
  }
  list() {
    return this.#entries.slice();
  }
  find(name: string) {
    return this.#entries.find((entry) => entry.name === name);
  }
}

// Abstract byte source: offsets are bigint so the parser can address
// archives larger than Number.MAX_SAFE_INTEGER without allocating them.
export interface ByteSource {
  byteLength: bigint;
  readByte(offset: bigint): number;
  readBytes(offset: bigint, length: number): Uint8Array;
}

export class ZipParseError extends Error {
  readonly field: string;
  readonly offset: bigint;
  constructor(field: string, offset: bigint, message: string) {
    super(`${message} (field ${field} at absolute offset 0x${offset.toString(16)})`);
    this.name = 'ZipParseError';
    this.field = field;
    this.offset = offset;
  }
}

export class Uint8ArraySource implements ByteSource {
  readonly byteLength: bigint;
  readonly #data: Uint8Array;

  constructor(data: Uint8Array) {
    this.#data = data;
    this.byteLength = BigInt(data.length);
  }

  readByte(offset: bigint): number {
    const n = toSafeNumber(offset, 'source.offset');
    if (n < 0 || n >= this.#data.length) {
      throw new ZipParseError('source.offset', offset, 'read past end of archive');
    }
    return this.#data[n];
  }

  readBytes(offset: bigint, length: number): Uint8Array {
    const n = toSafeNumber(offset, 'source.offset');
    const end = n + length;
    if (n < 0 || end > this.#data.length) {
      throw new ZipParseError('source.offset', offset, 'read past end of archive');
    }
    return this.#data.slice(n, end);
  }
}

// Bounds-checked little-endian reader anchored at an absolute base offset.
class Cursor {
  readonly base: bigint;
  #pos: bigint;
  readonly #src: ByteSource;

  constructor(src: ByteSource, base: bigint) {
    this.#src = src;
    this.base = base;
    this.#pos = base;
  }

  get position(): bigint {
    return this.#pos;
  }

  skip(length: bigint) {
    this.#pos += length;
  }

  u16(_field: string): number {
    let value = 0;
    for (let i = 0; i < 2; i++) {
      value |= this.#src.readByte(this.#pos + BigInt(i)) << (8 * i);
    }
    this.#pos += 2n;
    return value;
  }

  u32(_field: string): bigint {
    let value = 0n;
    for (let i = 0; i < 4; i++) {
      value |= BigInt(this.#src.readByte(this.#pos + BigInt(i))) << BigInt(8 * i);
    }
    this.#pos += 4n;
    return value;
  }

  u64(_field: string): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
      value |= BigInt(this.#src.readByte(this.#pos + BigInt(i))) << BigInt(8 * i);
    }
    this.#pos += 8n;
    return value;
  }
}

// Convert a bigint to a number used for slice lengths, array indices and
// entry counts.  The safe-integer range is checked first.
export function toSafeNumber(value: bigint, field: string, offset: bigint = 0n): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ZipParseError(field, offset, `value ${value} cannot be converted to a safe number`);
  }
  return Number(value);
}

const dec = new TextDecoder();

// Parse an unsigned 64-bit little-endian integer straight from raw bytes.
export function readUint64LE(data: Uint8Array, offset = 0): bigint {
  if (offset < 0 || offset + 8 > data.length) {
    throw new ZipParseError('uint64', BigInt(offset), 'read past end of 64-bit field');
  }
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value |= BigInt(data[offset + i]) << (8n * BigInt(i));
  }
  return value;
}

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_CENTRAL_FILE = 0x02014b50;
const SIG_LOCAL_FILE = 0x04034b50;

const U16_SENTINEL = 0xffffn;
const U32_SENTINEL = 0xffffffffn;
const MAX_EOCD_COMMENT = 0xffff;
const EOCD_FIXED_SIZE = 22;
const ZIP64_LOCATOR_SIZE = 20;
const ZIP64_EOCD_FIXED_SIZE = 56;

function expectSignature(src: ByteSource, offset: bigint, expected: number, field: string): void {
  const sig = new Cursor(src, offset).u32(field);
  if (sig !== BigInt(expected)) {
    throw new ZipParseError(
      field,
      offset,
      `invalid signature 0x${sig.toString(16).padStart(8, '0')}, expected 0x${expected.toString(16)}`,
    );
  }
}

// Find the End Of Central Directory record.
//
// The EOCD may carry up to 65535 bytes of trailing comment, so the record
// is located by a bounded backwards scan.  A candidate is never accepted on
// the signature alone: its declared comment length must reach exactly to
// the end of the archive, otherwise random "PK\005\006" bytes (including
// those planted inside a comment) are rejected.
function findEocd(src: ByteSource): bigint {
  const length = src.byteLength;
  if (length < BigInt(EOCD_FIXED_SIZE)) {
    throw new ZipParseError('eocd', length, 'archive too short to contain an end-of-central-directory record');
  }
  const lastCandidate = length - BigInt(EOCD_FIXED_SIZE);
  let firstCandidate = 0n;
  const earliest = length - BigInt(EOCD_FIXED_SIZE + MAX_EOCD_COMMENT);
  if (earliest > 0n) firstCandidate = earliest;

  for (let pos = lastCandidate; pos >= firstCandidate; pos--) {
    if (src.readByte(pos) !== 0x50 || src.readByte(pos + 1n) !== 0x4b) continue;
    const sig = new Cursor(src, pos).u32('eocd.signature');
    if (sig !== BigInt(SIG_EOCD)) continue;
    // Validate the comment length reaches exactly EOF before accepting.
    const commentLen = new Cursor(src, pos + 20n).u16('eocd.commentLength');
    if (pos + BigInt(EOCD_FIXED_SIZE + commentLen) === length) {
      return pos;
    }
    // Otherwise the match is coincidental; keep scanning.
  }
  throw new ZipParseError('eocd', length, 'end-of-central-directory record not found within the trailing 64 KiB');
}

type ClassicEocd = {
  offset: bigint;
  diskNumber: number;
  cdDisk: number;
  entriesDisk: number;
  totalEntries: number;
  cdSize: bigint;
  cdOffset: bigint;
  commentLength: number;
};

function readClassicEocd(src: ByteSource, offset: bigint): ClassicEocd {
  expectSignature(src, offset, SIG_EOCD, 'eocd.signature');
  const cur = new Cursor(src, offset + 4n);
  const diskNumber = cur.u16('eocd.diskNumber');
  const cdDisk = cur.u16('eocd.cdDisk');
  const entriesDisk = cur.u16('eocd.entriesOnDisk');
  const totalEntries = cur.u16('eocd.totalEntries');
  const cdSize = cur.u32('eocd.cdSize');
  const cdOffset = cur.u32('eocd.cdOffset');
  const commentLength = cur.u16('eocd.commentLength');
  if (offset + BigInt(EOCD_FIXED_SIZE + commentLength) !== src.byteLength) {
    throw new ZipParseError(
      'eocd.commentLength',
      offset + 20n,
      'end-of-central-directory comment does not reach end of archive',
    );
  }
  return { offset, diskNumber, cdDisk, entriesDisk, totalEntries, cdSize, cdOffset, commentLength };
}

type Zip64Locator = {
  offset: bigint;
  diskNumber: bigint;
  eocd64Offset: bigint;
  totalDisks: bigint;
};

// The locator, when present, always occupies the 20 bytes immediately
// before the classic EOCD.  No fallback scanning: a locator whose declared
// ZIP64 EOCD offset is wrong is an error, never an invitation to search for
// another signature elsewhere.
function readZip64Locator(src: ByteSource, eocdOffset: bigint): Zip64Locator | undefined {
  if (eocdOffset < BigInt(ZIP64_LOCATOR_SIZE)) return undefined;
  const offset = eocdOffset - BigInt(ZIP64_LOCATOR_SIZE);

  const sig = new Cursor(src, offset).u32('zip64Locator.signature');
  if (sig !== BigInt(SIG_ZIP64_LOCATOR)) {
    // Only the canonical locator signature at this exact position may
    // introduce ZIP64 state.
    return undefined;
  }

  const cur = new Cursor(src, offset + 4n);
  const diskNumber = cur.u32('zip64Locator.diskNumber');
  const eocd64Offset = cur.u64('zip64Locator.eocdOffset');
  const totalDisks = cur.u32('zip64Locator.totalDisks');

  if (diskNumber !== 0n) {
    throw new ZipParseError('zip64Locator.diskNumber', offset + 4n, 'multi-disk archives are not supported');
  }
  if (totalDisks !== 1n) {
    throw new ZipParseError('zip64Locator.totalDisks', offset + 16n, 'multi-disk archives are not supported');
  }
  if (eocd64Offset + BigInt(ZIP64_EOCD_FIXED_SIZE) !== offset) {
    throw new ZipParseError(
      'zip64Locator.eocdOffset',
      offset + 8n,
      `ZIP64 end-of-central-directory at 0x${eocd64Offset.toString(16)} does not sit directly before the locator at 0x${offset.toString(16)}`,
    );
  }
  return { offset, diskNumber, eocd64Offset, totalDisks };
}

type Zip64Eocd = {
  totalEntries: bigint;
  entriesDisk: bigint;
  cdSize: bigint;
  cdOffset: bigint;
};

function readZip64Eocd(src: ByteSource, locator: Zip64Locator): Zip64Eocd {
  const offset = locator.eocd64Offset;
  expectSignature(src, offset, SIG_ZIP64_EOCD, 'zip64Eocd.signature');
  const cur = new Cursor(src, offset + 4n);
  const recordSize = cur.u64('zip64Eocd.recordSize');
  // Fixed remainder of the ZIP64 EOCD is 44 bytes (56 total minus signature
  // and the size field itself).  Future extensions may append data, but it
  // must not underflow, and the record end must meet the locator exactly.
  if (recordSize < 44n) {
    throw new ZipParseError('zip64Eocd.recordSize', offset + 4n, `implausible ZIP64 EOCD record size ${recordSize}`);
  }
  if (offset + 12n + recordSize !== locator.offset) {
    throw new ZipParseError(
      'zip64Eocd.recordSize',
      offset + 4n,
      'ZIP64 end-of-central-directory record size does not reach the locator',
    );
  }
  cur.skip(2n + 2n); // version made by / version needed
  const diskNumber = cur.u32('zip64Eocd.diskNumber'); // absolute +16
  const cdDisk = cur.u32('zip64Eocd.cdDisk'); // absolute +20
  const entriesDisk = cur.u64('zip64Eocd.entriesOnDisk'); // absolute +24
  const totalEntries = cur.u64('zip64Eocd.totalEntries'); // absolute +32
  const cdSize = cur.u64('zip64Eocd.cdSize'); // absolute +40
  const cdOffset = cur.u64('zip64Eocd.cdOffset'); // absolute +48

  if (diskNumber !== 0n) {
    throw new ZipParseError('zip64Eocd.diskNumber', offset + 16n, 'multi-disk archives are not supported');
  }
  if (cdDisk !== 0n) {
    throw new ZipParseError('zip64Eocd.cdDisk', offset + 20n, 'multi-disk archives are not supported');
  }
  if (entriesDisk !== totalEntries) {
    throw new ZipParseError(
      'zip64Eocd.entriesOnDisk',
      offset + 24n,
      `entries on disk ${entriesDisk} disagrees with total entries ${totalEntries} for a single-disk archive`,
    );
  }
  return { totalEntries, entriesDisk, cdSize, cdOffset };
}

type Zip64Sentinels = {
  uncompressedSize: boolean;
  compressedSize: boolean;
  localHeaderOffset: boolean;
};

type Zip64ExtraValues = {
  uncompressedSize?: bigint;
  compressedSize?: bigint;
  localHeaderOffset?: bigint;
};

// Parse the ZIP64 extended information extra field (0x0001) out of a
// central directory record's extra block.  `extraBase` is the absolute
// offset of the extra block so error messages can name exact positions.
//
// APPNOTE 4.5.3 fixes the field order (uncompressed size, compressed size,
// local header offset, disk start) and says a field is present exactly when
// the corresponding classic field holds its sentinel.  We therefore read
// precisely the fields the sentinels demand, in that order.
function readZip64Extra(
  extra: Uint8Array,
  extraBase: bigint,
  need: Zip64Sentinels,
): Zip64ExtraValues {
  const values: Zip64ExtraValues = {};
  let sawZip64 = false;
  let p = 0;
  while (p < extra.length) {
    if (p + 4 > extra.length) {
      throw new ZipParseError(
        'centralEntry.extra',
        extraBase + BigInt(p),
        'extra field header truncated',
      );
    }
    const id = extra[p] | (extra[p + 1] << 8);
    const size = extra[p + 2] | (extra[p + 3] << 8);
    const dataStart = p + 4;
    if (dataStart + size > extra.length) {
      throw new ZipParseError(
        'centralEntry.extra',
        extraBase + BigInt(p + 2),
        `extra field 0x${id.toString(16)} declares ${size} bytes but only ${extra.length - dataStart} remain`,
      );
    }
    if (id === 0x0001) {
      if (sawZip64) {
        throw new ZipParseError('zip64Extra', extraBase + BigInt(p), 'duplicate ZIP64 extra field');
      }
      sawZip64 = true;

      const order: { key: keyof Zip64Sentinels; out: keyof Zip64ExtraValues }[] = [
        { key: 'uncompressedSize', out: 'uncompressedSize' },
        { key: 'compressedSize', out: 'compressedSize' },
        { key: 'localHeaderOffset', out: 'localHeaderOffset' },
      ];
      let q = dataStart;
      for (const { key, out } of order) {
        if (!need[key]) continue;
        if (q + 8 > dataStart + size) {
          throw new ZipParseError(
            'zip64Extra.' + out,
            extraBase + BigInt(q),
            'ZIP64 extra field ends before the 64-bit replacement value',
          );
        }
        values[out] = readUint64LE(extra, q);
        q += 8;
      }
      if (q !== dataStart + size) {
        throw new ZipParseError(
          'zip64Extra',
          extraBase + BigInt(q),
          `ZIP64 extra field has ${dataStart + size - q} unexpected trailing byte(s)`,
        );
      }
    }
    p = dataStart + size;
  }
  return values;
}

export function parseZipIndex(source: ByteSource | Uint8Array): ZipIndex {
  const src: ByteSource = source instanceof Uint8Array ? new Uint8ArraySource(source) : source;

  const eocdOffset = findEocd(src);
  const eocd = readClassicEocd(src, eocdOffset);
  const locator = readZip64Locator(src, eocdOffset);

  let totalEntries: bigint;
  let entriesDisk: bigint;
  let cdSize: bigint;
  let cdOffset: bigint;

  if (locator) {
    const z64 = readZip64Eocd(src, locator);

    // Classic u16 disk/count fields are either the u16 sentinel (0xffff,
    // meaning "consult ZIP64") or their real value; u32 size/offset fields
    // use the u32 sentinel (0xffffffff).
    const checkU16 = (classic: number, zip64Value: bigint, field: string, rel: bigint) => {
      const v = BigInt(classic);
      if (v !== U16_SENTINEL && v !== zip64Value) {
        throw new ZipParseError(
          field,
          eocdOffset + rel,
          `classic value ${classic} disagrees with ZIP64 value ${zip64Value}`,
        );
      }
    };
    checkU16(eocd.diskNumber, 0n, 'eocd.diskNumber', 4n);
    checkU16(eocd.cdDisk, 0n, 'eocd.cdDisk', 6n);
    checkU16(eocd.entriesDisk, z64.entriesDisk, 'eocd.entriesOnDisk', 8n);
    checkU16(eocd.totalEntries, z64.totalEntries, 'eocd.totalEntries', 10n);

    const checkU32 = (classic: bigint, zip64Value: bigint, field: string, rel: bigint) => {
      if (classic !== U32_SENTINEL && classic !== zip64Value) {
        throw new ZipParseError(
          field,
          eocdOffset + rel,
          `classic value ${classic} disagrees with ZIP64 value ${zip64Value}`,
        );
      }
    };
    checkU32(eocd.cdSize, z64.cdSize, 'eocd.cdSize', 12n);
    checkU32(eocd.cdOffset, z64.cdOffset, 'eocd.cdOffset', 16n);

    totalEntries = z64.totalEntries;
    entriesDisk = z64.entriesDisk;
    cdSize = z64.cdSize;
    cdOffset = z64.cdOffset;
  } else {
    if (eocd.diskNumber !== 0) {
      throw new ZipParseError('eocd.diskNumber', eocdOffset + 4n, 'multi-disk archives are not supported');
    }
    if (eocd.cdDisk !== 0) {
      throw new ZipParseError('eocd.cdDisk', eocdOffset + 6n, 'multi-disk archives are not supported');
    }
    const requireU16 = (value: number, field: string, rel: bigint): bigint => {
      if (value === Number(U16_SENTINEL)) {
        throw new ZipParseError(
          field,
          eocdOffset + rel,
          'canonical ZIP64 sentinel 0xffff without a ZIP64 end-of-central-directory locator',
        );
      }
      return BigInt(value);
    };
    const requireU32 = (value: bigint, field: string, rel: bigint): bigint => {
      if (value === U32_SENTINEL) {
        throw new ZipParseError(
          field,
          eocdOffset + rel,
          'canonical ZIP64 sentinel 0xffffffff without a ZIP64 end-of-central-directory locator',
        );
      }
      return value;
    };
    entriesDisk = requireU16(eocd.entriesDisk, 'eocd.entriesOnDisk', 8n);
    totalEntries = requireU16(eocd.totalEntries, 'eocd.totalEntries', 10n);
    cdSize = requireU32(eocd.cdSize, 'eocd.cdSize', 12n);
    cdOffset = requireU32(eocd.cdOffset, 'eocd.cdOffset', 16n);
  }

  if (entriesDisk !== totalEntries) {
    throw new ZipParseError(
      'eocd.entriesOnDisk',
      eocdOffset + 8n,
      `entries on disk ${entriesDisk} disagrees with total entries ${totalEntries}`,
    );
  }

  // Central directory must lie wholly before the EOCD chain.
  const endBoundary = locator ? locator.offset : eocdOffset;
  if (cdOffset > endBoundary || cdOffset + cdSize > endBoundary) {
    throw new ZipParseError(
      'eocd.cdOffset',
      eocdOffset + 16n,
      `central directory range [0x${cdOffset.toString(16)}, 0x${(cdOffset + cdSize).toString(16)}) runs into the end-of-central-directory at 0x${endBoundary.toString(16)}`,
    );
  }
  if (cdOffset + cdSize > src.byteLength) {
    throw new ZipParseError('eocd.cdSize', eocdOffset + 12n, 'central directory range extends past end of archive');
  }

  const count = toSafeNumber(totalEntries, 'eocd.totalEntries', eocdOffset + 10n);
  const index = new ZipIndex();
  let pos = cdOffset;
  const cdEnd = cdOffset + cdSize;

  for (let i = 0; i < count; i++) {
    if (pos >= cdEnd) {
      throw new ZipParseError(
        'eocd.totalEntries',
        eocdOffset + 10n,
        `central directory ended after ${i} of ${count} declared entries`,
      );
    }

    const entryOffset = pos;
    expectSignature(src, entryOffset, SIG_CENTRAL_FILE, 'centralEntry.signature');
    const cur = new Cursor(src, entryOffset + 4n);
    cur.skip(2n + 2n + 2n); // version made by / needed / flags
    cur.skip(2n + 2n + 2n + 4n); // compression / mod time / mod date / crc32
    const compressedSize = cur.u32('centralEntry.compressedSize'); // +20
    const uncompressedSize = cur.u32('centralEntry.uncompressedSize'); // +24
    const nameLength = cur.u16('centralEntry.nameLength'); // +28
    const extraLength = cur.u16('centralEntry.extraLength'); // +30
    const commentLength = cur.u16('centralEntry.commentLength'); // +32
    const diskStart = cur.u16('centralEntry.diskStart'); // +34
    cur.skip(2n + 4n); // internal / external attributes
    const localHeaderOffset = cur.u32('centralEntry.localHeaderOffset'); // +42

    const fixedPart = 46n;
    const recordLength = fixedPart + BigInt(nameLength + extraLength + commentLength);
    if (entryOffset + recordLength > cdEnd) {
      throw new ZipParseError(
        'centralEntry.commentLength',
        entryOffset + 32n,
        `central directory record of ${recordLength} bytes starting at 0x${entryOffset.toString(16)} runs past the declared central directory end 0x${cdEnd.toString(16)}`,
      );
    }

    // Each variable region is bounds-checked independently so truncation
    // errors point at the exact offending field.
    const nameFieldOffset = entryOffset + fixedPart;
    if (nameFieldOffset + BigInt(nameLength) > src.byteLength) {
      throw new ZipParseError('centralEntry.name', nameFieldOffset, 'file name truncated');
    }
    const extraFieldOffset = nameFieldOffset + BigInt(nameLength);
    if (extraFieldOffset + BigInt(extraLength) > src.byteLength) {
      throw new ZipParseError('centralEntry.extra', entryOffset + 30n, 'extra field block truncated');
    }
    const commentFieldOffset = extraFieldOffset + BigInt(extraLength);
    if (commentFieldOffset + BigInt(commentLength) > src.byteLength) {
      throw new ZipParseError('centralEntry.comment', entryOffset + 32n, 'comment truncated');
    }

    const nameBytes = src.readBytes(nameFieldOffset, nameLength);
    const extra = src.readBytes(extraFieldOffset, extraLength);
    const name = dec.decode(nameBytes);

    if (BigInt(diskStart) === U16_SENTINEL) {
      throw new ZipParseError(
        'centralEntry.diskStart',
        entryOffset + 34n,
        'sentinel disk start number requires multi-disk ZIP64 support',
      );
    }
    if (diskStart !== 0) {
      throw new ZipParseError('centralEntry.diskStart', entryOffset + 34n, 'multi-disk archives are not supported');
    }

    const need: Zip64Sentinels = {
      uncompressedSize: uncompressedSize === U32_SENTINEL,
      compressedSize: compressedSize === U32_SENTINEL,
      localHeaderOffset: localHeaderOffset === U32_SENTINEL,
    };
    const zip64 = readZip64Extra(extra, extraFieldOffset, need);

    let size = uncompressedSize;
    let offset = localHeaderOffset;
    if (need.uncompressedSize) {
      if (zip64.uncompressedSize === undefined) {
        throw new ZipParseError(
          'zip64Extra.uncompressedSize',
          extraFieldOffset,
          'uncompressed size sentinel present but ZIP64 extra field is missing',
        );
      }
      size = zip64.uncompressedSize;
    }
    if (need.compressedSize && zip64.compressedSize === undefined) {
      throw new ZipParseError(
        'zip64Extra.compressedSize',
        extraFieldOffset,
        'compressed size sentinel present but ZIP64 extra field is missing',
      );
    }
    if (need.localHeaderOffset) {
      if (zip64.localHeaderOffset === undefined) {
        throw new ZipParseError(
          'zip64Extra.localHeaderOffset',
          extraFieldOffset,
          'local header offset sentinel present but ZIP64 extra field is missing',
        );
      }
      offset = zip64.localHeaderOffset;
    }

    // The local header must exist inside the archive and carry the local
    // file signature; no guesswork or scanning.
    if (offset + 30n > src.byteLength) {
      throw new ZipParseError(
        'centralEntry.localHeaderOffset',
        entryOffset + 42n,
        `local header at 0x${offset.toString(16)} is outside the archive`,
      );
    }
    expectSignature(src, offset, SIG_LOCAL_FILE, 'localHeader.signature');

    index.add({ name, size, offset, extra });
    pos = commentFieldOffset + BigInt(commentLength);
  }

  if (pos !== cdEnd) {
    throw new ZipParseError(
      'eocd.cdSize',
      eocdOffset + 12n,
      `${count} entries consumed 0x${(pos - cdOffset).toString(16)} central directory bytes but 0x${cdSize.toString(16)} were declared`,
    );
  }

  return index;
}
