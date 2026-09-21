export type ZipEntry={name:string;size:bigint;offset:bigint;extra:Uint8Array};
export class ZipIndex{#entries:ZipEntry[]=[];add(entry:ZipEntry){this.#entries.push(entry)}list(){return this.#entries.slice()}find(name:string){return this.#entries.find(entry=>entry.name===name)}}
export function readUint64LE(data:Uint8Array,offset=0){let value=0n;for(let i=0;i<8;i++)value|=BigInt(data[offset+i]??0)<<(8n*BigInt(i));return value}

// ---------------------------------------------------------------------------
// End-of-central-directory parsing.
//
// Every 64-bit value is assembled directly from raw bytes into bigint and
// kept as bigint end to end — nothing is ever routed through a 32-bit
// bitwise result first. A classic 16/32-bit field is taken literally unless
// it holds the canonical ZIP64 sentinel (0xffff / 0xffffffff); only then is
// the matching ZIP64 value consulted. The locator, both EOCD records, the
// central directory range, and the entry count are cross-checked against
// each other, and every conversion from bigint to number is range-checked.
// ---------------------------------------------------------------------------

/** Malformed archive structure. Carries the failing field and its absolute file offset. */
export class ZipFormatError extends Error {
  readonly field: string;
  readonly offset: bigint;

  constructor(field: string, offset: bigint, detail: string) {
    super(`${field} at absolute offset ${offset}: ${detail}`);
    this.name = 'ZipFormatError';
    this.field = field;
    this.offset = offset;
  }
}

const EOCD_SIGNATURE = 0x06054b50;
const EOCD_LENGTH = 22;
const EOCD64_SIGNATURE = 0x06064b50;
const EOCD64_FIXED_LENGTH = 56;
const LOCATOR64_SIGNATURE = 0x07064b50;
const LOCATOR64_LENGTH = 20;
const CENTRAL_SIGNATURE = 0x02014b50;
const CENTRAL_FIXED_LENGTH = 46;
const ZIP64_EXTRA_ID = 0x0001;
const SENTINEL16 = 0xffff;
const SENTINEL32 = 0xffffffff;
const MAX_COMMENT_LENGTH = 0xffff;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

/** A window onto an archive: `data[0]` sits at absolute file offset `base`. */
interface FileView {
  data: Uint8Array;
  base: bigint;
}

function abs(view: FileView, at: number): bigint {
  return view.base + BigInt(at);
}

function fail(field: string, offset: bigint, detail: string): never {
  throw new ZipFormatError(field, offset, detail);
}

function hex32(value: number): string {
  return `0x${(value >>> 0).toString(16).padStart(8, '0')}`;
}

function need(view: FileView, at: number, length: number, field: string): void {
  if (at < 0 || at + length > view.data.length) {
    const from = Math.max(at, 0);
    fail(field, abs(view, from), `truncated: need ${length} bytes but only ${Math.max(0, view.data.length - from)} remain`);
  }
}

function readU16(view: FileView, at: number, field: string): number {
  need(view, at, 2, field);
  return view.data[at] | (view.data[at + 1] << 8);
}

function readU32(view: FileView, at: number, field: string): number {
  need(view, at, 4, field);
  // `>>> 0` yields the exact unsigned 32-bit value; nothing 64-bit is ever
  // built from 32-bit bitwise operators.
  return (view.data[at] | (view.data[at + 1] << 8) | (view.data[at + 2] << 16) | (view.data[at + 3] << 24)) >>> 0;
}

function readU64(view: FileView, at: number, field: string): bigint {
  need(view, at, 8, field);
  return readUint64LE(view.data, at);
}

/** Converts an absolute offset to a buffer index, rejecting anything outside the safe range. */
function toLocalIndex(view: FileView, value: bigint, field: string, fieldAt: bigint): number {
  if (value < 0n || value > MAX_SAFE_BIGINT) {
    fail(field, fieldAt, `${value} is outside the safe integer range 0..${MAX_SAFE_BIGINT}`);
  }
  const local = value - view.base;
  if (local < 0n || local > BigInt(view.data.length)) {
    fail(field, fieldAt, `${value} is outside the buffered range ${view.base}..${view.base + BigInt(view.data.length)}`);
  }
  return Number(local);
}

/**
 * Finds the end of central directory. The candidate closest to the end of
 * the buffer must be consistent (its comment reaches exactly to the end);
 * if it is not, parsing fails instead of scanning further back and possibly
 * accepting a random signature.
 */
function findEocd(view: FileView): number {
  const { data } = view;
  const earliest = Math.max(0, data.length - EOCD_LENGTH - MAX_COMMENT_LENGTH);
  for (let at = data.length - EOCD_LENGTH; at >= earliest; at--) {
    if (data[at] === 0x50 && data[at + 1] === 0x4b && data[at + 2] === 0x05 && data[at + 3] === 0x06) {
      const commentLength = readU16(view, at + 20, 'eocd comment length');
      const recordEnd = at + EOCD_LENGTH + commentLength;
      if (recordEnd !== data.length) {
        fail(
          'eocd comment length',
          abs(view, at + 20),
          `record spans [${abs(view, at)}, ${abs(view, recordEnd)}) but the data ends at ${abs(view, data.length)}; refusing to scan further back for another signature`,
        );
      }
      return at;
    }
  }
  fail('eocd signature', abs(view, data.length), `no end of central directory record found in the last ${Math.min(data.length, EOCD_LENGTH + MAX_COMMENT_LENGTH)} bytes`);
}

/** Where the central directory lives, resolved from the EOCD/ZIP64 chain. */
export interface CentralDirectoryLocation {
  /** Absolute offset of the first central directory byte. */
  readonly offset: bigint;
  /** Size of the whole central directory in bytes. */
  readonly size: bigint;
  /** Total number of entries in the central directory. */
  readonly entryCount: bigint;
  /** True when ZIP64 structures were required to resolve the location. */
  readonly zip64: boolean;
}

function crossCheck(field: string, fieldAt: bigint, classic: number, sentinel: number, zip64: bigint): void {
  if (classic !== sentinel && BigInt(classic) !== zip64) {
    fail(field, fieldAt, `classic value ${classic} disagrees with the zip64 value ${zip64}`);
  }
}

/**
 * Resolves the central directory location from a window containing the end
 * of the archive. `baseOffset` is the absolute file offset of `data[0]`, so
 * archives beyond 4 GiB can be resolved from their tail without buffering
 * the whole file and without ever narrowing an offset to 32 bits.
 */
export function locateCentralDirectory(data: Uint8Array, baseOffset: bigint = 0n): CentralDirectoryLocation {
  const view: FileView = { data, base: baseOffset };
  const eocdAt = findEocd(view);

  const disk = readU16(view, eocdAt + 4, 'eocd disk number');
  if (disk !== 0) fail('eocd disk number', abs(view, eocdAt + 4), `multi-disk archive (this is disk ${disk})`);
  const cdDisk = readU16(view, eocdAt + 6, 'eocd central directory disk');
  if (cdDisk !== 0) fail('eocd central directory disk', abs(view, eocdAt + 6), `multi-disk archive (central directory starts on disk ${cdDisk})`);
  const diskEntries = readU16(view, eocdAt + 8, 'eocd entries on this disk');
  const totalEntries = readU16(view, eocdAt + 10, 'eocd total entries');
  if (diskEntries !== totalEntries) {
    fail('eocd entries on this disk', abs(view, eocdAt + 8), `multi-disk archive (${diskEntries} of ${totalEntries} entries on this disk)`);
  }
  const classicSize = readU32(view, eocdAt + 12, 'eocd central directory size');
  const classicOffset = readU32(view, eocdAt + 16, 'eocd central directory offset');

  const zip64 =
    diskEntries === SENTINEL16 || totalEntries === SENTINEL16 ||
    classicSize === SENTINEL32 || classicOffset === SENTINEL32;

  let offset = BigInt(classicOffset);
  let size = BigInt(classicSize);
  let entryCount = BigInt(totalEntries);
  let offsetFieldAt = abs(view, eocdAt + 16);
  let sizeFieldAt = abs(view, eocdAt + 12);
  let endRecordsAt = abs(view, eocdAt);

  if (zip64) {
    const locatorAt = eocdAt - LOCATOR64_LENGTH;
    if (locatorAt < 0) {
      fail('zip64 locator signature', abs(view, eocdAt), 'classic fields hold ZIP64 sentinels but there is no room for a locator');
    }
    const locatorSignature = readU32(view, locatorAt, 'zip64 locator signature');
    if (locatorSignature !== LOCATOR64_SIGNATURE) {
      fail('zip64 locator signature', abs(view, locatorAt), `classic fields hold ZIP64 sentinels but found ${hex32(locatorSignature)} instead of ${hex32(LOCATOR64_SIGNATURE)}`);
    }
    const locatorDisk = readU32(view, locatorAt + 4, 'zip64 locator disk');
    if (locatorDisk !== 0) fail('zip64 locator disk', abs(view, locatorAt + 4), `multi-disk archive (zip64 eocd is on disk ${locatorDisk})`);
    const eocd64Offset = readU64(view, locatorAt + 8, 'zip64 eocd offset');
    const totalDisks = readU32(view, locatorAt + 16, 'zip64 locator total disks');
    if (totalDisks !== 1) fail('zip64 locator total disks', abs(view, locatorAt + 16), `multi-disk archive (${totalDisks} disks)`);

    const eocd64At = toLocalIndex(view, eocd64Offset, 'zip64 eocd offset', abs(view, locatorAt + 8));
    if (eocd64At + EOCD64_FIXED_LENGTH > locatorAt) {
      fail('zip64 eocd offset', abs(view, locatorAt + 8), `record at ${eocd64Offset} does not fit before the locator at ${abs(view, locatorAt)}`);
    }
    const eocd64Signature = readU32(view, eocd64At, 'zip64 eocd signature');
    if (eocd64Signature !== EOCD64_SIGNATURE) {
      fail('zip64 eocd signature', abs(view, eocd64At), `locator points here but found ${hex32(eocd64Signature)} instead of ${hex32(EOCD64_SIGNATURE)}`);
    }
    const recordSize = readU64(view, eocd64At + 4, 'zip64 eocd record size');
    if (recordSize < 44n) {
      fail('zip64 eocd record size', abs(view, eocd64At + 4), `record size ${recordSize} is smaller than the 44-byte fixed part`);
    }
    const recordEnd = eocd64Offset + 12n + recordSize;
    if (recordEnd > abs(view, locatorAt)) {
      fail('zip64 eocd record size', abs(view, eocd64At + 4), `record ends at ${recordEnd}, past the locator at ${abs(view, locatorAt)}`);
    }
    const disk64 = readU32(view, eocd64At + 16, 'zip64 eocd disk number');
    if (disk64 !== 0) fail('zip64 eocd disk number', abs(view, eocd64At + 16), `multi-disk archive (this is disk ${disk64})`);
    const cdDisk64 = readU32(view, eocd64At + 20, 'zip64 eocd central directory disk');
    if (cdDisk64 !== 0) fail('zip64 eocd central directory disk', abs(view, eocd64At + 20), `multi-disk archive (central directory starts on disk ${cdDisk64})`);
    const diskEntries64 = readU64(view, eocd64At + 24, 'zip64 eocd entries on this disk');
    const totalEntries64 = readU64(view, eocd64At + 32, 'zip64 eocd total entries');
    if (diskEntries64 !== totalEntries64) {
      fail('zip64 eocd entries on this disk', abs(view, eocd64At + 24), `multi-disk archive (${diskEntries64} of ${totalEntries64} entries on this disk)`);
    }
    const size64 = readU64(view, eocd64At + 40, 'zip64 eocd central directory size');
    const offset64 = readU64(view, eocd64At + 48, 'zip64 eocd central directory offset');

    // The locator, both EOCD records, and the classic fields must agree.
    crossCheck('eocd total entries', abs(view, eocdAt + 10), totalEntries, SENTINEL16, totalEntries64);
    crossCheck('eocd entries on this disk', abs(view, eocdAt + 8), diskEntries, SENTINEL16, diskEntries64);
    crossCheck('eocd central directory size', abs(view, eocdAt + 12), classicSize, SENTINEL32, size64);
    crossCheck('eocd central directory offset', abs(view, eocdAt + 16), classicOffset, SENTINEL32, offset64);

    if (totalEntries === SENTINEL16) entryCount = totalEntries64;
    if (classicSize === SENTINEL32) {
      size = size64;
      sizeFieldAt = abs(view, eocd64At + 40);
    }
    if (classicOffset === SENTINEL32) {
      offset = offset64;
      offsetFieldAt = abs(view, eocd64At + 48);
    }
    endRecordsAt = eocd64Offset;
  }

  if (offset > endRecordsAt) {
    fail('eocd central directory offset', offsetFieldAt, `central directory starts at ${offset}, past the end records at ${endRecordsAt}`);
  }
  if (offset + size > endRecordsAt) {
    fail('eocd central directory size', sizeFieldAt, `central directory range [${offset}, ${offset + size}) overlaps the end records at ${endRecordsAt}`);
  }

  return { offset, size, entryCount, zip64 };
}

/** The parsed central directory: its location plus every entry. */
export interface CentralDirectory extends CentralDirectoryLocation {
  readonly entries: ZipIndex;
}

/** Returns the body of the extra field `id`, or null when absent. */
function findExtraField(view: FileView, extraAt: number, extraLength: number, id: number): { at: number; length: number } | null {
  const end = extraAt + extraLength;
  let at = extraAt;
  while (end - at >= 4) {
    const fieldId = readU16(view, at, 'extra field id');
    const length = readU16(view, at + 2, 'extra field size');
    if (at + 4 + length > end) {
      fail('extra field size', abs(view, at + 2), `extra field 0x${fieldId.toString(16).padStart(4, '0')} spans past the end of the extra data`);
    }
    if (fieldId === id) return { at: at + 4, length };
    at += 4 + length;
  }
  if (at !== end) fail('extra field id', abs(view, at), 'truncated extra field header');
  return null;
}

const utf8 = new TextDecoder();

/** Parses the whole central directory of a buffered archive. */
export function readCentralDirectory(data: Uint8Array): CentralDirectory {
  const view: FileView = { data, base: 0n };
  const location = locateCentralDirectory(data);
  const cdStart = toLocalIndex(view, location.offset, 'central directory offset', location.offset);
  const cdEnd = toLocalIndex(view, location.offset + location.size, 'central directory end', location.offset + location.size);

  const entries = new ZipIndex();
  let at = cdStart;
  let seen = 0n;
  while (seen < location.entryCount) {
    if (at + CENTRAL_FIXED_LENGTH > cdEnd) {
      fail('central directory entry', abs(view, at), `truncated: entry header extends past the central directory end at ${abs(view, cdEnd)}`);
    }
    const signature = readU32(view, at, 'central directory entry signature');
    if (signature !== CENTRAL_SIGNATURE) {
      fail('central directory entry signature', abs(view, at), `expected ${hex32(CENTRAL_SIGNATURE)}, found ${hex32(signature)}`);
    }
    const compressedSize = readU32(view, at + 20, 'central directory entry compressed size');
    const uncompressedSize = readU32(view, at + 24, 'central directory entry uncompressed size');
    const nameLength = readU16(view, at + 28, 'central directory entry name length');
    const extraLength = readU16(view, at + 30, 'central directory entry extra length');
    const commentLength = readU16(view, at + 32, 'central directory entry comment length');
    const diskStart = readU16(view, at + 34, 'central directory entry disk start');
    const localOffset = readU32(view, at + 42, 'central directory entry local header offset');

    const recordLength = CENTRAL_FIXED_LENGTH + nameLength + extraLength + commentLength;
    if (at + recordLength > cdEnd) {
      fail('central directory entry', abs(view, at), `entry spans ${recordLength} bytes, past the central directory end at ${abs(view, cdEnd)}`);
    }
    const nameAt = at + CENTRAL_FIXED_LENGTH;
    const extraAt = nameAt + nameLength;
    const name = utf8.decode(data.subarray(nameAt, nameAt + nameLength));
    const extra = data.slice(extraAt, extraAt + extraLength);

    let size = BigInt(uncompressedSize);
    let offset = BigInt(localOffset);
    let disk = diskStart;
    if (uncompressedSize === SENTINEL32 || compressedSize === SENTINEL32 || localOffset === SENTINEL32 || diskStart === SENTINEL16) {
      const body = findExtraField(view, extraAt, extraLength, ZIP64_EXTRA_ID);
      if (body === null) {
        fail('zip64 extra field', abs(view, extraAt), 'classic header holds a 0xffffffff/0xffff sentinel but no zip64 extra field (id 0x0001) is present');
      }
      const bodyEnd = body.at + body.length;
      let p = body.at;
      const take = (width: number, field: string): number => {
        if (p + width > bodyEnd) fail(field, abs(view, p), `zip64 extra field holds only ${body.length} bytes`);
        const found = p;
        p += width;
        return found;
      };
      // Values appear in a fixed order, and only for fields whose classic
      // counterpart holds the canonical sentinel.
      if (uncompressedSize === SENTINEL32) size = readU64(view, take(8, 'zip64 extra uncompressed size'), 'zip64 extra uncompressed size');
      if (compressedSize === SENTINEL32) readU64(view, take(8, 'zip64 extra compressed size'), 'zip64 extra compressed size');
      if (localOffset === SENTINEL32) offset = readU64(view, take(8, 'zip64 extra local header offset'), 'zip64 extra local header offset');
      if (diskStart === SENTINEL16) disk = readU32(view, take(4, 'zip64 extra disk start'), 'zip64 extra disk start');
    }
    if (disk !== 0) {
      fail('central directory entry disk start', abs(view, at + 34), `multi-disk archive (entry starts on disk ${disk})`);
    }

    entries.add({ name, size, offset, extra });
    at += recordLength;
    seen += 1n;
  }
  if (at !== cdEnd) {
    fail('central directory entry count', abs(view, at), `${seen} entries end here but the declared central directory ends at ${abs(view, cdEnd)}`);
  }

  return { ...location, entries };
}
