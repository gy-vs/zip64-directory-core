# ZIP archive core

TypeScript library for archive records and entries.

Run `npm install`, then `npm test` and `npm run build`.

## API

- `readCentralDirectory(bytes: Uint8Array)` — locates the end-of-central-directory chain (EOCD, ZIP64 locator, ZIP64 EOCD), cross-validates the records against each other, and parses every central directory entry. Offsets, sizes, and counts are `bigint` end to end; 64-bit fields are assembled directly from raw bytes, never through 32-bit bitwise math.
- `locateCentralDirectory(tail: Uint8Array, baseOffset?: bigint)` — resolves only the central directory location from a tail window of a larger archive, so offsets beyond 4 GiB stay exact without buffering the whole file.
- Classic 16/32-bit fields are taken literally unless they hold the canonical ZIP64 sentinel (`0xffff` / `0xffffffff`); only then is the matching ZIP64 EOCD / extra-field (`0x0001`) value consulted.
- Malformed structures throw `ZipFormatError`, which carries the failing `field` and its absolute `offset` (a `bigint`). Parsing never rescans for another signature after a failed candidate.
