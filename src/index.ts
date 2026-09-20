export type ZipEntry={name:string;size:bigint;offset:bigint;extra:Uint8Array};
export class ZipIndex{#entries:ZipEntry[]=[];add(entry:ZipEntry){this.#entries.push(entry)}list(){return this.#entries.slice()}find(name:string){return this.#entries.find(entry=>entry.name===name)}}
export function readUint64LE(data:Uint8Array,offset=0){let value=0n;for(let i=0;i<8;i++)value|=BigInt(data[offset+i]??0)<<(8n*BigInt(i));return value}
