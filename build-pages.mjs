import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

const schema = 'notmeter-settings-cache-v1';
const maxBytes = 512 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const safePath = value => /^(?:entries\/[a-f0-9]{64}|catalog\/[0-9]{4}|(?:kr|tw|ww)\/[a-f0-9]{2})\.json\.gz$/.test(value);
const assert = (condition, message) => { if (!condition) throw Error(message); };

export function verify(manifest, bundle) {
  assert(manifest.schema === schema && /^[a-f0-9]{32}$/.test(manifest.generation) &&
    ['settings-a','settings-b'].includes(manifest.tag) && manifest.bundleName === `settings-${manifest.generation}.tar` &&
    Number.isSafeInteger(manifest.generatedAt) && manifest.generatedAt > 0 &&
    Number.isSafeInteger(manifest.count) && manifest.count >= 0 && manifest.count <= 100000 &&
    Number.isSafeInteger(manifest.totalBytes) && manifest.totalBytes <= maxBytes &&
    Array.isArray(manifest.files) && manifest.files.length <= 768 &&
    (manifest.catalog == null || Array.isArray(manifest.catalog) && manifest.catalog.length <= 200), 'Invalid settings manifest');
  assert(bundle.length === manifest.bundleSize && bundle.length <= 700000000 && digest(bundle) === manifest.bundleSha256, 'Invalid bundle hash or size');
  const files = new Map(); let total = 0;
  for (let offset = 0; offset + 512 <= bundle.length;) {
    const header = bundle.subarray(offset, offset+512); if (header.every(b => b === 0)) break;
    const text = (a,b) => header.subarray(a,b).toString('utf8').replace(/\0.*$/s,'').trim();
    const name = text(0,100), sizeText = text(124,136), checksum = text(148,156);
    const sum = header.reduce((n,b,i) => n + (i >= 148 && i < 156 ? 32 : b), 0);
    assert(safePath(name) && !files.has(name) && /^[0-7]+$/.test(sizeText) && /^[0-7]+$/.test(checksum) &&
      parseInt(checksum,8) === sum && [0,48].includes(header[156]) && text(157,257) === '' && text(345,500) === '', 'Invalid tar entry');
    const size = parseInt(sizeText,8); assert(size > 0 && size <= 1048576 && offset + 512 + size <= bundle.length, 'Invalid tar entry length');
    const bytes = bundle.subarray(offset+512,offset+512+size);
    total += size; assert(total <= maxBytes && files.size <= 100968, 'Cache exceeds storage budget');
    files.set(name, bytes); offset += 512 + Math.ceil(size/512)*512;
  }
  assert(total === manifest.totalBytes, 'Incomplete bundle');
  const referenced = new Set(); let count = 0;
  function read(file) {
    assert(file && safePath(file.path) && /^[a-f0-9]{64}$/.test(file.sha256), 'Invalid index reference');
    const bytes = files.get(file.path); assert(bytes?.length === file.size && digest(bytes) === file.sha256, 'Invalid cached document');
    referenced.add(file.path);
    const value = JSON.parse(gunzipSync(bytes,{ maxOutputLength: 2097152 })); assert(value.schema === schema, 'Invalid document schema'); return value;
  }
  const documents = new Set();
  const identities = new Map();
  for (const file of manifest.files) {
    assert(/^(kr|tw|ww)\/[a-f0-9]{2}\.json\.gz$/.test(file.path), 'Invalid index path');
    const index = read(file); assert(index.entries && typeof index.entries === 'object', 'Invalid index');
    for (const [key, entry] of Object.entries(index.entries)) {
      assert(['KR','TW','WW'].includes(entry.region) && Number.isSafeInteger(entry.serverId) &&
        /^[A-Za-z0-9_+/=-]{12,256}$/.test(entry.characterId) &&
        digest(`${entry.region}:${entry.serverId}:${entry.characterId}`) === key &&
        file.path === `${entry.region.toLowerCase()}/${key.slice(0,2)}.json.gz` &&
        Number.isSafeInteger(entry.updatedAt) && entry.updatedAt > 0 && entry.updatedAt <= manifest.generatedAt, 'Invalid character identity');
      assert(entry.file.path === `entries/${entry.file.sha256}.json.gz`, 'Invalid content address');
      assert(!identities.has(key), 'Duplicate character');
      identities.set(key, entry);
      if (!documents.has(entry.file.path)) {
        const doc = read(entry.file);
        assert(/^NM-SETTINGS-2:[A-Za-z0-9_-]{48,24000}$/.test(doc.settingsCode) && Array.isArray(doc.groups) &&
          Object.keys(doc).every(k => ['schema','settingsCode','groups','summary','previews'].includes(k)), 'Invalid shared settings document');
        if (doc.previews) for (const scene of ['idle','combat','assist']) assert(typeof doc.previews[scene] === 'string' && doc.previews[scene].length <= 524288, 'Invalid preview');
        documents.add(entry.file.path);
      }
      count++;
    }
  }
  if (manifest.catalog != null) {
    const seen = new Set();
    for (const [i, file] of manifest.catalog.entries()) {
      assert(file.path === `catalog/${String(i).padStart(4,'0')}.json.gz`, 'Invalid catalog path');
      const catalog = read(file);
      assert(Array.isArray(catalog.entries) && catalog.entries.length > 0 && catalog.entries.length <= 500, 'Invalid catalog');
      for (const entry of catalog.entries) {
        const key = digest(`${entry.region}:${entry.serverId}:${entry.characterId}`);
        assert(!seen.has(key) && JSON.stringify(identities.get(key)) === JSON.stringify(entry) &&
          Number.isSafeInteger(entry.likes) && entry.likes >= 0 &&
          ['','검성','수호성','살성','궁성','마도성','정령성','치유성','호법성','권성'].includes(entry.job), 'Invalid gallery entry');
        seen.add(key);
      }
    }
    assert(seen.size === count, 'Incomplete gallery');
  }
  assert(count === manifest.count && referenced.size === files.size, 'Unreferenced or missing files');
  assert(digest([...manifest.files,...(manifest.catalog || [])].map(f=>`${f.path}:${f.sha256}`).join('\n')).slice(0,32) === manifest.generation, 'Generation mismatch');
  return files;
}

export async function build({ source = '.', destination = '_site', bundleFile, metadataCache = '.settings-metadata' } = {}) {
  const manifestBytes = await fs.readFile(path.join(source,'manifest.json')); assert(manifestBytes.length <= 262144, 'Manifest too large');
  const manifest = JSON.parse(manifestBytes);
  assert(['settings-a','settings-b'].includes(manifest.tag) && /^settings-[a-f0-9]{32}\.tar$/.test(manifest.bundleName), 'Invalid release pointer');
  let bundle;
  if (bundleFile) bundle = await fs.readFile(bundleFile);
  else {
    const response = await fetch(`https://github.com/Not4You-Dev/NotMeter-Settings-Cache/releases/download/${manifest.tag}/${manifest.bundleName}`, { signal: AbortSignal.timeout(180000) });
    assert(response.ok && Number(response.headers.get('content-length')) <= 700000000, 'Release download failed');
    const chunks=[]; let size=0;
    for await (const chunk of response.body) { size+=chunk.length; assert(size <= 700000000, 'Bundle too large'); chunks.push(chunk); }
    bundle=Buffer.concat(chunks);
  }
  const files=verify(manifest,bundle);
  const current=[...manifest.files,...(manifest.catalog || [])].map(file=>({sha256:file.sha256,size:file.size,data:files.get(file.path).toString('base64')}));
  let previous=[];
  const stateFile=path.join(metadataCache,'state.json');
  try{
    const stat=await fs.stat(stateFile);assert(stat.size<=maxBytes,'Metadata history too large');
    const saved=JSON.parse(await fs.readFile(stateFile,'utf8'));
    if(saved.generation!==manifest.generation)previous=saved.current;
    else previous=saved.previous;
    assert(Array.isArray(previous)&&previous.length<=968,'Invalid metadata history');
  }catch(error){if(error.code!=='ENOENT')throw error;}
  const objects=new Map();
  for(const file of [...previous,...current]){
    assert(/^[a-f0-9]{64}$/.test(file.sha256)&&Number.isSafeInteger(file.size)&&file.size>0&&file.size<=1048576&&typeof file.data==='string'&&file.data.length<=1398104,'Invalid metadata object');
    const bytes=Buffer.from(file.data,'base64');
    assert(bytes.length===file.size&&digest(bytes)===file.sha256,'Invalid metadata history hash');
    objects.set(file.sha256,bytes);
  }
  assert(manifest.totalBytes+[...objects.values()].reduce((n,b)=>n+b.length,0)+manifestBytes.length<1000000000,'Pages storage budget exceeded');
  await fs.mkdir(destination,{recursive:true});
  assert((await fs.readdir(destination)).length===0,'Output must be empty');
  for(const [relative,bytes] of files){const file=path.join(destination,relative);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,bytes);}
  await fs.mkdir(path.join(destination,'objects'),{recursive:true});
  for(const [hash,bytes] of objects){
    await fs.writeFile(path.join(destination,'objects',`${hash}.json.gz`),bytes);
  }
  await fs.writeFile(path.join(destination,'manifest.json'),manifestBytes);
  await fs.writeFile(path.join(destination,'.nojekyll'),'');
  await fs.mkdir(metadataCache,{recursive:true});
  await fs.writeFile(stateFile,JSON.stringify({generation:manifest.generation,current,previous}));
  console.log(JSON.stringify({generation:manifest.generation,characters:manifest.count,files:files.size,bytes:manifest.totalBytes}));
}
if(process.argv[1] && import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) await build({source:process.argv[2]||'.',destination:process.argv[3]||'_site',bundleFile:process.argv[4]});
