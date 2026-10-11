import fs from 'node:fs/promises';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';

export function decodePointer(body) {
  const prefix = 'NotMeter settings pointer v1\n';
  if (typeof body !== 'string' || body.length > 60000 || !body.startsWith(prefix) ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(body.slice(prefix.length))) throw Error('Invalid settings pointer envelope');
  const bytes = gunzipSync(Buffer.from(body.slice(prefix.length), 'base64'), { maxOutputLength: 262144 });
  const value = JSON.parse(bytes);
  if (value.schema !== 'notmeter-settings-cache-v1' || !/^[a-f0-9]{32}$/.test(value.generation) ||
      !['settings-a', 'settings-b'].includes(value.tag)) throw Error('Invalid settings pointer');
  return bytes;
}

export async function resolvePointer(destination = 'manifest.json') {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'NotMeterSettingsCache' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const response = await fetch('https://api.github.com/repos/Not4You-Dev/NotMeter-Settings-Cache/releases/tags/settings-current',
    { headers, signal: AbortSignal.timeout(30000) });
  if (response.status === 404) return false;
  if (!response.ok) throw Error(`Settings pointer request failed: ${response.status}`);
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; if (size > 524288) throw Error('Pointer response too large'); chunks.push(chunk); }
  const bytes = decodePointer(JSON.parse(Buffer.concat(chunks)).body);
  await fs.writeFile(destination, bytes);
  return true;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const ready = await resolvePointer();
  if (process.env.GITHUB_OUTPUT) await fs.appendFile(process.env.GITHUB_OUTPUT, `ready=${ready}\n`);
  console.log(ready ? 'Settings pointer ready for verification.' : 'No settings have been published yet.');
}
