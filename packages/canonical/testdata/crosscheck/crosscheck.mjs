// Test-only cross-check of testdata/vectors.json and observation_vectors.json
// with Node crypto and the upstream JavaScript JCS reference (canonicalize.js,
// see internal/jcs/VENDOR.md).
// No Go code is involved, so expected values are not copied from the Go output.
//
//   node crosscheck.mjs           verify computed fields (exit 1 on mismatch)
//   node crosscheck.mjs --write   recompute computed fields from the templates
//
// Hand-written template fields: catalog.json_value, catalog_variants[] (target_id,
// origin), jcs[].input, normalize[].expect.*_template, normalize[].catalog_variant.
// Template placeholders: {"$digest": v} -> sha256(JCS(v)), {"$digest_ref": "a.b.c"} -> sha256(JCS(vectors.a.b.c)),
// "$content_digest", "$catalog_digest".
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const canonicalize = require('./canonicalize.js');
const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, '..', 'vectors.json');
const observationPath = join(here, '..', 'observation_vectors.json');
const write = process.argv.includes('--write');
const v = JSON.parse(readFileSync(path, 'utf8'));
const observations = JSON.parse(readFileSync(observationPath, 'utf8'));
const sha = (s) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
let failures = 0;

function put(obj, key, value, label) {
  const want = JSON.stringify(value);
  if (write) {
    obj[key] = value;
  } else if (JSON.stringify(obj[key]) !== want) {
    failures++;
    console.error(`MISMATCH ${label}.${key}\n  stored   ${JSON.stringify(obj[key])}\n  computed ${want}`);
  }
}

function resolve(t, ctx) {
  if (t === '$content_digest') return ctx.content_digest;
  if (t === '$catalog_digest') return ctx.catalog_digest;
  if (Array.isArray(t)) return t.map((x) => resolve(x, ctx));
  if (t !== null && typeof t === 'object') {
    if ('$digest' in t) return sha(canonicalize(resolve(t.$digest, ctx)));
    if ('$digest_ref' in t) return sha(canonicalize(t.$digest_ref.split('.').reduce((o, k) => o[k], v)));
    const out = {};
    for (const k of Object.keys(t)) out[k] = resolve(t[k], ctx);
    return out;
  }
  return t;
}

// Catalog digest.
const catJCS = canonicalize(v.catalog.json_value);
put(v.catalog, 'jcs', catJCS, 'catalog');
put(v.catalog, 'catalog_digest', sha(catJCS), 'catalog');
const catalogDigest = sha(catJCS);

// Catalog variants: json_value with one target origin replaced (same
// catalog_version), so catalog_digest must change.
const variantDigests = {};
for (const cv of v.catalog_variants || []) {
  const value = JSON.parse(JSON.stringify(v.catalog.json_value));
  const target = value.targets.find((t) => t.target_id === cv.target_id);
  if (!target) {
    failures++;
    console.error(`catalog variant ${cv.id}: unknown target ${cv.target_id}`);
    continue;
  }
  target.origin = cv.origin;
  const d = sha(canonicalize(value));
  if (d === catalogDigest) {
    failures++;
    console.error(`catalog variant ${cv.id}: catalog_digest did not change`);
  }
  put(cv, 'catalog_digest', d, `catalog variant ${cv.id}`);
  variantDigests[cv.id] = d;
}

// JCS vectors.
for (const c of v.jcs) {
  const out = canonicalize(JSON.parse(c.input));
  if (c.rfc_expected !== undefined && c.rfc_expected !== out) {
    failures++;
    console.error(`MISMATCH jcs ${c.id}: reference output differs from RFC/upstream expected bytes`);
  }
  put(c, 'expected_jcs', out, `jcs ${c.id}`);
  put(c, 'expected_sha256', sha(out), `jcs ${c.id}`);
}

// Normalize vectors.
const digests = {};
for (const c of v.normalize) {
  const e = c.expect;
  if (e.http_status !== undefined) continue; // rejection case, nothing to compute
  if (c.catalog_variant !== undefined && !(c.catalog_variant in variantDigests)) {
    failures++;
    console.error(`normalize ${c.id}: unknown catalog variant ${c.catalog_variant}`);
    continue;
  }
  const ctx = { catalog_digest: c.catalog_variant ? variantDigests[c.catalog_variant] : catalogDigest, content_digest: null };
  if (e.content_input_template === null) {
    put(e, 'content_jcs', null, `normalize ${c.id}`);
    put(e, 'content_digest', null, `normalize ${c.id}`);
  } else {
    const content = canonicalize(resolve(e.content_input_template, ctx));
    ctx.content_digest = sha(content);
    put(e, 'content_jcs', content, `normalize ${c.id}`);
    put(e, 'content_digest', ctx.content_digest, `normalize ${c.id}`);
  }
  const hash = canonicalize(resolve(e.hash_object_template, ctx));
  put(e, 'hash_jcs', hash, `normalize ${c.id}`);
  put(e, 'action_digest', sha(hash), `normalize ${c.id}`);
  if (e.wire === 'content') {
    put(e, 'wire_body_digest', ctx.content_digest, `normalize ${c.id}`);
  } else {
    put(e, 'wire_body_digest', null, `normalize ${c.id}`);
  }
  digests[c.id] = sha(hash);
}

// Equivalence relations.
for (const g of v.equivalence) {
  const ds = g.cases.map((id) => {
    if (!(id in digests)) {
      failures++;
      console.error(`equivalence ${g.id}: unknown or rejected case ${id}`);
    }
    return digests[id];
  });
  const allSame = ds.every((d) => d === ds[0]);
  const allDistinct = new Set(ds).size === ds.length;
  if ((g.same && !allSame) || (!g.same && !allDistinct)) {
    failures++;
    console.error(`equivalence ${g.id}: expected same=${g.same}, digests ${ds.join(' ')}`);
  }
}

// Observation UUIDv5: SHA-1(namespace bytes || UTF-8 name), then set the
// version and variant bits. Derive the namespaces independently of their
// stored values, so changing a namespace and its IDs together still fails.
function uuidV5(namespace, name) {
  const bytes = createHash('sha1')
    .update(Buffer.from(namespace.replaceAll('-', ''), 'hex'))
    .update(name, 'utf8').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const observationNamespaces = {};
for (const stream of ['kernel', 'lifecycle']) {
  const namespace = uuidV5('6ba7b811-9dad-11d1-80b4-00c04fd430c8',
    `https://github.com/Beaver-Dam-Community/Agentarium/${stream}`);
  put(observations.namespaces, stream, namespace, 'observation namespaces');
  observationNamespaces[stream] = namespace;
}
for (const [i, row] of observations.ids.entries()) {
  const name = `${row.source_id}/${row.source_epoch}/${row.source_sequence}`;
  for (const [stream, namespace] of Object.entries(observationNamespaces)) {
    put(row, `${stream}_id`, uuidV5(namespace, name), `observation ID ${i}`);
  }
}
// NetworkPolicyRecord.record_id: a separate namespace and the name
// cluster_uid/node_uid/source_epoch/source_sequence (COMMON NetworkPolicyRecord).
const netpolNamespace = uuidV5('6ba7b811-9dad-11d1-80b4-00c04fd430c8',
  'https://github.com/Beaver-Dam-Community/Agentarium/network-policy');
put(observations.namespaces, 'network-policy', netpolNamespace, 'observation namespaces');
for (const [i, row] of observations.network_policy_ids.entries()) {
  const name = `${row.cluster_uid}/${row.node_uid}/${row.source_epoch}/${row.source_sequence}`;
  put(row, 'record_id', uuidV5(netpolNamespace, name), `network policy ID ${i}`);
}
for (const [i, row] of observations.ranges.entries()) {
  const jcs = canonicalize(row.input);
  put(row, 'jcs', jcs, `observation range ${i}`);
  put(row, 'digest', sha(jcs), `observation range ${i}`);
}

if (write) {
  writeFileSync(observationPath, JSON.stringify(observations, null, 2) + '\n');
  console.log('wrote', observationPath);
  writeFileSync(path, JSON.stringify(v, null, 2) + '\n');
  console.log('wrote', path);
}
if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log('crosscheck ok:', v.jcs.length, 'jcs,', Object.keys(variantDigests).length, 'catalog variants,', Object.keys(digests).length, 'normalize digests,', v.equivalence.length, 'equivalence groups,', Object.keys(observationNamespaces).length, 'observation namespaces,', observations.ids.length * 2, 'observation IDs,', observations.network_policy_ids.length, 'network policy IDs,', observations.ranges.length, 'observation ranges');
