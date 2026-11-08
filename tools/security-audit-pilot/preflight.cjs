#!/usr/bin/env node
'use strict';

// Offline, read-only integrity gate. It does not install or execute the upstream skill.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const UPSTREAM = Object.freeze({
  repository: 'https://github.com/cloudflare/security-audit-skill',
  commit: 'c1c8a8c1471069fb0e188eeaff69b8e8db6564a8',
  license: 'MIT',
});

// Git blob IDs and byte lengths from the immutable upstream commit tree.
// A future update must replace the whole reviewed manifest, not just the commit text.
const FILES = Object.freeze([
  ['LICENSE', '6dbc9ecb3a5b9080e95b962869e8c7ab16cfdc20', 1078],
  ['README.md', 'c80305c88cd5087db37f76a0d230c1fc092c864c', 6950],
  ['skills/security-audit/AI-AND-LLM.md', '02ba9039eca4cec811fefc77bce0d7349b379aae', 10617],
  ['skills/security-audit/ATTACK-CLASSES.md', '18a2beb4dbb554fb52b0a0293b8bd9108207f8fa', 15695],
  ['skills/security-audit/CLIENT-SIDE.md', '8ba673e9e7e3d02f5518aa0219bcbeec7957531b', 8594],
  ['skills/security-audit/CLOUD-AND-DEPLOYMENT.md', '5569f76c7740744aa3f60aaa89eaefe275f2e6c9', 8291],
  ['skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md', '0cba1fa463b62c9b0caba710a201e29c1eecd0ec', 7798],
  ['skills/security-audit/DESKTOP-MOBILE-AND-LOCAL-IPC.md', 'd6230098651bff6348d3868c11f566bfb1306e7f', 8739],
  ['skills/security-audit/HUNTING.md', '377d4dcfbe88a049379448cd7892717185401597', 22446],
  ['skills/security-audit/MEMORY-SAFETY-AND-BINARY.md', '86ff4920752661fc4a31a35ca4f962ace5dd5f48', 10513],
  ['skills/security-audit/PROTOCOLS-RPC-AND-MESSAGING.md', 'b04ab88f852224838fdc9683d9fcccd858b0778a', 7483],
  ['skills/security-audit/RECONNAISSANCE.md', '1a170a93ab76b93dc5ac268a5b690beb423a8aa9', 15902],
  ['skills/security-audit/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md', '6cbbd1e2cfa482068c8279c2f7da9db43d3f54b8', 7476],
  ['skills/security-audit/SKILL.md', '92178dad304d3f63e37582a297026a7874e12c62', 22026],
  ['skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md', 'bf96aed0803bc07471483ab129dea86759c3e305', 7258],
  ['skills/security-audit/VALIDATION-AND-REPORTING.md', '5e200d7387e665e53e0e4190fa4a5814c334c507', 17843],
  ['skills/security-audit/WEB-PROTOCOL-AND-AUTH.md', '1a099fa575cf52a61e9a627f91b61015120fa517', 12300],
  ['skills/security-audit/report-schema.json', '55815a3687a45fff63d8ebf20068611bd6ad6d9a', 14494],
  ['skills/security-audit/validate-coverage-ledger.cjs', '0ef58657bef18b26a92321df6c8e3d31bc8e6659', 33522],
  ['skills/security-audit/validate-coverage-ledger.test.cjs', 'b1444f57e1b021a61175733b8c356171861c8701', 28483],
  ['skills/security-audit/validate-findings.cjs', '2843feceddb7e30bf10d6e4f7bbe6640e4c57799', 28806],
  ['skills/security-audit/validate-findings.test.cjs', '8d245b226bbe2fdf28b46b3203b99c2824039d2d', 26384],
]);

function gitBlobID(content) {
  return crypto.createHash('sha1')
    .update(`blob ${content.length}\0`)
    .update(content)
    .digest('hex');
}

function requiredOpenFlags() {
  if (process.platform !== 'linux' ||
      !Number.isInteger(fs.constants.O_NOFOLLOW) || !fs.constants.O_NOFOLLOW ||
      !Number.isInteger(fs.constants.O_NONBLOCK) || !fs.constants.O_NONBLOCK) {
    throw new Error('unsupported host: the offline gate currently requires Linux no-follow and nonblocking open flags');
  }
  return fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
}

function verifySnapshot(root, manifest = FILES) {
  const flags = requiredOpenFlags();
  // No path component leading to the source root may be a symlink.
  // A descriptor-backed walk below pins directories against rename/replacement.
  if (!path.isAbsolute(root)) throw new Error('source root must be absolute');
  let component = path.parse(root).root;
  for (const part of root.slice(component.length).split(path.sep).filter(Boolean)) {
    if (part === '.' || part === '..') throw new Error('unsafe source root component');
    component = path.join(component, part);
    const stat = fs.lstatSync(component);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('source path has a symlink or non-directory ancestor');
    }
  }
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('source root must be a real directory, not a symlink');
  }
  if (!Number.isInteger(fs.constants.O_DIRECTORY) || !fs.constants.O_DIRECTORY ||
      !fs.existsSync('/proc/self/fd')) {
    throw new Error('Linux descriptor-backed directory scanning is unavailable');
  }
  const expected = new Map();
  const dirs = new Set();
  for (const [name, oid, size] of manifest) {
    if (!/^[A-Za-z0-9._/-]+$/.test(name) || name.startsWith('/') || name.split('/').some(p => p === '..' || p === '' || p === '.')) {
      throw new Error('invalid manifest path');
    }
    if (expected.has(name) || !/^[0-9a-f]{40}$/.test(oid) || !Number.isSafeInteger(size) || size < 0 || size > 1024 * 1024) {
      throw new Error('invalid or duplicated manifest entry');
    }
    expected.set(name, {oid, size});
    const parts = name.split('/');
    for (let i=1;i<parts.length;i++) dirs.add(parts.slice(0,i).join('/'));
  }
  if (!expected.size) throw new Error('empty source manifest');
  const checked = new Set();
  // Use pinned directory descriptors, not path-based recursive descent. A
  // renamed directory cannot redirect descendants outside this open tree.
  function walk(directoryFd, rel) {
    const directoryRef = '/proc/self/fd/' + directoryFd;
    const entries = fs.readdirSync(directoryRef).sort();
    for (const name of entries) {
      const ref = directoryRef + '/' + name;
      if (rel === '' && name === '.git') {
        // Git metadata never contributes to the file-content snapshot.
        const stat = fs.lstatSync(ref);
        if (stat.isSymbolicLink() || !(stat.isDirectory() || stat.isFile())) {
          throw new Error('unsafe git metadata entry');
        }
        continue;
      }
      const key = rel ? rel + '/' + name : name;
      const st = fs.lstatSync(ref);
      if (st.isSymbolicLink()) throw new Error('symlink prohibited: ' + JSON.stringify(key));
      if (st.isDirectory()) {
        if (!dirs.has(key)) throw new Error('unexpected directory: ' + JSON.stringify(key));
        const childFd = fs.openSync(ref, flags | fs.constants.O_DIRECTORY);
        try {
          const opened = fs.fstatSync(childFd);
          if (!opened.isDirectory() || opened.dev !== st.dev || opened.ino !== st.ino) {
            throw new Error('directory changed during check: ' + JSON.stringify(key));
          }
          walk(childFd, key);
        } finally { fs.closeSync(childFd); }
      } else if (st.isFile()) {
        const item = expected.get(key);
        if (!item) throw new Error('unexpected file: ' + JSON.stringify(key));
        if (st.size !== item.size) throw new Error('size mismatch: ' + JSON.stringify(key));
        const fd = fs.openSync(ref, flags);
        let bytes;
        try {
          const opened = fs.fstatSync(fd);
          if (!opened.isFile() || opened.size !== item.size ||
              opened.dev !== st.dev || opened.ino !== st.ino) {
            throw new Error('unsafe or changed file: ' + JSON.stringify(key));
          }
          // Reads only the listed, byte-bounded source files. Never execute them.
          bytes = Buffer.alloc(item.size);
          let offset = 0;
          while (offset < bytes.length) {
            const n = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
            if (n === 0) throw new Error('short read: ' + JSON.stringify(key));
            offset += n;
          }
          const after = fs.fstatSync(fd);
          if (after.size !== item.size || after.mtimeMs !== opened.mtimeMs ||
              after.ctimeMs !== opened.ctimeMs) {
            throw new Error('file changed during check: ' + JSON.stringify(key));
          }
        } finally { fs.closeSync(fd); }
        if (gitBlobID(bytes) !== item.oid) {
          throw new Error('content hash mismatch: ' + JSON.stringify(key));
        }
        checked.add(key);
      } else {
        throw new Error('nonregular entry: ' + JSON.stringify(key));
      }
    }
  }
  const rootFd = fs.openSync(root, flags | fs.constants.O_DIRECTORY);
  try {
    const openedRoot = fs.fstatSync(rootFd);
    if (!openedRoot.isDirectory() || openedRoot.dev !== rootStat.dev ||
        openedRoot.ino !== rootStat.ino) {
      throw new Error('source root changed while opening');
    }
    walk(rootFd, '');
  } finally { fs.closeSync(rootFd); }
  for (const name of expected.keys()) {
    if (!checked.has(name)) throw new Error(`missing file: ${JSON.stringify(name)}`);
  }
  return checked.size;
}

function main(argv) {
  if (argv.length === 1 && argv[0] === '--help') {
    process.stdout.write('Offline source check only. Usage: node preflight.cjs /absolute/path/to/upstream-checkout\n');
    return 0;
  }
  if (argv.length !== 1 || !path.isAbsolute(argv[0])) {
    process.stderr.write('Expected exactly one absolute local directory path. This command never launches a security audit.\n');
    return 2;
  }
  try {
    const count = verifySnapshot(argv[0]);
    process.stdout.write(`PASS: verified ${count} upstream file blobs against pinned ${UPSTREAM.commit}. No target or skill code executed.\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`BLOCKED: ${err.message}\n`);
    return 1;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = {UPSTREAM,FILES,gitBlobID,verifySnapshot,main};
