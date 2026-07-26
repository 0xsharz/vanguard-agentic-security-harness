'use strict';
/*
 * Node.js preload observer for JavaScript / TypeScript PoCs.
 *
 *     NODE_OPTIONS="--require $PWD/vash_node_observer.js" node poc.js
 *
 * Node loads a `--require` preload before the entry module, so this file wraps
 * the dangerous builtins (`child_process`, `fs`, `net`, `http`/`https`, `vm`)
 * *before* the PoC — or any of the target's own code — can capture a
 * reference to them. Every wrapped call prints a marker line to **stderr** and
 * then delegates to the original, unchanged: the observer must never alter
 * what the PoC does, only report it.
 *
 * Why patching and not a tracer: Node has no audit-hook equivalent (there is
 * no stable diagnostics channel for "a child process was spawned"), and
 * `--inspect` needs a debugger client. Monkey-patching the builtin module
 * objects is the mechanism that works in a plain container with nothing
 * installed.
 *
 * Known limits, stated honestly:
 *  - `eval` / `new Function` are language constructs and cannot be wrapped;
 *    only `vm.*` is observable here.
 *  - An ESM entry point still triggers this preload, but code that reaches the
 *    syscall layer through a native addon bypasses the wrappers entirely.
 *  - Reads of `.js`/`.json`/`.node` files are suppressed because the CommonJS
 *    loader itself goes through `fs.readFileSync` for every `require`.
 *
 * This observer is OPTIONAL instrumentation. If node is missing, or the
 * preload is not used, the PoC still runs — and the absence of observer
 * evidence is NOT evidence that the vulnerability did not reproduce.
 */

const MARKER = '[VASH-OBSERVER]';
const MAX_PER_KIND = 25;
const counts = Object.create(null);

// suppressed for `fs` only: the module loader reads these on every require()
const CODE_FILE_RX = /\.(js|cjs|mjs|json|node|ts|map)$/i;

function emit(kind, detail) {
  try {
    process.stderr.write(MARKER + ' node:' + kind + ' ' + detail + '\n');
  } catch (err) { /* instrumentation must never break the PoC */ }
}

// `  <- from file:line` naming the code that caused the call.
//
// Without it an event line only proves "a process was spawned", which innocent
// code does too. What makes it EVIDENCE is that the call came from the sink
// under test. Node frames (internal/*, node:*) and this observer's own frames
// are skipped; the PoC is NOT skipped on purpose — if the nearest user frame is
// the PoC itself, the PoC reached the sink DIRECTLY and proves nothing about
// the target, and the hunter needs to see that.
function attribution() {
  try {
    const stack = new Error().stack || '';
    const lines = stack.split('\n').slice(1);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line.startsWith('at ')) continue;
      if (line.includes(__filename)) continue;              // this observer
      if (line.includes('node:internal') || line.includes('node:')) continue;
      const m = line.match(/\(?([^()\s]+:\d+:\d+)\)?$/);
      if (m) return '  <- from ' + m[1];
    }
  } catch (err) { /* attribution is best effort */ }
  return '';
}

function record(kind, detail) {
  const seen = (counts[kind] = (counts[kind] || 0) + 1);
  if (seen > MAX_PER_KIND) {
    if (seen === MAX_PER_KIND + 1) {
      emit(kind, '<further occurrences suppressed>');
    }
    return;
  }
  emit(kind, detail + attribution());
}

function describe(args) {
  const parts = [];
  for (let i = 0; i < args.length && i < 3; i++) {
    const a = args[i];
    if (a === null || a === undefined) { parts.push(String(a)); continue; }
    if (typeof a === 'function') { parts.push('[Function]'); continue; }
    if (typeof a === 'string') { parts.push(JSON.stringify(clip(a))); continue; }
    if (typeof a === 'object') {
      let text;
      try { text = JSON.stringify(a); } catch (err) { text = undefined; }
      parts.push(text === undefined ? '[object]' : clip(text));
      continue;
    }
    parts.push(String(a));
  }
  return parts.join(' ');
}

function clip(text) {
  return text.length > 200 ? text.slice(0, 200) + '...<truncated>' : text;
}

function isCodeFile(args) {
  return args.length > 0 && typeof args[0] === 'string' && CODE_FILE_RX.test(args[0]);
}

function wrap(obj, name, kind, skip) {
  if (!obj) { return; }
  const original = obj[name];
  if (typeof original !== 'function') { return; }
  function observed() {
    if (!skip || !skip(arguments)) {
      record(kind, describe(arguments));
    }
    return original.apply(this, arguments);
  }
  try {
    // carry over promisify hooks, `.__promisify__`, custom symbols, etc.
    const descriptors = Object.getOwnPropertyDescriptors(original);
    delete descriptors.length;
    delete descriptors.name;
    delete descriptors.prototype;
    Object.defineProperties(observed, descriptors);
  } catch (err) { /* best effort */ }
  try {
    obj[name] = observed;
  } catch (err) { /* frozen builtin — leave it alone */ }
}

function wrapAll(obj, names, prefix, skip) {
  for (let i = 0; i < names.length; i++) {
    wrap(obj, names[i], prefix + '.' + names[i], skip);
  }
}

try {
  const child_process = require('child_process');
  wrapAll(child_process,
    ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'],
    'child_process');

  const fs = require('fs');
  wrapAll(fs,
    ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile',
     'appendFileSync', 'open', 'openSync', 'unlink', 'unlinkSync', 'rename',
     'renameSync', 'copyFile', 'copyFileSync', 'createReadStream',
     'createWriteStream', 'mkdir', 'mkdirSync', 'rm', 'rmSync'],
    'fs', isCodeFile);

  const net = require('net');
  wrapAll(net, ['connect', 'createConnection'], 'net');
  if (net.Socket && net.Socket.prototype) {
    wrap(net.Socket.prototype, 'connect', 'net.Socket.connect');
  }

  const http = require('http');
  wrapAll(http, ['request', 'get'], 'http');
  const https = require('https');
  wrapAll(https, ['request', 'get'], 'https');

  const vm = require('vm');
  wrapAll(vm, ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction'], 'vm');

  emit('preload-armed', 'pid=' + process.pid + ' node=' + process.version);

  process.on('exit', function () {
    const kinds = Object.keys(counts);
    let total = 0;
    for (let i = 0; i < kinds.length; i++) { total += counts[kinds[i]]; }
    emit('preload-summary', 'observed=' + total + ' ' +
      (kinds.length ? kinds.map(function (k) { return k + '=' + counts[k]; }).join(' ') : 'none') +
      ' (no events observed is NOT proof the vulnerability did not fire)');
  });
} catch (err) {
  emit('preload-error', String(err && err.message ? err.message : err));
}
