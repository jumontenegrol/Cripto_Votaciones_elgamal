const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const CANDIDATES = [
  { id: 'c1', name: 'Valeria Rojas', group: 'Lista Horizonte', color: '#7d1f35', initials: 'VR' },
  { id: 'c2', name: 'Mateo Cardenas', group: 'Lista Campus Abierto', color: '#416b43', initials: 'MC' },
  { id: 'c3', name: 'Sara Villamil', group: 'Lista Raiz Universitaria', color: '#34556c', initials: 'SV' },
];
const VOTER_COUNT = 100;

// OpenSSL's standardized MODP 2048-bit group. Squaring its generator places it
// in the order-q subgroup used by this educational ElGamal construction.
const dh = crypto.getDiffieHellman('modp14');
const P = BigInt(`0x${dh.getPrime().toString('hex')}`);
const Q = (P - 1n) / 2n;
const G = (BigInt(`0x${dh.getGenerator().toString('hex')}`) ** 2n) % P;
const privateKey = randomScalar();
const publicKey = powMod(G, privateKey, P);

let opened = true;
let usedVoters = new Set();
let board = [];
let result = null;

function mod(a, n) { const r = a % n; return r < 0n ? r + n : r; }
function powMod(base, exp, modulus) {
  let b = mod(base, modulus), e = exp, out = 1n;
  while (e > 0n) { if (e & 1n) out = (out * b) % modulus; b = (b * b) % modulus; e >>= 1n; }
  return out;
}
function inv(a, n) { return powMod(a, n - 2n, n); }
function dec(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  const value = String(v);
  const digits = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (!/^[0-9a-f]+$/i.test(digits)) throw new Error('Valor hexadecimal invalido en la papeleta.');
  return BigInt(`0x${digits}`);
}
function hex(v) { return v.toString(16); }
function randomScalar() {
  const nbytes = Math.ceil(Q.toString(2).length / 8);
  while (true) {
    const x = BigInt(`0x${crypto.randomBytes(nbytes).toString('hex')}`);
    if (x > 0n && x < Q) return x;
  }
}
function hashScalar(parts) {
  const digest = crypto.createHash('sha256').update(parts.join('|'), 'utf8').digest('hex');
  return BigInt(`0x${digest}`) % Q;
}
function validElement(x) { return x > 0n && x < P && powMod(x, Q, P) === 1n; }
function transcript(domain, statement, commitments) {
  return hashScalar([domain, statement, ...commitments.map(hex)]);
}
function verifyBitProof(ct, proof, index) {
  const a = dec(ct.a), b = dec(ct.b);
  if (!validElement(a) || !validElement(b)) return 'el criptograma no pertenece al subgrupo esperado';
  if (!Array.isArray(proof) || proof.length !== 2) return 'la prueba de bit tiene una estructura invalida';
  const commitments = [];
  const cs = [], zs = [];
  for (let bit = 0; bit <= 1; bit++) {
    const branch = proof[bit];
    const c = dec(branch.c), z = dec(branch.z);
    if (c < 0n || c >= Q || z < 0n || z >= Q) return 'la prueba de bit contiene un escalar fuera de rango';
    const d = mod(b * inv(powMod(G, BigInt(bit), P), P), P);
    const t1 = mod(powMod(G, z, P) * inv(powMod(a, c, P), P), P);
    const t2 = mod(powMod(publicKey, z, P) * inv(powMod(d, c, P), P), P);
    commitments.push(t1, t2); cs.push(c); zs.push(z);
  }
  const statement = `${index}:${hex(a)}:${hex(b)}`;
  if (mod(cs[0] + cs[1], Q) !== transcript('elgamal-bit-v1', statement, commitments))
    return 'no coincide el reto Fiat-Shamir de la prueba 0/1';
  return null;
}
function verifyEqualityProof(secondBase, firstValue, secondValue, proof, domain, statement) {
  const base2 = dec(secondBase), value1 = dec(firstValue), value2 = dec(secondValue);
  const T1 = dec(proof.T1), T2 = dec(proof.T2), c = dec(proof.c), z = dec(proof.z);
  if (![base2, value1, value2, T1, T2].every(validElement) || c < 0n || c >= Q || z < 0n || z >= Q) return false;
  const expected = transcript(domain, statement, [T1, T2]);
  return c === expected && powMod(G, z, P) === mod(T1 * powMod(value1, c, P), P)
    && powMod(base2, z, P) === mod(T2 * powMod(value2, c, P), P);
}
function validateBallot(ballot) {
  if (!ballot || !Array.isArray(ballot.ciphertexts) || ballot.ciphertexts.length !== CANDIDATES.length
      || !Array.isArray(ballot.bitProofs) || ballot.bitProofs.length !== CANDIDATES.length) return 'la estructura debe tener tres criptogramas y tres pruebas';
  for (let i = 0; i < CANDIDATES.length; i++) {
    const error = verifyBitProof(ballot.ciphertexts[i], ballot.bitProofs[i], i);
    if (error) return `candidatura ${i + 1}: ${error}`;
  }
  let A = 1n, B = 1n;
  for (const ct of ballot.ciphertexts) { A = (A * dec(ct.a)) % P; B = (B * dec(ct.b)) % P; }
  const BdivG = mod(B * inv(G, P), P);
  const statement = `sum-one:${hex(A)}:${hex(BdivG)}`;
  if (!verifyEqualityProof(publicKey, A, BdivG, ballot.sumProof, 'elgamal-sum-v1', statement))
    return 'la prueba de que la papeleta suma exactamente uno no es valida';
  return null;
}
function stable(value) { return JSON.stringify(value); }
function boardEntry(ballot) {
  const previousHash = board.length ? board[board.length - 1].hash : '0'.repeat(64);
  const entry = { index: board.length + 1, previousHash, ballot };
  entry.hash = crypto.createHash('sha256').update(stable(entry)).digest('hex');
  return entry;
}
function publicState() {
  return { candidates: CANDIDATES, voterCount: VOTER_COUNT, votedCount: usedVoters.size,
    availableVoterIds: Array.from({ length: VOTER_COUNT }, (_, i) => `V${String(i + 1).padStart(3, '0')}`).filter(id => !usedVoters.has(id)),
    opened, board, result, publicKey: hex(publicKey), p: hex(P), q: hex(Q), g: hex(G) };
}
function tally() {
  const totals = CANDIDATES.map(() => ({ A: 1n, B: 1n }));
  for (const entry of board) entry.ballot.ciphertexts.forEach((ct, i) => {
    totals[i].A = totals[i].A * dec(ct.a) % P;
    totals[i].B = totals[i].B * dec(ct.b) % P;
  });
  const candidates = totals.map(({ A, B }, i) => {
    const D = powMod(A, privateKey, P), encoded = mod(B * inv(D, P), P);
    let count = 0, value = 1n;
    while (value !== encoded && count <= board.length) { value = value * G % P; count++; }
    if (value !== encoded) throw new Error('No se pudo recuperar el total acotado');
    const w = randomScalar(), T1 = powMod(G, w, P), T2 = powMod(A, w, P);
    const statement = `decrypt:${i}:${hex(A)}:${hex(D)}`;
    const c = transcript('elgamal-decrypt-v1', statement, [T1, T2]);
    const z = mod(w + c * privateKey, Q);
    return { count, A: hex(A), D: hex(D), proof: { T1: hex(T1), T2: hex(T2), c: hex(c), z: hex(z) } };
  });
  return { candidates, totalVotes: board.length, closedAt: new Date().toISOString() };
}
function verifyAudit() {
  let prev = '0'.repeat(64);
  for (const entry of board) {
    if (entry.previousHash !== prev) return { ok: false, message: `Enlace anterior invalido en papeleta ${entry.index}` };
    const body = { index: entry.index, previousHash: entry.previousHash, ballot: entry.ballot };
    const h = crypto.createHash('sha256').update(stable(body)).digest('hex');
    if (h !== entry.hash) return { ok: false, message: `Hash invalido en papeleta ${entry.index}` };
    const ballotError = validateBallot(entry.ballot);
    if (ballotError) return { ok: false, message: `Prueba invalida en papeleta ${entry.index}: ${ballotError}` };
    prev = entry.hash;
  }
  if (result) {
    if (result.candidates.reduce((sum, x) => sum + x.count, 0) !== result.totalVotes)
      return { ok: false, message: 'Los totales no suman el total de votos' };
    for (let i = 0; i < result.candidates.length; i++) {
      const x = result.candidates[i];
      const A = dec(x.A), D = dec(x.D), encoded = mod((() => {
        let b = 1n; for (const entry of board) b = b * dec(entry.ballot.ciphertexts[i].b) % P; return b;
      })() * inv(D, P), P);
      if (powMod(G, BigInt(x.count), P) !== encoded) return { ok: false, message: `Conteo invalido para ${CANDIDATES[i].name}` };
      const statement = `decrypt:${i}:${hex(A)}:${hex(D)}`;
      if (!verifyEqualityProof(A, publicKey, D, x.proof, 'elgamal-decrypt-v1', statement)) return { ok: false, message: `Prueba de descifrado invalida para ${CANDIDATES[i].name}` };
    }
  }
  return { ok: true, message: `Auditoria correcta: ${board.length} papeletas verificadas${result ? ' y conteo comprobado' : ''}.` };
}
function send(res, status, data, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(type.startsWith('application/json') ? JSON.stringify(data) : data);
}
function readBody(req) { return new Promise((resolve, reject) => { let s = ''; req.on('data', c => { s += c; if (s.length > 3_000_000) reject(new Error('Cuerpo demasiado grande')); }); req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch { reject(new Error('JSON invalido')); } }); req.on('error', reject); }); }
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, publicState());
    if (req.method === 'POST' && url.pathname === '/api/vote') {
      const body = await readBody(req);
      if (!opened) return send(res, 409, { error: 'La eleccion esta cerrada.' });
      if (!/^V\d{3}$/.test(body.voterId || '') || Number(body.voterId.slice(1)) < 1 || Number(body.voterId.slice(1)) > VOTER_COUNT)
        return send(res, 400, { error: 'Selecciona una identidad simulada valida.' });
      if (usedVoters.has(body.voterId)) return send(res, 409, { error: 'Esta identidad simulada ya voto.' });
      const ballotError = validateBallot(body.ballot);
      if (ballotError) return send(res, 400, { error: `La papeleta no es valida: ${ballotError}.` });
      usedVoters.add(body.voterId);
      board.push(boardEntry(body.ballot));
      return send(res, 201, { ok: true, state: publicState() });
    }
    if (req.method === 'POST' && url.pathname === '/api/close') {
      if (!opened) return send(res, 409, { error: 'La eleccion ya esta cerrada.' });
      const previousResult = result;
      result = tally();
      let audit;
      try { audit = verifyAudit(); }
      catch (error) { result = previousResult; throw error; }
      if (!audit.ok) { result = previousResult; return send(res, 500, { error: audit.message }); }
      opened = false;
      return send(res, 200, { state: publicState(), audit });
    }
    if (req.method === 'POST' && url.pathname === '/api/reset') {
      opened = true; usedVoters = new Set(); board = []; result = null;
      return send(res, 200, { state: publicState() });
    }
    if (req.method === 'GET' && url.pathname === '/api/audit') return send(res, 200, verifyAudit());
    const requested = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1));
    const file = path.resolve(__dirname, 'public', requested);
    if (!file.startsWith(path.resolve(__dirname, 'public') + path.sep)) return send(res, 403, 'Prohibido', 'text/plain; charset=utf-8');
    fs.readFile(file, (err, data) => {
      if (err) return send(res, 404, 'No encontrado', 'text/plain; charset=utf-8');
      const ext = path.extname(file);
      const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
      send(res, 200, data, types[ext] || 'application/octet-stream');
    });
  } catch (err) { send(res, 400, { error: err.message || 'Solicitud invalida.' }); }
});
let activePort = PORT;
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE' && activePort < PORT + 10) {
    activePort += 1;
    console.warn(`El puerto ${activePort - 1} esta ocupado; intentando ${activePort}...`);
    server.listen(activePort, '127.0.0.1');
    return;
  }
  console.error(`No se pudo iniciar el servidor: ${error.message}`);
  process.exitCode = 1;
});
server.listen(activePort, '127.0.0.1', () => {
  console.log(`Demo ElGamal disponible en http://localhost:${server.address().port}`);
});
