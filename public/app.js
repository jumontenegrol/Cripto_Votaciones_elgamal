const $ = (selector) => document.querySelector(selector);
const ui = {
  candidates: $('#candidate-grid'), voter: $('#voter-select'), cast: $('#cast-vote'),
  turnout: $('#turnout-count'), progress: $('#turnout-progress'), status: $('#status-pill'),
  board: $('#board-list'), boardCount: $('#board-count'), result: $('#result-section'),
  resultList: $('#result-list'), simulate: $('#simulate-button'), close: $('#close-button'),
  reset: $('#reset-button'), audit: $('#audit-button'), simProgress: $('#simulation-progress'),
  simBar: $('#simulation-progress-bar'), simLabel: $('#simulation-progress-label'), toast: $('#toast'),
};
let state = null;
let selected = null;
let toastTimer;

const mod = (a, n) => ((a % n) + n) % n;
function powMod(base, exp, modulus) {
  let b = mod(base, modulus), e = exp, out = 1n;
  while (e > 0n) { if (e & 1n) out = out * b % modulus; b = b * b % modulus; e >>= 1n; }
  return out;
}
const inverse = (a, n) => powMod(a, n - 2n, n);
const hex = (n) => n.toString(16);
const scalarHex = (s) => BigInt(`0x${s}`);
function randomScalar(q) {
  const bytes = Math.ceil(q.toString(2).length / 8);
  const buf = new Uint8Array(bytes);
  while (true) {
    crypto.getRandomValues(buf);
    const value = BigInt(`0x${Array.from(buf, b => b.toString(16).padStart(2, '0')).join('')}`);
    if (value > 0n && value < q) return value;
  }
}
async function challenge(domain, statement, commitments) {
  const data = [domain, statement, ...commitments.map(hex)].join('|');
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data)));
  const value = BigInt(`0x${Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')}`);
  return value % scalarHex(state.q);
}
function group() {
  return { p: scalarHex(state.p), q: scalarHex(state.q), g: scalarHex(state.g), y: scalarHex(state.publicKey) };
}
async function sameExponentProof(secondBase, witness, domain, statement) {
  const { p, q, g, y } = group();
  const w = randomScalar(q), T1 = powMod(g, w, p), T2 = powMod(secondBase, w, p);
  const c = await challenge(domain, statement, [T1, T2]);
  const z = mod(w + c * witness, q);
  return { T1: hex(T1), T2: hex(T2), c: hex(c), z: hex(z) };
}
async function encryptBit(bit, index) {
  const { p, q, g, y } = group();
  const r = randomScalar(q), a = powMod(g, r, p);
  const b = powMod(y, r, p) * powMod(g, BigInt(bit), p) % p;
  const d = [b, mod(b * inverse(g, p), p)];
  const real = bit, simulated = 1 - bit;
  const c = [0n, 0n], z = [0n, 0n], pairs = [null, null];
  c[simulated] = randomScalar(q); z[simulated] = randomScalar(q);
  pairs[simulated] = [
    powMod(g, z[simulated], p) * inverse(powMod(a, c[simulated], p), p) % p,
    powMod(y, z[simulated], p) * inverse(powMod(d[simulated], c[simulated], p), p) % p,
  ];
  const w = randomScalar(q);
  pairs[real] = [powMod(g, w, p), powMod(y, w, p)];
  const commitments = [...pairs[0], ...pairs[1]];
  const statement = `${index}:${hex(a)}:${hex(b)}`;
  c[real] = mod(await challenge('elgamal-bit-v1', statement, commitments) - c[simulated], q);
  z[real] = mod(w + c[real] * r, q);
  return { ciphertext: { a: hex(a), b: hex(b) }, proof: [{ c: hex(c[0]), z: hex(z[0]) }, { c: hex(c[1]), z: hex(z[1]) }], randomness: r };
}
async function makeBallot(choice) {
  const encryptions = [];
  for (let i = 0; i < state.candidates.length; i++) encryptions.push(await encryptBit(i === choice ? 1 : 0, i));
  const { p, q, g, y } = group();
  let A = 1n, B = 1n, witness = 0n;
  for (const item of encryptions) {
    A = A * scalarHex(item.ciphertext.a) % p;
    B = B * scalarHex(item.ciphertext.b) % p;
    witness = mod(witness + item.randomness, q);
  }
  const BdivG = B * inverse(g, p) % p;
  const statement = `sum-one:${hex(A)}:${hex(BdivG)}`;
  const sumProof = await sameExponentProof(y, witness, 'elgamal-sum-v1', statement);
  return { ciphertexts: encryptions.map(x => x.ciphertext), bitProofs: encryptions.map(x => x.proof), sumProof };
}

async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'No fue posible completar la solicitud.');
  return data;
}
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function render() {
  if (!state) return;
  ui.candidates.innerHTML = state.candidates.map((c, i) => `
    <article class="candidate-card ${selected === i ? 'selected' : ''}" data-candidate="${i}" tabindex="0" role="button" aria-pressed="${selected === i}">
      <div class="candidate-banner"><span class="candidate-number">CANDIDATURA 0${i + 1}</span><span class="candidate-initials">${escapeHtml(c.initials)}</span><span class="candidate-title">${escapeHtml(c.name)}</span></div>
      <div class="candidate-body"><div class="candidate-group">${escapeHtml(c.group)}</div><p class="candidate-slogan">Una comunidad universitaria más participativa, abierta y conectada.</p><div class="select-link"><span>${selected === i ? 'Seleccionada' : 'Seleccionar candidatura'}</span><span class="select-indicator">${selected === i ? '✓' : '＋'}</span></div></div>
    </article>`).join('');
  document.querySelectorAll('[data-candidate]').forEach(card => {
    const choose = () => { selected = Number(card.dataset.candidate); render(); };
    card.addEventListener('click', choose);
    card.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); choose(); } });
  });
  const ids = state.availableVoterIds || [];
  ui.voter.innerHTML = ids.length
    ? `<option value="">Selecciona un votante de prueba</option>${ids.map(id => `<option value="${id}">Votante ${id.slice(1)}</option>`).join('')}`
    : '<option value="">No quedan identidades disponibles</option>';
  ui.voter.disabled = !state.opened || !ids.length;
  ui.cast.disabled = !state.opened || selected === null || !ui.voter.value;
  ui.turnout.textContent = state.votedCount;
  ui.progress.style.width = `${state.votedCount}%`;
  ui.boardCount.textContent = `${state.board.length} ${state.board.length === 1 ? 'ENTRADA' : 'ENTRADAS'}`;
  ui.status.textContent = state.opened ? '● ABIERTA' : '● CERRADA';
  ui.status.classList.toggle('closed', !state.opened);
  ui.close.disabled = !state.opened;
  ui.simulate.disabled = !state.opened || !ids.length;
  renderBoard();
  renderResult();
}
function renderBoard() {
  if (!state.board.length) {
    ui.board.innerHTML = '<div class="empty-state"><span class="empty-symbol">⌁</span><p>Aún no hay papeletas en el tablón.</p><small>Las papeletas cifradas aparecerán aquí.</small></div>';
    return;
  }
  ui.board.innerHTML = [...state.board].reverse().map(entry => `<div class="board-row"><span class="entry-id">#${String(entry.index).padStart(3, '0')}</span><span class="entry-hash" title="${entry.hash}">${entry.hash}</span><span class="entry-state">Cifrada · ✓</span></div>`).join('');
}
function renderResult() {
  if (!state.result) { ui.result.classList.add('hidden'); return; }
  ui.result.classList.remove('hidden');
  const max = Math.max(1, ...state.result.candidates.map(c => c.count));
  const ordered = state.result.candidates.map((x, i) => ({ ...x, candidate: state.candidates[i] })).sort((a, b) => b.count - a.count);
  ui.resultList.innerHTML = ordered.map((x, i) => `<div class="result-row ${i === 0 ? 'winner' : ''}"><span class="result-ordinal">0${i + 1}</span><div><div class="result-name">${escapeHtml(x.candidate.name)}${i === 0 ? ' · Mayor votación' : ''}</div><div class="result-track"><span style="width:${(x.count / max) * 100}%"></span></div></div><span class="result-count">${x.count}</span></div>`).join('');
}
async function refresh() {
  state = await api('/api/state');
  const banner = $('#connection-banner');
  if (banner) banner.hidden = true;
  render();
}
function notify(message) {
  ui.toast.textContent = message; ui.toast.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => ui.toast.classList.remove('show'), 3200);
}
async function castVote(voterId, choice, quiet = false) {
  const ballot = await makeBallot(choice);
  const response = await api('/api/vote', { method: 'POST', body: JSON.stringify({ voterId, ballot }) });
  state = response.state;
  render();
  if (!quiet) notify('Papeleta cifrada y aceptada por el tablón.');
}
ui.voter.addEventListener('change', () => { ui.cast.disabled = !state?.opened || selected === null || !ui.voter.value; });
ui.cast.addEventListener('click', async () => {
  if (selected === null || !ui.voter.value) return;
  ui.cast.disabled = true; ui.cast.textContent = 'Cifrando…';
  try { await castVote(ui.voter.value, selected); }
  catch (error) { notify(error.message); await refresh(); }
  finally { ui.cast.innerHTML = 'Emitir voto <span>→</span>'; render(); }
});
ui.simulate.addEventListener('click', async () => {
  const ids = [...(state.availableVoterIds || [])];
  if (!ids.length) return notify('Ya se usaron las 100 identidades simuladas.');
  ui.simulate.disabled = true; ui.cast.disabled = true; ui.simProgress.classList.remove('hidden');
  const initial = state.votedCount;
  try {
    for (let i = 0; i < ids.length; i++) {
      const choice = i % state.candidates.length;
      ui.simLabel.textContent = `Cifrando y verificando voto ${i + 1} de ${ids.length}…`;
      await castVote(ids[i], choice, true);
      ui.simBar.style.width = `${((i + 1) / ids.length) * 100}%`;
      if (i % 3 === 2) await new Promise(resolve => setTimeout(resolve, 0));
    }
    notify(`${state.votedCount - initial} votos simulados y publicados.`);
  } catch (error) { notify(`Simulación detenida: ${error.message}`); }
  finally { ui.simProgress.classList.add('hidden'); ui.simBar.style.width = '0%'; await refresh(); }
});
ui.close.addEventListener('click', async () => {
  if (!confirm('¿Cerrar la elección y publicar el conteo agregado?')) return;
  ui.close.disabled = true; ui.close.textContent = 'Contando…';
  try {
    const data = await api('/api/close', { method: 'POST', body: '{}' });
    state = data.state; render();
    notify(data.audit.message); $('#result-section').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) { notify(error.message); await refresh(); }
  finally { ui.close.innerHTML = 'Cerrar y contar <span>→</span>'; render(); }
});
ui.reset.addEventListener('click', async () => {
  if (!confirm('Se borrarán las papeletas de esta sesión y se reiniciará la simulación. ¿Continuar?')) return;
  try { const data = await api('/api/reset', { method: 'POST', body: '{}' }); selected = null; state = data.state; render(); notify('La simulación se reinició.'); }
  catch (error) { notify(error.message); }
});
ui.audit.addEventListener('click', async () => {
  ui.audit.disabled = true; ui.audit.textContent = 'Verificando…';
  try { const data = await api('/api/audit'); notify(data.message); }
  catch (error) { notify(error.message); }
  finally { ui.audit.innerHTML = 'Verificar elección <span>↗</span>'; ui.audit.disabled = false; }
});
const dialog = $('#info-dialog');
$('#learn-more').addEventListener('click', () => dialog.showModal());
$('#dialog-close').addEventListener('click', () => dialog.close());
$('#dialog-ok').addEventListener('click', () => dialog.close());

refresh().catch(error => notify(`No fue posible conectar con el servidor local: ${error.message}`));
