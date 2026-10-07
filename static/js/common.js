/* ==========================================================================
   common.js  -  helpers shared by the User console and the Admin console
   Sections:  1. Hashing   2. Formatting   3. HTML building blocks
   ========================================================================== */


/* ---------- 1. HASHING (SHA family) -------------------------------------- */

const ALGORITHMS = [
    'SHA-1',
    'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512',
    'SHA-512/224', 'SHA-512/256',
    'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'
];

// These four are built into every browser (Web Crypto API).
const WEB_CRYPTO_ALGORITHMS = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

// The rest come from the small libraries loaded in index.html.
const LIBRARY_HASHERS = {
    'SHA-224':     bytes => sha256.sha224(bytes),
    'SHA-512/224': bytes => sha512.sha512_224(bytes),
    'SHA-512/256': bytes => sha512.sha512_256(bytes),
    'SHA3-224':    bytes => sha3_224(bytes),
    'SHA3-256':    bytes => sha3_256(bytes),
    'SHA3-384':    bytes => sha3_384(bytes),
    'SHA3-512':    bytes => sha3_512(bytes)
};

function toHex(arrayBuffer) {
    return [...new Uint8Array(arrayBuffer)]
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

/** Hash some bytes with ONE algorithm. Returns a hex string, or null if unavailable. */
async function hashBytes(bytes, algorithm) {
    try {
        if (WEB_CRYPTO_ALGORITHMS.includes(algorithm)) {
            return toHex(await crypto.subtle.digest(algorithm, bytes));
        }
        return LIBRARY_HASHERS[algorithm](bytes);
    } catch (error) {
        return null;
    }
}

/** Hash some bytes with MANY algorithms. Returns { 'SHA-256': 'ab12...', ... } */
async function hashAll(bytes, algorithms) {
    const hashes = {};
    for (const algorithm of algorithms) {
        const hash = await hashBytes(bytes, algorithm);
        if (hash) hashes[algorithm] = hash;
    }
    return hashes;
}


/* ---------- 2. FORMATTING ------------------------------------------------ */

const byId = id => document.getElementById(id);

function escapeHtml(text) {
    const replacements = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
    return String(text).replace(/[&<>"]/g, character => replacements[character]);
}

function formatDateTime(date) {
    if (!date) return '—';
    return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}

function formatTime(date) {
    return date.toLocaleTimeString([], { timeStyle: 'short' });
}

function formatSize(bytes) {
    if (bytes < 1024)    return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}


/* ---------- 3. HTML BUILDING BLOCKS -------------------------------------- */

/** Coloured status badge: safe / modified / tampered / active ... */
function pill(status) {
    return `<span class="pill ${status}">${String(status).replace('_', ' ')}</span>`;
}

/** Small blue chip with an algorithm name, e.g. SHA-256 */
function algorithmChip(algorithm) {
    return `<span class="algo">${algorithm}</span>`;
}

/** Monospace hash box */
function hashBox(hash, shownLength = hash.length) {
    const shown = hash.length > shownLength ? hash.slice(0, shownLength) + '…' : hash;
    return `<span class="hash" title="${hash}">${shown}</span>`;
}

/** Page heading with optional action buttons on the right. */
function pageTitle(title, subtitle, actionsHtml = '') {
    return `
        <div class="pt page-head">
            <div>
                <h2>${title}</h2>
                <p>${subtitle}</p>
            </div>
            <div>${actionsHtml}</div>
        </div>`;
}

/** Table. `rows` is an array of <tr> strings. Shows `emptyMessage` when there are no rows. */
function table(headers, rows, emptyMessage) {
    const headerCells = headers.map(title => `<th>${title}</th>`).join('');
    const body = rows.length
        ? rows.join('')
        : `<tr><td class="em" colspan="${headers.length}">${emptyMessage}</td></tr>`;

    return `
        <div class="tw">
            <table>
                <thead><tr>${headerCells}</tr></thead>
                <tbody>${body}</tbody>
            </table>
        </div>`;
}

/** Vertical list of label / value rows (used on the Profile pages). */
function keyValueRows(pairs) {
    return pairs.map(([label, value]) => `
        <div class="kv">
            <span>${label}</span>
            <b>${value}</b>
        </div>`).join('');
}

/** Donut chart. slices = [[label, count, colour], ...] */
function donutChart(slices) {
    const radius = 40;
    const circumference = 2 * Math.PI * radius;
    const total = slices.reduce((sum, slice) => sum + slice[1], 0);

    let offset = 0;
    const rings = total === 0
        ? `<circle cx="60" cy="60" r="${radius}" fill="none" stroke="var(--line)" stroke-width="16"/>`
        : slices.map(([, count, colour]) => {
            const length = circumference * count / total;
            const ring = `<circle cx="60" cy="60" r="${radius}" fill="none" stroke="${colour}" stroke-width="16"
                              stroke-dasharray="${length} ${circumference - length}"
                              stroke-dashoffset="${-offset}" transform="rotate(-90 60 60)"/>`;
            offset += length;
            return ring;
        }).join('');

    return `
        <svg width="130" height="130" viewBox="0 0 120 120">
            ${rings}
            <text x="60" y="66" text-anchor="middle" fill="var(--ink)" font-size="22" font-weight="800">${total}</text>
        </svg>`;
}

/** Horizontal progress bar (0 - 100). */
function progressBar(percent) {
    return `<div class="bar"><i style="width:${percent}%"></i></div>`;
}