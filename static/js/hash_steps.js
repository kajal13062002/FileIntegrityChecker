/* ==========================================================================
   hash_steps.js  -  step-by-step working of the SHA algorithms

   HashSteps.explain(algorithm, bytes) ->
       { steps: [ { title, text, values: [[label, value], ...] } ],
         digest: "hex", complete: true|false }

   Everything shown is REAL data computed from the input bytes:
   padding, message schedule, round values, intermediate hash, final digest.
   The first block is traced in detail; later blocks are processed the same
   way (all of them are computed when the input is small enough).

   Works in the browser (window.HashSteps) and in Node (module.exports).
   ========================================================================== */
(function (root) {
    "use strict";

    /* ---------- tiny helpers ---------------------------------------------- */

    const M32 = 0xFFFFFFFF;
    const M64 = (1n << 64n) - 1n;

    const rotr32 = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
    const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    const rotr64 = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;
    const rotl64 = (x, n) => n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;

    const h32 = (x) => (x >>> 0).toString(16).padStart(8, "0");
    const h64 = (x) => x.toString(16).padStart(16, "0");
    const hexOf = (bytes, from = 0, to = bytes.length) =>
        Array.from(bytes.slice(from, to), (b) => b.toString(16).padStart(2, "0")).join("");

    function short(hex, max = 64) {
        return hex.length > max ? hex.slice(0, max) + "…" : hex;
    }

    function printable(bytes) {
        const head = bytes.slice(0, 40);
        const text = Array.from(head, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "·")).join("");
        return text + (bytes.length > 40 ? "…" : "");
    }

    /* ---------- constants (derived from primes, exactly as the standard does) */

    const PRIMES = [];
    for (let n = 2; PRIMES.length < 80; n++) {
        if (PRIMES.every((p) => n % p !== 0)) PRIMES.push(n);
    }

    function iroot(n, k) {                       // integer k-th root (BigInt)
        let lo = 0n, hi = 1n;
        while (hi ** BigInt(k) <= n) hi <<= 1n;
        while (lo < hi) {
            const mid = (lo + hi + 1n) >> 1n;
            if (mid ** BigInt(k) <= n) lo = mid; else hi = mid - 1n;
        }
        return lo;
    }

    const K256 = PRIMES.slice(0, 64).map((p) => Number(iroot(BigInt(p) << 96n, 3) & 0xFFFFFFFFn));
    const K512 = PRIMES.slice(0, 80).map((p) => iroot(BigInt(p) << 192n, 3) & M64);
    const IV256 = PRIMES.slice(0, 8).map((p) => Number(iroot(BigInt(p) << 64n, 2) & 0xFFFFFFFFn));
    const IV224 = PRIMES.slice(8, 16).map((p) => Number(iroot(BigInt(p) << 128n, 2) & 0xFFFFFFFFn));
    const IV512 = PRIMES.slice(0, 8).map((p) => iroot(BigInt(p) << 128n, 2) & M64);
    const IV384 = PRIMES.slice(8, 16).map((p) => iroot(BigInt(p) << 128n, 2) & M64);
    const IV1 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    const K1 = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

    /* ---------- padding ---------------------------------------------------- */

    function mdPad(bytes, blockSize, lengthBytes) {
        const bitLen = BigInt(bytes.length) * 8n;
        let total = bytes.length + 1 + lengthBytes;
        total = Math.ceil(total / blockSize) * blockSize;
        const out = new Uint8Array(total);
        out.set(bytes);
        out[bytes.length] = 0x80;
        for (let i = 0; i < lengthBytes; i++) {
            out[total - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xFFn);
        }
        return out;
    }

    /* ---------- SHA-512 core (also used to derive SHA-512/t IVs) ----------- */

    function sha512Blocks(H, padded, trace) {
        H = H.slice();
        const blocks = padded.length / 128;
        const info = {};
        for (let b = 0; b < blocks; b++) {
            const W = new Array(80);
            for (let i = 0; i < 16; i++) {
                let v = 0n;
                for (let k = 0; k < 8; k++) v = (v << 8n) | BigInt(padded[b * 128 + i * 8 + k]);
                W[i] = v;
            }
            for (let i = 16; i < 80; i++) {
                const s0 = rotr64(W[i - 15], 1) ^ rotr64(W[i - 15], 8) ^ (W[i - 15] >> 7n);
                const s1 = rotr64(W[i - 2], 19) ^ rotr64(W[i - 2], 61) ^ (W[i - 2] >> 6n);
                W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & M64;
            }
            let [a, bb, c, d, e, f, g, h] = H;
            const start = [a, bb, c, d, e, f, g, h];
            for (let i = 0; i < 80; i++) {
                const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
                const ch = (e & f) ^ ((~e & M64) & g);
                const t1 = (h + S1 + ch + K512[i] + W[i]) & M64;
                const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
                const maj = (a & bb) ^ (a & c) ^ (bb & c);
                const t2 = (S0 + maj) & M64;
                if (trace && b === 0 && i === 0) {
                    info.round1 = { S1, ch, t1, S0, maj, t2 };
                }
                h = g; g = f; f = e; e = (d + t1) & M64;
                d = c; c = bb; bb = a; a = (t1 + t2) & M64;
            }
            const end = [a, bb, c, d, e, f, g, h];
            if (trace && b === 0) { info.W = W; info.start = start; info.end = end; }
            H = H.map((x, i) => (x + end[i]) & M64);
            if (trace && b === 0) info.afterFirst = H.slice();
        }
        return { H, info };
    }

    function deriveIV512t(t) {
        const iv = IV512.map((x) => x ^ 0xa5a5a5a5a5a5a5a5n);
        const text = new TextEncoder().encode("SHA-512/" + t);
        return sha512Blocks(iv, mdPad(text, 128, 16), false).H;
    }

    /* ---------- the explainers ---------------------------------------------- */

    function explainSha1(bytes, label, maxFull) {
        const steps = [];
        const padded = mdPad(bytes, 64, 8);
        const blocks = padded.length / 64;

        steps.push({
            title: "Input message",
            text: "The input is treated as a sequence of bytes (8 bits each).",
            values: [["Length", `${bytes.length} bytes = ${bytes.length * 8} bits`],
                     ["Content", printable(bytes)],
                     ["First bytes (hex)", short(hexOf(bytes, 0, 24), 48) || "(empty)"]]
        });
        steps.push({
            title: "Padding",
            text: "Append a single 1-bit (0x80), then 0-bits until the length is 448 mod 512, then the original length as a 64-bit big-endian number. The result is a whole number of 512-bit blocks.",
            values: [["Padded length", `${padded.length} bytes = ${blocks} block(s) of 512 bits`],
                     ["Last 16 bytes (hex)", hexOf(padded, padded.length - 16)]]
        });
        steps.push({
            title: "Initial hash values (H0–H4)",
            text: "Five fixed 32-bit starting words defined by the standard.",
            values: IV1.map((x, i) => [`H${i}`, h32(x)])
        });

        const full = blocks * 64 <= maxFull;
        const limit = full ? blocks : 1;
        let H = IV1.slice();
        let first = null;

        for (let b = 0; b < limit; b++) {
            const W = new Array(80);
            for (let i = 0; i < 16; i++) {
                W[i] = ((padded[b * 64 + i * 4] << 24) | (padded[b * 64 + i * 4 + 1] << 16) |
                        (padded[b * 64 + i * 4 + 2] << 8) | padded[b * 64 + i * 4 + 3]) >>> 0;
            }
            for (let i = 16; i < 80; i++) W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

            let [a, bb, c, d, e] = H;
            const start = [a, bb, c, d, e];
            let r1 = null;
            for (let i = 0; i < 80; i++) {
                let f, k;
                if (i < 20) { f = ((bb & c) | (~bb & d)) >>> 0; k = K1[0]; }
                else if (i < 40) { f = (bb ^ c ^ d) >>> 0; k = K1[1]; }
                else if (i < 60) { f = ((bb & c) | (bb & d) | (c & d)) >>> 0; k = K1[2]; }
                else { f = (bb ^ c ^ d) >>> 0; k = K1[3]; }
                const temp = (rotl32(a, 5) + f + e + k + W[i]) >>> 0;
                if (b === 0 && i === 0) r1 = { f, k, temp };
                e = d; d = c; c = rotl32(bb, 30); bb = a; a = temp;
            }
            const end = [a, bb, c, d, e];
            H = H.map((x, i) => (x + end[i]) >>> 0);
            if (b === 0) first = { W, start, end, r1, H: H.slice() };
        }

        steps.push({
            title: "Message schedule (block 1)",
            text: "The 512-bit block is split into 16 words W0–W15. Words W16–W79 are built with W[t] = ROTL1(W[t-3] ⊕ W[t-8] ⊕ W[t-14] ⊕ W[t-16]).",
            values: [["W0", h32(first.W[0])], ["W1", h32(first.W[1])], ["W2", h32(first.W[2])],
                     ["W15", h32(first.W[15])], ["W16 (computed)", h32(first.W[16])],
                     ["W79 (computed)", h32(first.W[79])]]
        });
        steps.push({
            title: "Compression – 80 rounds (block 1)",
            text: "Working variables a–e start from H0–H4. Each round: temp = ROTL5(a) + f(b,c,d) + e + K + W[t]; then e=d, d=c, c=ROTL30(b), b=a, a=temp. f and K change every 20 rounds.",
            values: [["a,b,c,d,e before", first.start.map(h32).join(" ")],
                     ["Round 1: f", h32(first.r1.f)], ["Round 1: K", h32(first.r1.k)],
                     ["Round 1: temp (new a)", h32(first.r1.temp)],
                     ["a,b,c,d,e after 80 rounds", first.end.map(h32).join(" ")]]
        });
        steps.push({
            title: "Add to hash state",
            text: "The compressed values are added (mod 2³²) to H0–H4. With more blocks this repeats with the new H.",
            values: [["H after block 1", first.H.map(h32).join(" ")],
                     ["Blocks processed", full ? `${blocks} of ${blocks}` : `1 of ${blocks} shown (rest follow the same steps)`]]
        });
        const digest = full ? H.map(h32).join("") : null;
        steps.push({
            title: "Final digest",
            text: "H0‖H1‖H2‖H3‖H4 written as hex gives the 160-bit SHA-1 digest.",
            values: [["SHA-1", digest || "(see hash result)"]]
        });
        return { steps, digest, complete: full };
    }

    function explainSha2x32(name, bytes, maxFull) {
        const is224 = name === "SHA-224";
        const IV = is224 ? IV224 : IV256;
        const outWords = is224 ? 7 : 8;
        const steps = [];
        const padded = mdPad(bytes, 64, 8);
        const blocks = padded.length / 64;

        steps.push({
            title: "Input message",
            text: "The input is treated as a sequence of bytes (8 bits each).",
            values: [["Length", `${bytes.length} bytes = ${bytes.length * 8} bits`],
                     ["Content", printable(bytes)],
                     ["First bytes (hex)", short(hexOf(bytes, 0, 24), 48) || "(empty)"]]
        });
        steps.push({
            title: "Padding",
            text: "Append a 1-bit (0x80), then 0-bits up to 448 mod 512, then the message length as a 64-bit big-endian number.",
            values: [["Padded length", `${padded.length} bytes = ${blocks} block(s) of 512 bits`],
                     ["Last 16 bytes (hex)", hexOf(padded, padded.length - 16)]]
        });
        steps.push({
            title: "Initial hash values (H0–H7)",
            text: is224
                ? "SHA-224 uses its own eight starting words (taken from the square roots of the 9th–16th primes) and cuts the output to 224 bits."
                : "Eight starting words = first 32 bits of the fractional parts of the square roots of the first 8 primes.",
            values: IV.map((x, i) => [`H${i}`, h32(x)])
        });

        const full = blocks * 64 <= maxFull;
        const limit = full ? blocks : 1;
        let H = IV.slice();
        let first = null;

        for (let b = 0; b < limit; b++) {
            const W = new Array(64);
            for (let i = 0; i < 16; i++) {
                W[i] = ((padded[b * 64 + i * 4] << 24) | (padded[b * 64 + i * 4 + 1] << 16) |
                        (padded[b * 64 + i * 4 + 2] << 8) | padded[b * 64 + i * 4 + 3]) >>> 0;
            }
            for (let i = 16; i < 64; i++) {
                const s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >>> 3);
                const s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >>> 10);
                W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
            }
            let [a, bb, c, d, e, f, g, h] = H;
            const start = [a, bb, c, d, e, f, g, h];
            let r1 = null;
            for (let i = 0; i < 64; i++) {
                const S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
                const ch = ((e & f) ^ (~e & g)) >>> 0;
                const t1 = (h + S1 + ch + K256[i] + W[i]) >>> 0;
                const S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
                const maj = ((a & bb) ^ (a & c) ^ (bb & c)) >>> 0;
                const t2 = (S0 + maj) >>> 0;
                if (b === 0 && i === 0) r1 = { S1, ch, t1, S0, maj, t2 };
                h = g; g = f; f = e; e = (d + t1) >>> 0;
                d = c; c = bb; bb = a; a = (t1 + t2) >>> 0;
            }
            const end = [a, bb, c, d, e, f, g, h];
            H = H.map((x, i) => (x + end[i]) >>> 0);
            if (b === 0) first = { W, start, end, r1, H: H.slice() };
        }

        steps.push({
            title: "Message schedule (block 1)",
            text: "The block gives W0–W15. W16–W63 are built with σ0 = ROTR7 ⊕ ROTR18 ⊕ SHR3 and σ1 = ROTR17 ⊕ ROTR19 ⊕ SHR10: W[t] = W[t-16] + σ0(W[t-15]) + W[t-7] + σ1(W[t-2]).",
            values: [["W0", h32(first.W[0])], ["W1", h32(first.W[1])], ["W15", h32(first.W[15])],
                     ["W16 (computed)", h32(first.W[16])], ["W63 (computed)", h32(first.W[63])]]
        });
        steps.push({
            title: "Compression – 64 rounds (block 1)",
            text: "Working variables a–h start from H0–H7. Each round: T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]; T2 = Σ0(a) + Maj(a,b,c); then the variables shift and e = d + T1, a = T1 + T2. K[t] are 64 constants (cube roots of the first 64 primes).",
            values: [["a…h before", first.start.map(h32).join(" ")],
                     ["Round 1: Σ1(e)", h32(first.r1.S1)], ["Round 1: Ch(e,f,g)", h32(first.r1.ch)],
                     ["Round 1: K[0]", h32(K256[0])], ["Round 1: T1", h32(first.r1.t1)],
                     ["Round 1: Σ0(a)", h32(first.r1.S0)], ["Round 1: Maj(a,b,c)", h32(first.r1.maj)],
                     ["Round 1: T2", h32(first.r1.t2)],
                     ["a…h after 64 rounds", first.end.map(h32).join(" ")]]
        });
        steps.push({
            title: "Add to hash state",
            text: "Each working variable is added (mod 2³²) to its H word. This is the chaining value for the next block.",
            values: [["H after block 1", first.H.map(h32).join(" ")],
                     ["Blocks processed", full ? `${blocks} of ${blocks}` : `1 of ${blocks} shown (rest follow the same steps)`]]
        });
        const digest = full ? H.slice(0, outWords).map(h32).join("") : null;
        steps.push({
            title: "Final digest",
            text: is224
                ? "H0…H6 (the last word is dropped) joined as hex = 224-bit digest."
                : "H0‖H1…‖H7 joined as hex = 256-bit digest.",
            values: [[name, digest || "(see hash result)"]]
        });
        return { steps, digest, complete: full };
    }

    function explainSha2x64(name, bytes, maxFull) {
        const cfg = {
            "SHA-512": { iv: IV512, out: 128, note: "first 64 bits of the square roots of the first 8 primes" },
            "SHA-384": { iv: IV384, out: 96, note: "square roots of the 9th–16th primes (64 bits each)" },
            "SHA-512/256": { iv: deriveIV512t(256), out: 64, note: "generated by running SHA-512 over the text \"SHA-512/256\" (IV ⊕ a5a5…)" },
            "SHA-512/224": { iv: deriveIV512t(224), out: 56, note: "generated by running SHA-512 over the text \"SHA-512/224\" (IV ⊕ a5a5…)" }
        }[name];
        const steps = [];
        const padded = mdPad(bytes, 128, 16);
        const blocks = padded.length / 128;

        steps.push({
            title: "Input message",
            text: "The input is treated as a sequence of bytes (8 bits each).",
            values: [["Length", `${bytes.length} bytes = ${bytes.length * 8} bits`],
                     ["Content", printable(bytes)],
                     ["First bytes (hex)", short(hexOf(bytes, 0, 24), 48) || "(empty)"]]
        });
        steps.push({
            title: "Padding",
            text: "Append a 1-bit (0x80), then 0-bits up to 896 mod 1024, then the message length as a 128-bit big-endian number.",
            values: [["Padded length", `${padded.length} bytes = ${blocks} block(s) of 1024 bits`],
                     ["Last 16 bytes (hex)", hexOf(padded, padded.length - 16)]]
        });
        steps.push({
            title: "Initial hash values (H0–H7)",
            text: `Eight 64-bit starting words: ${cfg.note}.`,
            values: cfg.iv.map((x, i) => [`H${i}`, h64(x)])
        });

        const full = blocks * 128 <= maxFull;
        const run = sha512Blocks(cfg.iv, full ? padded : padded.slice(0, 128), true);
        const info = run.info;

        steps.push({
            title: "Message schedule (block 1)",
            text: "The 1024-bit block gives W0–W15 (64-bit words). W16–W79 use σ0 = ROTR1 ⊕ ROTR8 ⊕ SHR7 and σ1 = ROTR19 ⊕ ROTR61 ⊕ SHR6.",
            values: [["W0", h64(info.W[0])], ["W1", h64(info.W[1])], ["W15", h64(info.W[15])],
                     ["W16 (computed)", h64(info.W[16])], ["W79 (computed)", h64(info.W[79])]]
        });
        steps.push({
            title: "Compression – 80 rounds (block 1)",
            text: "Same structure as SHA-256 but with 64-bit words, 80 rounds, rotations 28/34/39 (Σ0) and 14/18/41 (Σ1), and 80 constants K[t] (cube roots of the first 80 primes).",
            values: [["a…h before", info.start.map(h64).join(" ")],
                     ["Round 1: Σ1(e)", h64(info.round1.S1)], ["Round 1: Ch(e,f,g)", h64(info.round1.ch)],
                     ["Round 1: K[0]", h64(K512[0])], ["Round 1: T1", h64(info.round1.t1)],
                     ["Round 1: Σ0(a)", h64(info.round1.S0)], ["Round 1: Maj(a,b,c)", h64(info.round1.maj)],
                     ["Round 1: T2", h64(info.round1.t2)],
                     ["a…h after 80 rounds", info.end.map(h64).join(" ")]]
        });
        steps.push({
            title: "Add to hash state",
            text: "Each working variable is added (mod 2⁶⁴) to its H word.",
            values: [["H after block 1", info.afterFirst.map(h64).join(" ")],
                     ["Blocks processed", full ? `${blocks} of ${blocks}` : `1 of ${blocks} shown (rest follow the same steps)`]]
        });
        const digest = full ? run.H.map(h64).join("").slice(0, cfg.out) : null;
        steps.push({
            title: "Final digest",
            text: `H0…H7 joined as hex, truncated to ${cfg.out * 4} bits.`,
            values: [[name, digest || "(see hash result)"]]
        });
        return { steps, digest, complete: full };
    }

    /* ---- SHA-3 / Keccak ---- */

    const KECCAK_ROT = (() => {
        const r = Array.from({ length: 5 }, () => new Array(5).fill(0));
        let x = 1, y = 0;
        for (let t = 0; t < 24; t++) {
            r[x][y] = (((t + 1) * (t + 2)) / 2) % 64;
            [x, y] = [y, (2 * x + 3 * y) % 5];
        }
        return r;
    })();

    const KECCAK_RC = (() => {
        const lfsr = (t) => {
            let R = 1;
            for (let i = 1; i <= t % 255; i++) {
                R <<= 1;
                if (R & 0x100) R ^= 0x171;
            }
            return R & 1;
        };
        const rcs = [];
        for (let ir = 0; ir < 24; ir++) {
            let rc = 0n;
            for (let j = 0; j <= 6; j++) {
                if (lfsr(j + 7 * ir)) rc |= 1n << BigInt((1 << j) - 1);
            }
            rcs.push(rc);
        }
        return rcs;
    })();

    function keccakF(A, trace) {
        // A is an array of 25 BigInts, index = x + 5*y
        const info = {};
        for (let round = 0; round < 24; round++) {
            const C = new Array(5), D = new Array(5);
            for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (let i = 0; i < 25; i++) A[i] ^= D[i % 5];
            if (trace && round === 0) { info.C = C.slice(); info.D = D.slice(); info.afterTheta = A.slice(); }

            const B = new Array(25);
            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], KECCAK_ROT[x][y]);
                }
            }
            if (trace && round === 0) info.afterRhoPi = B.slice();

            for (let x = 0; x < 5; x++) {
                for (let y = 0; y < 5; y++) {
                    A[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y] & M64) & B[((x + 2) % 5) + 5 * y]);
                }
            }
            if (trace && round === 0) info.afterChi = A.slice();

            A[0] ^= KECCAK_RC[round];
            if (trace && round === 0) { info.rc = KECCAK_RC[round]; info.afterIota = A.slice(); }
        }
        return info;
    }

    function explainSha3(name, bytes, maxFull) {
        const bits = parseInt(name.split("-")[1], 10);          // 224 / 256 / 384 / 512
        const rate = 200 - 2 * (bits / 8);                      // bytes
        const steps = [];

        const padLen = rate - (bytes.length % rate);
        const padded = new Uint8Array(bytes.length + padLen);
        padded.set(bytes);
        padded[bytes.length] ^= 0x06;
        padded[padded.length - 1] ^= 0x80;
        const blocks = padded.length / rate;

        steps.push({
            title: "Input message",
            text: "The input is treated as a sequence of bytes.",
            values: [["Length", `${bytes.length} bytes = ${bytes.length * 8} bits`],
                     ["Content", printable(bytes)],
                     ["First bytes (hex)", short(hexOf(bytes, 0, 24), 48) || "(empty)"]]
        });
        steps.push({
            title: "Padding (SHA-3 domain bits + pad10*1)",
            text: `SHA-3 is a sponge. The message is padded with the bits 01 (SHA-3 domain tag) followed by pad10*1 so that its length is a multiple of the rate r = ${rate * 8} bits (${rate} bytes). In bytes this adds 0x06 … 0x80 (they merge into 0x86 when only one byte is needed).`,
            values: [["Rate r / capacity c", `${rate * 8} bits / ${1600 - rate * 8} bits`],
                     ["Padded length", `${padded.length} bytes = ${blocks} block(s) of ${rate} bytes`],
                     ["First padding byte", "0x" + padded[bytes.length].toString(16).padStart(2, "0")],
                     ["Last byte", "0x" + padded[padded.length - 1].toString(16).padStart(2, "0")]]
        });

        const full = blocks * rate <= maxFull;
        const limit = full ? blocks : 1;
        const A = new Array(25).fill(0n);
        let first = null;

        for (let b = 0; b < limit; b++) {
            for (let i = 0; i < rate / 8; i++) {
                let lane = 0n;
                for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[b * rate + i * 8 + k]);
                A[i] ^= lane;
            }
            const before = b === 0 ? A.slice() : null;
            const info = keccakF(A, b === 0);
            if (b === 0) first = { before, info, after: A.slice() };
        }

        steps.push({
            title: "Initialise the 1600-bit state",
            text: "The state is a 5×5 grid of 64-bit lanes (25 × 64 = 1600 bits), all zero at the start. The first r bits are the 'rate' part (touched by input), the rest is the 'capacity' (never touched directly – it gives the security).",
            values: [["Lanes", "25 lanes × 64 bits"], ["Start value", "all zeros"]]
        });
        steps.push({
            title: "Absorb block 1 (XOR into state)",
            text: "The block is XORed into the first r bits of the state (as little-endian 64-bit lanes).",
            values: [["Lane A[0,0] after XOR", h64(first.before[0])],
                     ["Lane A[1,0] after XOR", h64(first.before[1])],
                     ["Lane A[2,0] after XOR", h64(first.before[2])]]
        });
        steps.push({
            title: "Keccak-f[1600] – round 1 of 24",
            text: "Each round has 5 steps: θ (column parity mixing), ρ (rotate each lane), π (move lanes), χ (non-linear mixing across rows), ι (XOR a round constant into lane 0).",
            values: [["θ: column parity C[0]", h64(first.info.C[0])],
                     ["θ: D[0] = C[4] ⊕ ROTL1(C[1])", h64(first.info.D[0])],
                     ["θ: A[0,0] after", h64(first.info.afterTheta[0])],
                     ["ρ+π: lane B[0,0]", h64(first.info.afterRhoPi[0])],
                     ["χ: A[0,0] after", h64(first.info.afterChi[0])],
                     ["ι: round constant RC[0]", h64(first.info.rc)],
                     ["ι: A[0,0] after", h64(first.info.afterIota[0])]]
        });
        steps.push({
            title: "All 24 rounds",
            text: "The five steps repeat 24 times with different round constants, thoroughly mixing every bit of the state.",
            values: [["A[0,0] after 24 rounds", h64(first.after[0])],
                     ["A[1,0] after 24 rounds", h64(first.after[1])],
                     ["Blocks absorbed", full ? `${blocks} of ${blocks}` : `1 of ${blocks} shown (rest follow the same steps)`]]
        });

        let digest = null;
        if (full) {
            const out = [];
            for (let i = 0; i < 25 && out.length < bits / 8; i++) {
                let lane = A[i];
                for (let k = 0; k < 8; k++) { out.push(Number(lane & 0xFFn)); lane >>= 8n; }
            }
            digest = hexOf(out.slice(0, bits / 8));
        }
        steps.push({
            title: "Squeeze – final digest",
            text: `The first ${bits} bits of the state (lane bytes in little-endian order) are the digest.`,
            values: [[name, digest || "(see hash result)"]]
        });
        return { steps, digest, complete: full };
    }

    /* ---------- public entry point ----------------------------------------- */

    const LIMITS = { sha1: 4 << 20, sha2: 4 << 20, sha3: 512 << 10 };

    function explain(algorithm, bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        if (algorithm === "SHA-1") return explainSha1(bytes, algorithm, LIMITS.sha1);
        if (algorithm === "SHA-224" || algorithm === "SHA-256") return explainSha2x32(algorithm, bytes, LIMITS.sha2);
        if (["SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"].includes(algorithm)) {
            return explainSha2x64(algorithm, bytes, LIMITS.sha2);
        }
        if (/^SHA3-(224|256|384|512)$/.test(algorithm)) return explainSha3(algorithm, bytes, LIMITS.sha3);
        throw new Error("Unsupported algorithm: " + algorithm);
    }

    const api = { explain };
    if (typeof module !== "undefined" && module.exports) module.exports = api;
    else root.HashSteps = api;
})(typeof window !== "undefined" ? window : globalThis);
