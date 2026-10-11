/* ==========================================================================
   fic_tools.js  -  shared tools for the User dashboard AND the Admin console

     1. Basics            escape, size, file kind, hashing
     2. Drop zone         "Click or drag me" box with a PREVIEW (no file name)
     3. Upload progress   XHR upload with a progress bar
     4. Hash Tool         pick ONE algorithm (step-by-step) or ALL (no steps)
     5. Verify result     safe / modified percent bar + algorithm table
     6. Compare           image diff (% + highlighted regions), PDF diff
                          (page / line / word / character), hash match
     7. Monitor           Tamper & Restore table
     8. Charts            donut, bars, stacked columns, report charts

   Needs hash_steps.js (HashSteps). Uses the js-sha libraries when present.
   ========================================================================== */
(function () {
    "use strict";

    const FIC = (window.FIC = {});

    /* ======================================================================
       1. BASICS
       ====================================================================== */

    const esc = (value) =>
        String(value == null ? "" : value).replace(/[&<>"']/g, (c) =>
            ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    FIC.esc = esc;

    FIC.size = (bytes) => {
        bytes = Number(bytes) || 0;
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
        return (bytes / 1073741824).toFixed(2) + " GB";
    };

    FIC.ALGORITHMS = [
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    ];

    const IMAGE_EXT = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "tif", "tiff", "heic", "avif"];
    const VIDEO_EXT = ["mp4", "mkv", "mov", "avi", "webm", "wmv", "flv", "m4v", "3gp", "mpg", "mpeg"];
    const AUDIO_EXT = ["mp3", "wav", "ogg", "m4a", "flac", "aac"];
    const DOC_EXT = ["doc", "docx", "txt", "rtf", "odt", "xls", "xlsx", "csv", "ppt", "pptx", "md", "json", "xml", "html"];

    const extOf = (name) => (String(name || "").split(".").pop() || "").toLowerCase();

    /** image | video | pdf | audio | document | other  (from a File or a file name) */
    FIC.kind = (fileOrName) => {
        const name = typeof fileOrName === "string" ? fileOrName : fileOrName.name;
        const mime = typeof fileOrName === "string" ? "" : fileOrName.type || "";
        const ext = extOf(name);
        if (mime.startsWith("image/") || IMAGE_EXT.includes(ext)) return "image";
        if (mime.startsWith("video/") || VIDEO_EXT.includes(ext)) return "video";
        if (mime === "application/pdf" || ext === "pdf") return "pdf";
        if (mime.startsWith("audio/") || AUDIO_EXT.includes(ext)) return "audio";
        if (DOC_EXT.includes(ext)) return "document";
        return "other";
    };

    const hex = (buffer) =>
        Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");

    const WEB_CRYPTO = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    const LIBRARIES = {
        "SHA-224": (b) => sha256.sha224(b),
        "SHA-512/224": (b) => sha512.sha512_224(b),
        "SHA-512/256": (b) => sha512.sha512_256(b),
        "SHA3-224": (b) => sha3_224(b),
        "SHA3-256": (b) => sha3_256(b),
        "SHA3-384": (b) => sha3_384(b),
        "SHA3-512": (b) => sha3_512(b)
    };

    /** Hash bytes (ArrayBuffer / Uint8Array) with ONE algorithm -> hex string or null. */
    FIC.hash = async (bytes, algorithm) => {
        const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        try {
            if (WEB_CRYPTO.includes(algorithm)) return hex(await crypto.subtle.digest(algorithm, data));
            return LIBRARIES[algorithm](data);
        } catch (error) {
            try {                                   // our own implementation as a fallback
                const result = window.HashSteps.explain(algorithm, data);
                return result.digest || null;
            } catch (inner) {
                return null;
            }
        }
    };

    FIC.hashAll = async (bytes, algorithms = FIC.ALGORITHMS) => {
        const out = {};
        for (const algorithm of algorithms) {
            const value = await FIC.hash(bytes, algorithm);
            if (value) out[algorithm] = value;
        }
        return out;
    };

    const nextFrame = () => new Promise((resolve) => setTimeout(resolve, 30));

    const copyBtn = (text) =>
        `<button type="button" class="fic-btn fic-btn-light fic-btn-sm" data-fic-copy="${esc(text)}">Copy</button>`;

    function bindCopy(root) {
        (root || document).querySelectorAll("[data-fic-copy]").forEach((button) => {
            button.onclick = async () => {
                try { await navigator.clipboard.writeText(button.dataset.ficCopy); } catch (e) { /* ignore */ }
                button.textContent = "Copied ✓";
            };
        });
    }

    const pill = (status) => `<span class="fic-pill fic-${esc(String(status).replace(/\s+/g, "-"))}">${esc(status)}</span>`;
    FIC.pill = pill;

    /* ======================================================================
       2. DROP ZONE  - shows a PREVIEW, never the file name
       ====================================================================== */

    FIC.drop = (id, options = {}) => `
        <div class="fic-drop" data-fic-drop>
            <div class="fic-drop-idle">
                <div class="fic-drop-ico">${options.icon || "☁"}</div>
                <b>${esc(options.label || "Click or drag me")}</b>
                ${options.hint ? `<small>${esc(options.hint)}</small>` : ""}
            </div>
            <div class="fic-drop-prev" hidden></div>
            <button type="button" class="fic-drop-clear" title="Remove" hidden>✕</button>
            <input type="file" id="${id}" hidden
                ${options.accept ? `accept="${esc(options.accept)}"` : ""}
                ${options.multiple ? "multiple" : ""}>
        </div>`;

    function thumb(file, url, single) {
        const kind = FIC.kind(file);
        const badge = `<span class="fic-badge">${kind === "other" ? esc(extOf(file.name) || "file") : kind} · ${FIC.size(file.size)}</span>`;
        if (kind === "image") return `<div class="fic-thumb ${single ? "big" : ""}"><img src="${url}" alt="">${badge}</div>`;
        if (kind === "video") {
            return `<div class="fic-thumb ${single ? "big" : ""}"><video src="${url}#t=0.2" ${single ? "controls" : ""} muted playsinline preload="metadata"></video>
                    ${single ? "" : `<span class="fic-play">▶</span>`}${badge}</div>`;
        }
        if (kind === "pdf") {
            return `<div class="fic-thumb fic-thumb-doc ${single ? "big" : ""}" data-pdf-thumb="${url}">
                        <span class="fic-doc-ico pdf">PDF</span>${badge}</div>`;
        }
        const icon = { pdf: "PDF", audio: "♪", document: "DOC", other: (extOf(file.name) || "FILE").slice(0, 4).toUpperCase() }[kind];
        return `<div class="fic-thumb fic-thumb-doc ${single ? "big" : ""}"><span class="fic-doc-ico ${kind}">${icon}</span>${badge}</div>`;
    }


    /** Render page 1 of a PDF into the thumbnail box (needs pdf.js; keeps the PDF icon if it is missing). */
    FIC.renderPdfThumbs = (root) => {
        (root || document).querySelectorAll("[data-pdf-thumb]").forEach(async (box) => {
            const url = box.dataset.pdfThumb;
            box.removeAttribute("data-pdf-thumb");
            if (!window.pdfjsLib) return;
            try {
                window.pdfjsLib.GlobalWorkerOptions.workerSrc =
                    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
                const pdf = await window.pdfjsLib.getDocument(url).promise;
                const page = await pdf.getPage(1);
                const base = page.getViewport({ scale: 1 });
                const viewport = page.getViewport({ scale: 360 / base.width });
                const canvas = document.createElement("canvas");
                canvas.width = viewport.width;
                canvas.height = viewport.height;
                canvas.style.cssText = "max-width:100%;max-height:100%;background:#fff;border-radius:6px";
                await page.render({ canvasContext: canvas.getContext("2d"), viewport }).promise;
                const icon = box.querySelector(".fic-doc-ico");
                if (icon) icon.replaceWith(canvas);
            } catch (error) { /* keep the icon */ }
        });
    };

    function showPreview(zone, input) {
        (zone._urls || []).forEach((url) => URL.revokeObjectURL(url));
        zone._urls = [];
        const files = [...input.files];
        const idle = zone.querySelector(".fic-drop-idle");
        const prev = zone.querySelector(".fic-drop-prev");
        const clear = zone.querySelector(".fic-drop-clear");

        idle.hidden = files.length > 0;
        prev.hidden = clear.hidden = files.length === 0;
        zone.classList.toggle("has-file", files.length > 0);

        const shown = files.slice(0, 6);
        prev.className = "fic-drop-prev" + (files.length > 1 ? " multi" : "");
        prev.innerHTML = shown.map((file) => {
            const url = URL.createObjectURL(file);
            zone._urls.push(url);
            return thumb(file, url, files.length === 1);
        }).join("") + (files.length > 6 ? `<div class="fic-more">+${files.length - 6} more</div>` : "");
        FIC.renderPdfThumbs(prev);
    }

    FIC.bindDrops = (root) => {
        (root || document).querySelectorAll("[data-fic-drop]").forEach((zone) => {
            if (zone.dataset.bound) return;
            zone.dataset.bound = "1";
            const input = zone.querySelector("input[type=file]");

            zone.addEventListener("click", (event) => {
                if (event.target.closest(".fic-drop-clear")) {
                    input.value = "";
                    showPreview(zone, input);
                    input.dispatchEvent(new Event("change", { bubbles: true }));
                    return;
                }
                if (event.target.tagName === "VIDEO") return;
                if (event.target !== input) input.click();
            });
            input.addEventListener("click", (event) => event.stopPropagation());
            input.addEventListener("change", () => showPreview(zone, input));

            zone.addEventListener("dragover", (event) => { event.preventDefault(); zone.classList.add("dragging"); });
            zone.addEventListener("dragleave", () => zone.classList.remove("dragging"));
            zone.addEventListener("drop", (event) => {
                event.preventDefault();
                zone.classList.remove("dragging");
                if (!event.dataTransfer.files.length) return;
                input.files = event.dataTransfer.files;
                input.dispatchEvent(new Event("change", { bubbles: true }));
            });
        });
    };

    FIC.file = (id) => {
        const input = document.getElementById(id);
        return input && input.files.length ? input.files[0] : null;
    };

    /* ======================================================================
       3. UPLOAD WITH PROGRESS BAR
       ====================================================================== */

    FIC.progress = (id) => `
        <div class="fic-progress" id="${id}" hidden>
            <div class="fic-progress-top"><span class="fic-progress-label">Loading…</span><b class="fic-progress-pct">0%</b></div>
            <div class="fic-bar"><i style="width:0%"></i></div>
        </div>`;

    /** percent = number (0-100) or null for "busy, unknown length"; hide when percent === false */
    FIC.setProgress = (id, percent, label) => {
        const box = document.getElementById(id);
        if (!box) return;
        if (percent === false) { box.hidden = true; return; }
        box.hidden = false;
        const bar = box.querySelector(".fic-bar");
        bar.classList.toggle("busy", percent === null);
        bar.firstElementChild.style.width = (percent === null ? 100 : Math.max(0, Math.min(100, percent))) + "%";
        box.querySelector(".fic-progress-pct").textContent = percent === null ? "…" : Math.round(percent) + "%";
        if (label) box.querySelector(".fic-progress-label").textContent = label;
    };

    /** POST FormData with upload progress. Resolves { ok, status, data } and never rejects. */
    FIC.post = (url, formData, onProgress) => new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", url);
        xhr.withCredentials = true;
        if (onProgress) {
            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) onProgress(event.loaded, event.total);
            };
        }
        xhr.onload = () => {
            let data = {};
            try { data = JSON.parse(xhr.responseText); } catch (e) { /* not json */ }
            if (xhr.status === 401) { window.location.reload(); }
            resolve({ ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status, data });
        };
        xhr.onerror = () => resolve({ ok: false, status: 0, data: { error: "Network error - please try again." } });
        xhr.send(formData);
    });

    FIC.postJSON = async (url) => {
        try {
            const response = await fetch(url, { method: "POST", credentials: "same-origin" });
            let data = {};
            try { data = await response.json(); } catch (e) { /* ignore */ }
            return { ok: response.ok, status: response.status, data };
        } catch (error) {
            return { ok: false, status: 0, data: { error: "Network error - please try again." } };
        }
    };

    /* ======================================================================
       4. HASH TOOL  (one algorithm -> steps, "All" -> no steps)
       ====================================================================== */

    const SHA_GROUPS = [
        ["SHA-1 / SHA-2", ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"]],
        ["SHA-3", ["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]]
    ];

    FIC.algorithmMenu = (name, selected) => `
        <div class="fic-algo-menu">
            ${SHA_GROUPS.map(([title, list]) => `
                <div class="fic-algo-group">
                    <small>${title}</small>
                    <div class="fic-radios">
                        ${list.map((algorithm) => `
                            <label class="fic-radio">
                                <input type="radio" name="${name}" value="${algorithm}" ${selected === algorithm ? "checked" : ""}>
                                <span>${algorithm}</span>
                            </label>`).join("")}
                    </div>
                </div>`).join("")}
            <div class="fic-algo-group">
                <small>Everything</small>
                <div class="fic-radios">
                    <label class="fic-radio fic-radio-all">
                        <input type="radio" name="${name}" value="ALL" ${selected === "ALL" ? "checked" : ""}>
                        <span>Select all</span>
                    </label>
                </div>
            </div>
        </div>`;

    FIC.hashToolHTML = () => `
        <div class="fic">
            <div class="fic-card">
                <textarea id="ficText" class="fic-textarea" placeholder="Type or paste text…"></textarea>
                <div class="fic-or"><span>or</span></div>
                ${FIC.drop("ficHashFile", { hint: "PDF, image, video or any file – processed in your browser" })}

                <h4 class="fic-h">Hash algorithm</h4>
                <p class="fic-note">Choose one algorithm to see its step-by-step working, or <b>Select all</b> to get every hash at once (no steps).</p>
                ${FIC.algorithmMenu("ficAlgo", "SHA-256")}

                <div class="fic-row"><button type="button" class="fic-btn" id="ficHashBtn">Generate hash</button></div>
            </div>
            <div id="ficHashOut"></div>
        </div>`;

    FIC.stepsHTML = (algorithm, explained, realDigest) => {
        const steps = explained.steps.map((step, index) => {
            const isLast = index === explained.steps.length - 1;
            const rows = step.values.map(([label, value]) => {
                const shown = isLast && realDigest ? realDigest : value;
                return `<div class="fic-kv"><span>${esc(label)}</span><code>${esc(shown)}</code></div>`;
            }).join("");
            return `
                <li class="fic-step">
                    <div class="fic-step-n">${index + 1}</div>
                    <div class="fic-step-b">
                        <h5>Step ${index + 1} · ${esc(step.title)}</h5>
                        <p>${esc(step.text)}</p>
                        <div class="fic-kvs">${rows}</div>
                    </div>
                </li>`;
        }).join("");

        let footer;
        if (explained.digest && realDigest && explained.digest === realDigest) {
            footer = `<div class="fic-ok-note">✓ The whole working above was re-computed step by step and gives exactly the same digest as the built-in hash function.</div>`;
        } else if (!explained.complete) {
            footer = `<div class="fic-note">This input is large, so only block 1 is traced in detail – every following block goes through exactly the same steps. The final digest comes from the built-in hash function.</div>`;
        } else {
            footer = "";
        }
        return `<ol class="fic-steps">${steps}</ol>${footer}`;
    };

    /** Wires the Hash Tool. options.onDone(text) is called after each run. */
    FIC.bindHashTool = (options = {}) => {
        const button = document.getElementById("ficHashBtn");
        if (!button) return;
        button.onclick = async () => {
            const out = document.getElementById("ficHashOut");
            const file = FIC.file("ficHashFile");
            const text = document.getElementById("ficText").value;
            const selected = (document.querySelector('input[name="ficAlgo"]:checked') || {}).value;

            if (!file && !text) {
                out.innerHTML = `<div class="fic-card fic-empty">Type some text or choose a file first.</div>`;
                return;
            }
            if (!selected) {
                out.innerHTML = `<div class="fic-card fic-empty">Choose an algorithm (or Select all).</div>`;
                return;
            }

            button.disabled = true;
            out.innerHTML = `<div class="fic-card fic-empty">Calculating…</div>`;
            await nextFrame();

            try {
                const bytes = file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(text);
                const what = file ? `${FIC.kind(file)} · ${FIC.size(bytes.length)}` : `Text · ${bytes.length} characters (bytes)`;

                if (selected === "ALL") {
                    const hashes = await FIC.hashAll(bytes);
                    const rows = Object.entries(hashes).map(([algorithm, value]) => `
                        <tr><td><span class="fic-algo">${algorithm}</span></td>
                            <td><span class="fic-hash">${value}</span></td><td>${copyBtn(value)}</td></tr>`).join("");
                    out.innerHTML = `
                        <div class="fic-card fic-flush">
                            <div class="fic-card-head">All ${Object.keys(hashes).length} hashes <small>${what}</small></div>
                            <div class="fic-table-wrap"><table class="fic-table">
                                <thead><tr><th>Algorithm</th><th>Hash</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
                        </div>`;
                    if (options.onDone) options.onDone(`Hashed ${file ? "a file" : "text"} with all algorithms`);
                } else {
                    const real = await FIC.hash(bytes, selected);
                    const explained = window.HashSteps.explain(selected, bytes);
                    out.innerHTML = `
                        <div class="fic-card">
                            <div class="fic-card-head">${selected} <small>${what}</small></div>
                            <div class="fic-digest"><span class="fic-hash">${real || explained.digest || ""}</span>${copyBtn(real || explained.digest || "")}</div>
                        </div>
                        <div class="fic-card">
                            <div class="fic-card-head">Step-by-step working <small>${selected}</small></div>
                            ${FIC.stepsHTML(selected, explained, real)}
                        </div>`;
                    if (options.onDone) options.onDone(`Hashed ${file ? "a file" : "text"} with ${selected}`);
                }
                bindCopy(out);
            } catch (error) {
                out.innerHTML = `<div class="fic-card fic-empty">Could not hash this input: ${esc(error.message)}</div>`;
            }
            button.disabled = false;
        };
    };

    /* ======================================================================
       5. VERIFY RESULT  (percent bar + Algo / Stored / Calculated / Result)
       ====================================================================== */

    FIC.verifyResultHTML = (data) => {
        const original = data.status === "safe";
        let modified = data.modified_percent;
        const known = modified !== null && modified !== undefined;
        if (!known) modified = original ? 0 : 100;
        const safe = Math.max(0, 100 - modified);
        const hashPct = data.total ? Math.round(100 * data.matched / data.total) : 0;

        const fmt = (n) => (Math.round(n * 100) / 100).toString();
        const rows = data.rows.map((row) => `
            <tr>
                <td><span class="fic-algo">${esc(row.algorithm)}</span></td>
                <td><span class="fic-hash">${esc(row.stored)}</span></td>
                <td><span class="fic-hash">${esc(row.calculated || "n/a")}</span></td>
                <td>${pill(row.match ? "match" : "mismatch")}</td>
            </tr>`).join("");

        return `
            <div class="fic">
                <div class="fic-verdict ${original ? "ok" : "bad"}">
                    <h3>${original ? "✓ INTACT – file is original, no change found" : "⚠ TAMPERED – file is " + esc(String(data.result).toLowerCase())}</h3>
                    <p>Modification score ${fmt(modified)}% · ${data.matched}/${data.total} hashes matched</p>
                </div>

                <div class="fic-card">
                    <div class="fic-card-head">How much changed? ${known ? "" : "<small>(original copy not on server – based on hash match)</small>"}</div>
                    <div class="fic-split-labels"><span class="g">Safe ${fmt(safe)}%</span><span class="r">Modified ${fmt(modified)}%</span></div>
                    <div class="fic-bar fic-bar-split">
                        <i class="safe" style="width:${safe}%"></i><i class="bad" style="width:${modified}%"></i>
                    </div>
                    <div class="fic-split-labels" style="margin-top:14px"><span>Hashes matched</span><span>${data.matched} / ${data.total}</span></div>
                    <div class="fic-bar"><i style="width:${hashPct}%"></i></div>
                </div>

                <div class="fic-card fic-flush">
                    <div class="fic-card-head">Algorithm results</div>
                    <div class="fic-table-wrap"><table class="fic-table">
                        <thead><tr><th>Algorithm</th><th>Stored</th><th>Calculated</th><th>Result</th></tr></thead>
                        <tbody>${rows}</tbody></table></div>
                </div>
            </div>`;
    };

    /* ======================================================================
       6. COMPARE  (image / PDF / hash match)
       ====================================================================== */

    let compareTab = "img";

    FIC.compareHTML = () => `
        <div class="fic">
            <div class="fic-tabs">
                <button type="button" data-fic-tab="img">🖼 Image compare</button>
                <button type="button" data-fic-tab="pdf">📄 PDF compare</button>
                <button type="button" data-fic-tab="hash">⚖ Hash match</button>
            </div>

            <section data-fic-panel="img">
                <div class="fic-two">
                    <div class="fic-card"><h4 class="fic-h">Image 1 (P1)</h4>${FIC.drop("ficImgA", { accept: "image/*", hint: "PNG, JPG, WEBP, BMP…" })}</div>
                    <div class="fic-card"><h4 class="fic-h">Image 2 (P2)</h4>${FIC.drop("ficImgB", { accept: "image/*", hint: "PNG, JPG, WEBP, BMP…" })}</div>
                </div>
                <div class="fic-row"><button type="button" class="fic-btn" id="ficImgBtn">Compare images</button></div>
                ${FIC.progress("ficImgProg")}
                <div id="ficImgOut"></div>
            </section>

            <section data-fic-panel="pdf" hidden>
                <div class="fic-two">
                    <div class="fic-card"><h4 class="fic-h">PDF 1</h4>${FIC.drop("ficPdfA", { accept: "application/pdf,.pdf", hint: "PDF document" })}</div>
                    <div class="fic-card"><h4 class="fic-h">PDF 2</h4>${FIC.drop("ficPdfB", { accept: "application/pdf,.pdf", hint: "PDF document" })}</div>
                </div>
                <div class="fic-row"><button type="button" class="fic-btn" id="ficPdfBtn">Compare PDFs</button></div>
                ${FIC.progress("ficPdfProg")}
                <div id="ficPdfOut"></div>
            </section>

            <section data-fic-panel="hash" hidden>
                <div class="fic-two">
                    <div class="fic-card"><h4 class="fic-h">File A</h4>${FIC.drop("ficHashA", { hint: "Any file" })}</div>
                    <div class="fic-card"><h4 class="fic-h">File B</h4>${FIC.drop("ficHashB", { hint: "Any file" })}</div>
                </div>
                <div class="fic-row"><button type="button" class="fic-btn" id="ficHashCmpBtn">Compare hashes</button></div>
                <div id="ficHashCmpOut"></div>
            </section>
        </div>`;

    const bar = (percentBad) => `
        <div class="fic-bar fic-bar-split">
            <i class="safe" style="width:${Math.max(0, 100 - percentBad)}%"></i><i class="bad" style="width:${percentBad}%"></i>
        </div>`;

    const pct = (n) => (Math.round(n * 100) / 100).toString() + "%";

    function imageResultHTML(data, urlA, urlB) {
        const regionRows = data.regions.map((r) => `
            <tr>
                <td><span class="fic-no">${r.no}</span></td>
                <td>x ${r.x}, y ${r.y}</td>
                <td>${r.w} × ${r.h}</td>
                <td><b>${pct(r.percent_of_image)}</b></td>
                <td>${r.percent_in_region}%</td>
            </tr>`).join("");

        return `
            <div class="fic-verdict ${data.identical ? "ok" : "bad"}">
                <h3>${data.identical ? "✓ Images are identical" : "⚠ " + pct(data.percent_different) + " of the image is different"}</h3>
                <p>${data.identical ? "No pixel differs." : `${data.changed_pixels.toLocaleString()} of ${data.total_pixels.toLocaleString()} pixels changed · ${data.regions.length} region(s) highlighted`}
                ${data.resized_b ? `<br><small>Image 2 (${data.size_b.join("×")}) has another size than Image 1 (${data.size_a.join("×")}) – it was stretched to fit before comparing.</small>` : ""}</p>
            </div>

            <div class="fic-card">
                <div class="fic-split-labels"><span class="g">Same ${pct(100 - data.percent_different)}</span><span class="r">Different ${pct(data.percent_different)}</span></div>
                ${bar(data.percent_different)}
            </div>

            <div class="fic-imgs">
                <figure><img src="${urlA}" alt="P1"><figcaption>P1 · Image 1</figcaption></figure>
                <figure><img src="${urlB}" alt="P2"><figcaption>P2 · Image 2</figcaption></figure>
                <figure class="hl"><img src="${data.highlight}" alt="Highlighted differences"><figcaption>Highlighted regions (yellow boxes, changed pixels in red)</figcaption></figure>
            </div>

            ${data.regions.length ? `
            <div class="fic-card fic-flush">
                <div class="fic-card-head">Highlighted regions <small>coordinates in ${data.analysed_size.join("×")} px</small></div>
                <div class="fic-table-wrap"><table class="fic-table">
                    <thead><tr><th>#</th><th>Position</th><th>Size</th><th>Region % of image</th><th>Changed inside box</th></tr></thead>
                    <tbody>${regionRows}</tbody></table></div>
            </div>` : ""}`;
    }

    function pdfResultHTML(data, urlA, urlB) {
        const t = data.totals;
        const verdict = data.identical_bytes
            ? `<div class="fic-verdict ok"><h3>✓ PDFs are identical</h3><p>Both files are byte-for-byte the same.</p></div>`
            : !data.text_found
                ? `<div class="fic-verdict bad"><h3>⚠ PDFs are different</h3><p>No readable text was found (scanned/image PDF?), so the comparison could only be done on the file bytes.</p></div>`
                : data.percent_different === 0
                    ? `<div class="fic-verdict ok"><h3>✓ Text is identical</h3><p>The text content is the same, but the files differ in bytes (metadata, fonts, layout…).</p></div>`
                    : `<div class="fic-verdict bad"><h3>⚠ ${pct(data.percent_different)} of the text is different</h3><p>Pages: ${data.pages_a} vs ${data.pages_b}</p></div>`;

        const tile = (label, changed, total) =>
            `<div class="fic-stat"><b>${changed.toLocaleString()}<em> / ${total.toLocaleString()}</em></b><span>${label} different</span></div>`;

        const rows = data.pages.map((p) => `
            <tr>
                <td><b>Page ${p.page}</b></td>
                <td>${pill(p.status === "same" ? "same" : p.status === "different" ? "different" : p.status)}</td>
                <td><b>${pct(p.percent)}</b></td>
                <td>${p.lines_changed} / ${p.lines_total}</td>
                <td>${p.words_changed} / ${p.words_total}</td>
                <td>${p.chars_changed} / ${p.chars_total}</td>
            </tr>
            ${p.samples.length ? `<tr class="fic-sub"><td colspan="6">
                <details><summary>Side by side: PDF 1 | PDF 2 (${p.samples.length}${p.lines_changed > p.samples.length ? "+" : ""})</summary>
                    ${p.samples.map((s) => `
                        <div class="fic-diffline">
                            <span class="fic-tag ${s.type}">${s.type}</span>
                            <div class="fic-side">
                                <div class="old">${s.pdf1 ? esc(s.pdf1) : "<em>—</em>"}</div>
                                <div class="new">${s.pdf2 ? esc(s.pdf2) : "<em>—</em>"}</div>
                            </div>
                        </div>`).join("")}
                </details></td></tr>` : ""}`).join("");

        return `
            ${verdict}
            <div class="fic-imgs fic-two-up">
                <figure><div class="fic-thumb fic-thumb-doc big" data-pdf-thumb="${urlA}"><span class="fic-doc-ico pdf">PDF</span></div><figcaption>PDF 1 · page 1 · ${data.pages_a} page(s)</figcaption></figure>
                <figure><div class="fic-thumb fic-thumb-doc big" data-pdf-thumb="${urlB}"><span class="fic-doc-ico pdf">PDF</span></div><figcaption>PDF 2 · page 1 · ${data.pages_b} page(s)</figcaption></figure>
            </div>
            ${data.text_found ? `
            <div class="fic-card">
                <div class="fic-split-labels"><span class="g">Same ${pct(100 - data.percent_different)}</span><span class="r">Different ${pct(data.percent_different)}</span></div>
                ${bar(data.percent_different)}
                <div class="fic-stats">
                    <div class="fic-stat"><b>${data.pages_a}<em> vs ${data.pages_b}</em></b><span>pages (PDF 1 vs PDF 2)</span></div>
                    ${tile("lines", t.lines, t.lines_total)}
                    ${tile("words", t.words, t.words_total)}
                    ${tile("characters", t.chars, t.chars_total)}
                </div>
            </div>
            <div class="fic-card fic-flush">
                <div class="fic-card-head">Page-wise difference</div>
                <div class="fic-table-wrap"><table class="fic-table">
                    <thead><tr><th>Page</th><th>Status</th><th>% different</th><th>Lines</th><th>Words</th><th>Characters</th></tr></thead>
                    <tbody>${rows}</tbody></table></div>
            </div>` : ""}`;
    }

    async function runServerCompare(kind, ids, outId, progId, buttonId) {
        const a = FIC.file(ids[0]);
        const b = FIC.file(ids[1]);
        const out = document.getElementById(outId);
        const button = document.getElementById(buttonId);
        if (!a || !b) {
            out.innerHTML = `<div class="fic-card fic-empty">Choose both files first.</div>`;
            return;
        }
        const form = new FormData();
        form.append("file_a", a);
        form.append("file_b", b);

        button.disabled = true;
        out.innerHTML = "";
        FIC.setProgress(progId, 0, "Uploading…");
        const total = a.size + b.size;
        const result = await FIC.post(`/api/compare/${kind}`, form, (loaded) => {
            const percent = total ? (100 * loaded) / (total + 1) : 0;
            FIC.setProgress(progId, Math.min(percent, 99), "Uploading…");
            if (loaded >= total) FIC.setProgress(progId, null, "Comparing…");
        });
        FIC.setProgress(progId, false);
        button.disabled = false;

        if (!result.ok) {
            out.innerHTML = `<div class="fic-card fic-empty">${esc(result.data.error || "Comparison failed.")}</div>`;
            return;
        }
        if (kind === "image") {
            const urlA = URL.createObjectURL(a);
            const urlB = URL.createObjectURL(b);
            out.innerHTML = imageResultHTML(result.data, urlA, urlB);
        } else {
            out.innerHTML = pdfResultHTML(result.data, URL.createObjectURL(a), URL.createObjectURL(b));
            FIC.renderPdfThumbs(out);
        }
        if (FIC.onCompared) FIC.onCompared(kind, result.data);
    }

    FIC.bindCompare = (options = {}) => {
        FIC.onCompared = options.onDone ? (kind, data) =>
            options.onDone(`Compared two ${kind === "image" ? "images" : "PDFs"} – ${data.percent_different}% different`) : null;

        const tabs = document.querySelectorAll("[data-fic-tab]");
        const panels = document.querySelectorAll("[data-fic-panel]");
        const show = (name) => {
            compareTab = name;
            tabs.forEach((t) => t.classList.toggle("on", t.dataset.ficTab === name));
            panels.forEach((p) => { p.hidden = p.dataset.ficPanel !== name; });
        };
        tabs.forEach((t) => { t.onclick = () => show(t.dataset.ficTab); });
        show(compareTab);

        const imgBtn = document.getElementById("ficImgBtn");
        if (imgBtn) imgBtn.onclick = () => runServerCompare("image", ["ficImgA", "ficImgB"], "ficImgOut", "ficImgProg", "ficImgBtn");
        const pdfBtn = document.getElementById("ficPdfBtn");
        if (pdfBtn) pdfBtn.onclick = () => runServerCompare("pdf", ["ficPdfA", "ficPdfB"], "ficPdfOut", "ficPdfProg", "ficPdfBtn");

        const hashBtn = document.getElementById("ficHashCmpBtn");
        if (hashBtn) {
            hashBtn.onclick = async () => {
                const a = FIC.file("ficHashA");
                const b = FIC.file("ficHashB");
                const out = document.getElementById("ficHashCmpOut");
                if (!a || !b) { out.innerHTML = `<div class="fic-card fic-empty">Choose both files first.</div>`; return; }
                hashBtn.disabled = true;
                out.innerHTML = `<div class="fic-card fic-empty">Calculating…</div>`;
                await nextFrame();
                const ha = await FIC.hashAll(new Uint8Array(await a.arrayBuffer()));
                const hb = await FIC.hashAll(new Uint8Array(await b.arrayBuffer()));
                const algorithms = Object.keys(ha);
                let same = 0;
                const rows = algorithms.map((algorithm) => {
                    const match = ha[algorithm] === hb[algorithm];
                    same += match ? 1 : 0;
                    return `<tr><td><span class="fic-algo">${algorithm}</span></td>
                        <td><span class="fic-hash">${ha[algorithm]}</span></td>
                        <td><span class="fic-hash">${hb[algorithm] || ""}</span></td>
                        <td>${pill(match ? "same" : "different")}</td></tr>`;
                }).join("");
                const identical = same === algorithms.length;
                out.innerHTML = `
                    <div class="fic-verdict ${identical ? "ok" : "bad"}">
                        <h3>${identical ? "✓ Files are identical" : "⚠ Files are different"}</h3>
                        <p>${same} of ${algorithms.length} hashes are equal</p>
                    </div>
                    <div class="fic-card fic-flush"><div class="fic-table-wrap"><table class="fic-table">
                        <thead><tr><th>Algorithm</th><th>File A</th><th>File B</th><th>Result</th></tr></thead>
                        <tbody>${rows}</tbody></table></div></div>`;
                hashBtn.disabled = false;
                if (options.onDone) options.onDone("Compared two files by hash");
            };
        }
    };

    /* ======================================================================
       7. MONITOR  - Tamper & Restore only
       ====================================================================== */

    /** files: [{ id, name, size, status, lastChecked(Date|null), owner? }] */
    FIC.monitorHTML = (files, options = {}) => {
        const rows = files.map((file) => `
            <tr>
                <td>${file.id}</td>
                ${options.owner ? `<td>${esc(file.owner || "—")}</td>` : ""}
                <td><b>${esc(file.name)}</b><div class="fic-mini">${FIC.size(file.size)} · ${FIC.kind(file.name)}</div></td>
                <td>${pill(file.status)}</td>
                <td>${file.lastChecked ? file.lastChecked.toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—"}</td>
                <td>
                    <div class="fic-row fic-tight">
                        <button type="button" class="fic-btn fic-btn-red fic-btn-sm" data-fic-tamper="${file.id}">Tamper</button>
                        <button type="button" class="fic-btn fic-btn-light fic-btn-sm" data-fic-restore="${file.id}">Restore</button>
                    </div>
                </td>
            </tr>`).join("");
        const headers = ["ID"].concat(options.owner ? ["User"] : [], ["File", "Status", "Last checked", "Action"]);

        return `
            <div class="fic">
                <div id="ficMonitorMsg"></div>
                <div class="fic-card fic-flush">
                    <div class="fic-table-wrap"><table class="fic-table">
                        <thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
                        <tbody>${rows || `<tr><td class="fic-empty-cell" colspan="${headers.length}">${esc(options.empty || "No files to monitor yet.")}</td></tr>`}</tbody>
                    </table></div>
                </div>
            </div>`;
    };

    /** urlFor(action, id) -> endpoint. onDone() reloads data and redraws the page. */
    FIC.bindMonitor = (urlFor, onDone) => {
        const run = async (button, action) => {
            const id = button.dataset[action === "tamper" ? "ficTamper" : "ficRestore"];
            const msg = document.getElementById("ficMonitorMsg");
            document.querySelectorAll("[data-fic-tamper],[data-fic-restore]").forEach((b) => { b.disabled = true; });
            msg.innerHTML = `<div class="fic-verdict"><p>Working…</p></div>`;
            const result = await FIC.postJSON(urlFor(action, id));
            const keep = result.ok
                ? `<div class="fic-verdict ${result.data.status === "safe" ? "ok" : "bad"}">
                        <h3>${action === "tamper" ? "File tampered" : "File restored"} – now <b>${esc(result.data.status)}</b></h3>
                        <p>${esc(result.data.file)} · ${result.data.matched}/${result.data.total} hashes still match${result.data.remarks && /bytes changed/.test(result.data.remarks) ? " · " + esc(result.data.remarks.split("·").pop().trim()) : ""}</p>
                   </div>`
                : `<div class="fic-verdict bad"><h3>${action === "tamper" ? "Tamper" : "Restore"} failed</h3><p>${esc(result.data.error || "Something went wrong.")}</p></div>`;
            await onDone();
            const box = document.getElementById("ficMonitorMsg");
            if (box) box.innerHTML = keep;
        };
        document.querySelectorAll("[data-fic-tamper]").forEach((b) => { b.onclick = () => run(b, "tamper"); });
        document.querySelectorAll("[data-fic-restore]").forEach((b) => { b.onclick = () => run(b, "restore"); });
    };

    /* ======================================================================
       8. CHARTS
       ====================================================================== */

    FIC.donut = (slices, size = 130) => {
        const radius = 40, circumference = 2 * Math.PI * radius;
        const total = slices.reduce((sum, s) => sum + s.value, 0);
        let offset = 0;
        const rings = total === 0
            ? `<circle cx="60" cy="60" r="${radius}" fill="none" stroke="rgba(128,128,128,.25)" stroke-width="16"/>`
            : slices.filter((s) => s.value > 0).map((s) => {
                const length = circumference * s.value / total;
                const ring = `<circle cx="60" cy="60" r="${radius}" fill="none" stroke="${s.color}" stroke-width="16"
                    stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" transform="rotate(-90 60 60)"/>`;
                offset += length;
                return ring;
            }).join("");
        return `<svg width="${size}" height="${size}" viewBox="0 0 120 120">${rings}
            <text x="60" y="66" text-anchor="middle" fill="currentColor" font-size="22" font-weight="800">${total}</text></svg>`;
    };

    /** Horizontal bars. items: [{ label, value, color?, text? }] */
    FIC.hbars = (items, empty = "No data yet.") => {
        if (!items.length) return `<div class="fic-empty-cell">${empty}</div>`;
        const max = Math.max(1, ...items.map((i) => i.value));
        return `<div class="fic-hbars">${items.map((item) => `
            <div class="fic-hbar">
                <span class="fic-hbar-l" title="${esc(item.label)}">${esc(item.label)}</span>
                <span class="fic-hbar-t"><i style="width:${Math.max(2, 100 * item.value / max)}%;${item.color ? "background:" + item.color : ""}"></i></span>
                <b>${esc(item.text != null ? item.text : item.value)}</b>
            </div>`).join("")}</div>`;
    };

    /** Stacked columns. days: [{ label, safe, bad }] */
    FIC.columns = (days, empty = "No data yet.") => {
        if (!days.length) return `<div class="fic-empty-cell">${empty}</div>`;
        const width = 320, height = 170, pad = 24;
        const max = Math.max(1, ...days.map((d) => d.safe + d.bad));
        const slot = (width - pad) / days.length;
        const bw = Math.min(34, slot * 0.6);
        const unit = (height - 46) / max;
        const cols = days.map((d, i) => {
            const x = pad + i * slot + (slot - bw) / 2;
            const hs = d.safe * unit, hb = d.bad * unit;
            const base = height - 24;
            return `
                <rect x="${x}" y="${base - hs}" width="${bw}" height="${hs}" rx="3" fill="#22c55e"/>
                <rect x="${x}" y="${base - hs - hb}" width="${bw}" height="${hb}" rx="3" fill="#ef4444"/>
                <text x="${x + bw / 2}" y="${base - hs - hb - 5}" text-anchor="middle" font-size="10" fill="currentColor">${d.safe + d.bad}</text>
                <text x="${x + bw / 2}" y="${height - 8}" text-anchor="middle" font-size="9" fill="currentColor" opacity=".65">${esc(d.label)}</text>`;
        }).join("");
        return `<svg viewBox="0 0 ${width} ${height}" class="fic-columns" role="img">
            <line x1="${pad - 4}" y1="${height - 24}" x2="${width}" y2="${height - 24}" stroke="currentColor" opacity=".2"/>${cols}</svg>
            <div class="fic-legend"><span><i style="background:#22c55e"></i>Safe</span><span><i style="background:#ef4444"></i>Modified / tampered</span></div>`;
    };

    const CATEGORY = { image: "Images", video: "Videos", pdf: "PDF", audio: "Audio", document: "Documents", other: "Other" };
    const PALETTE = ["#6366f1", "#22d3ee", "#10b981", "#f59e0b", "#ec4899", "#8b5cf6", "#fb7185", "#60a5fa"];
    const TYPE_NAMES = { pie: "Pie", donut: "Donut", bar: "Bar", hist: "Histogram", line: "Line" };
    const chartRegistry = {};
    const fmtDefault = (v) => (Math.round(v * 100) / 100).toString();

    function slicesOf(ds) {
        if (ds.series.length === 1) {
            return ds.labels.map((label, i) => ({ label, value: ds.series[0].values[i], color: ds.colors[i] }));
        }
        return ds.series.map((s) => ({ label: s.name, value: s.values.reduce((a, b) => a + b, 0), color: s.color }));
    }

    let uid = 0;
    const gradDef = (id, c, top = 1, bottom = 0.5) =>
        `<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${c}" stop-opacity="${top}"/><stop offset="1" stop-color="${c}" stop-opacity="${bottom}"/></linearGradient>`;
    const tipAttr = (text) => `data-tip="${esc(text)}"`;

    function legendHTML(slices, fmt, total) {
        return `<div class="fic-legend-list">${slices.map((s) => `
            <div class="fic-lg-row"><i style="background:${s.color}"></i><span class="fic-lg-l" title="${esc(s.label)}">${esc(s.label)}</span>
            <b>${esc(fmt(s.value))}</b>${total ? `<em>${Math.round(100 * s.value / total)}%</em>` : ""}</div>`).join("")}</div>`;
    }

    const emptyBox = (ds) => `<div class="fic-empty-chart"><span>📊</span>${esc(ds.empty || "No data yet.")}</div>`;

    function pieSVG(ds, donut) {
        const slices = slicesOf(ds).filter((s) => s.value > 0);
        const total = slices.reduce((a, s) => a + s.value, 0);
        if (!total) return emptyBox(ds);
        const id = "g" + (++uid) + "_";
        const defs = slices.map((s, i) => gradDef(id + i, s.color, 1, 0.65)).join("");
        let body = "";
        if (donut) {
            const r = 42, circ = 2 * Math.PI * r, gap = slices.length > 1 ? 2.4 : 0;
            let off = 0;
            body = `<circle cx="60" cy="60" r="${r}" fill="none" stroke="currentColor" opacity=".07" stroke-width="15"/>` +
                slices.map((s, i) => {
                    const len = circ * s.value / total;
                    const ring = `<circle class="fic-seg" cx="60" cy="60" r="${r}" fill="none" stroke="url(#${id}${i})" stroke-width="15"
                        stroke-dasharray="${Math.max(len - gap, 0.5)} ${circ}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)" ${tipAttr(`${s.label}: ${ds.fmt(s.value)} (${Math.round(100 * s.value / total)}%)`)}/>`;
                    off += len; return ring;
                }).join("") +
                `<text x="60" y="61" text-anchor="middle" fill="currentColor" font-size="17" font-weight="800">${esc(ds.fmt(total))}</text>
                 <text x="60" y="73" text-anchor="middle" fill="currentColor" opacity=".5" font-size="6.5" letter-spacing="1.4">TOTAL</text>`;
        } else if (slices.length === 1) {
            body = `<circle class="fic-seg" cx="60" cy="60" r="52" fill="url(#${id}0)" ${tipAttr(`${slices[0].label}: ${ds.fmt(slices[0].value)} (100%)`)}/>`;
        } else {
            let angle = -Math.PI / 2;
            body = slices.map((s, i) => {
                const sweep = 2 * Math.PI * s.value / total, r = 52;
                const x1 = 60 + r * Math.cos(angle), y1 = 60 + r * Math.sin(angle);
                angle += sweep;
                const x2 = 60 + r * Math.cos(angle), y2 = 60 + r * Math.sin(angle);
                return `<path class="fic-seg" d="M60 60 L${x1.toFixed(2)} ${y1.toFixed(2)} A${r} ${r} 0 ${sweep > Math.PI ? 1 : 0} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} Z" fill="url(#${id}${i})" stroke="var(--f-card)" stroke-width="1.6" ${tipAttr(`${s.label}: ${ds.fmt(s.value)} (${Math.round(100 * s.value / total)}%)`)}/>`;
            }).join("");
        }
        return `<div class="fic-donut-row"><svg class="fic-pop" width="160" height="160" viewBox="0 0 120 120"><defs>${defs}</defs>${body}</svg>${legendHTML(slices, ds.fmt, total)}</div>`;
    }

    function axis(max, fmt, W, H, pad, top) {
        let out = "";
        for (let i = 0; i <= 4; i++) {
            const y = top + (H - top - pad.b) * (1 - i / 4);
            out += `<line x1="${pad.l}" y1="${y}" x2="${W - 6}" y2="${y}" stroke="currentColor" opacity="${i === 0 ? ".28" : ".1"}" ${i === 0 ? "" : 'stroke-dasharray="3 4"'}/>
                    <text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" font-size="9" fill="currentColor" opacity=".5">${esc(fmt(max * i / 4))}</text>`;
        }
        return out;
    }

    const shortLabel = (t, n = 9) => (String(t).length > n ? String(t).slice(0, n - 1) + "…" : String(t));

    function roundedTop(x, y, w, h, r) {
        r = Math.max(0, Math.min(r, w / 2, h));
        return `M${x} ${y + h} V${y + r} Q${x} ${y} ${x + r} ${y} H${x + w - r} Q${x + w} ${y} ${x + w} ${y + r} V${y + h} Z`;
    }

    function seriesLegend(ds) {
        return `<div class="fic-legend">${ds.series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.name)}</span>`).join("")}</div>`;
    }

    function barSVG(ds) {
        if (!ds.labels.length) return emptyBox(ds);
        const id = "g" + (++uid) + "_";
        const W = 340, H = 205, pad = { l: 40, b: 34 }, top = 16;
        const stacked = ds.series.length > 1;
        const totals = ds.labels.map((_, i) => ds.series.reduce((a, s) => a + s.values[i], 0));
        const max = Math.max(1e-9, ...totals);
        const slot = (W - pad.l - 8) / ds.labels.length, bw = Math.min(36, slot * 0.58);
        const plotH = H - top - pad.b;
        const defs = stacked
            ? ds.series.map((s, k) => gradDef(id + k, s.color, 1, 0.7)).join("")
            : ds.labels.map((_, i) => gradDef(id + i, ds.colors[i], 1, 0.55)).join("");
        const bars = ds.labels.map((label, i) => {
            const x = pad.l + i * slot + (slot - bw) / 2;
            let y = H - pad.b, out = "";
            const lastIdx = ds.series.reduce((acc, s, k) => (s.values[i] > 0 ? k : acc), -1);
            ds.series.forEach((s, k) => {
                const h = plotH * s.values[i] / max;
                if (h <= 0) return;
                y -= h;
                const fill = `url(#${id}${stacked ? k : i})`;
                const t = tipAttr(`${label} – ${stacked ? s.name + ": " : ""}${ds.fmt(s.values[i])}`);
                out += k === lastIdx
                    ? `<path d="${roundedTop(x, y, bw, h, 5)}" fill="${fill}" ${t}/>`
                    : `<rect x="${x}" y="${y}" width="${bw}" height="${h}" fill="${fill}" ${t}/>`;
            });
            if (!out) out = `<rect x="${x}" y="${H - pad.b - 2}" width="${bw}" height="2" rx="1" fill="currentColor" opacity=".25"/>`;
            return `<g class="fic-grow" style="animation-delay:${i * 60}ms">${out}</g>
                <text x="${x + bw / 2}" y="${y - 5}" text-anchor="middle" font-size="10" font-weight="700" fill="currentColor">${esc(ds.fmt(totals[i]))}</text>
                <text x="${x + bw / 2}" y="${H - 17}" text-anchor="middle" font-size="9" fill="currentColor" opacity=".6">${esc(shortLabel(label, 8))}</text>`;
        }).join("");
        return `<svg viewBox="0 0 ${W} ${H}" class="fic-columns"><defs>${defs}</defs>${axis(max, ds.fmt, W, H, pad, top)}${bars}</svg>${stacked ? seriesLegend(ds) : ""}`;
    }

    function smoothPath(pts, lo, hi) {
        if (pts.length < 2) return "";
        const clamp = (v) => Math.max(lo, Math.min(hi, v));
        let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
            const c1 = [p1[0] + (p2[0] - p0[0]) / 6, clamp(p1[1] + (p2[1] - p0[1]) / 6)];
            const c2 = [p2[0] - (p3[0] - p1[0]) / 6, clamp(p2[1] - (p3[1] - p1[1]) / 6)];
            d += ` C${c1[0].toFixed(1)},${c1[1].toFixed(1)} ${c2[0].toFixed(1)},${c2[1].toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
        }
        return d;
    }

    function lineSVG(ds) {
        if (!ds.labels.length) return emptyBox(ds);
        const id = "g" + (++uid) + "_";
        const W = 340, H = 205, pad = { l: 40, b: 34 }, top = 16;
        const max = Math.max(1e-9, ...ds.series.flatMap((s) => s.values));
        const n = ds.labels.length, plotW = W - pad.l - 18, plotH = H - top - pad.b, base = H - pad.b;
        const X = (i) => pad.l + 8 + (n === 1 ? plotW / 2 : (plotW - 8) * i / (n - 1));
        const Y = (v) => top + plotH * (1 - v / max);
        const defs = ds.series.map((s, k) => gradDef(id + k, s.color || PALETTE[k % PALETTE.length], 0.38, 0)).join("");
        const lines = ds.series.map((s, k) => {
            const color = s.color || PALETTE[k % PALETTE.length];
            const pts = s.values.map((v, i) => [X(i), Y(v)]);
            const path = smoothPath(pts, top, base);
            const area = path ? `<path class="fic-fade" d="${path} L${X(n - 1).toFixed(1)},${base} L${X(0).toFixed(1)},${base} Z" fill="url(#${id}${k})"/>` : "";
            const stroke = path ? `<path class="fic-draw" pathLength="1" d="${path}" fill="none" stroke="${color}" stroke-width="2.6" stroke-linecap="round" style="filter:drop-shadow(0 3px 5px ${color}66)"/>` : "";
            const dots = s.values.map((v, i) => `
                <circle cx="${X(i).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="8" fill="${color}" opacity=".16" class="fic-halo"/>
                <circle cx="${X(i).toFixed(1)}" cy="${Y(v).toFixed(1)}" r="3.8" fill="${color}" stroke="var(--f-card)" stroke-width="1.8" ${tipAttr(`${ds.labels[i]} – ${s.name}: ${ds.fmt(v)}`)}/>`).join("");
            return area + stroke + dots;
        }).join("");
        const xl = ds.labels.map((l, i) => `<text x="${X(i).toFixed(1)}" y="${H - 17}" text-anchor="middle" font-size="9" fill="currentColor" opacity=".6">${esc(shortLabel(l, 8))}</text>`).join("");
        return `<svg viewBox="0 0 ${W} ${H}" class="fic-columns"><defs>${defs}</defs>${axis(max, ds.fmt, W, H, pad, top)}${lines}${xl}</svg>${ds.series.length > 1 ? seriesLegend(ds) : ""}`;
    }

    /** Histogram: groups the values into ranges (bins) and counts how many fall in each range. */
    function histSVG(ds) {
        const values = ds.labels.map((_, i) => ds.series.reduce((a, s) => a + s.values[i], 0));
        if (!values.length) return emptyBox(ds);
        const id = "g" + (++uid) + "_";
        const lo = Math.min(...values), hi = Math.max(...values);
        const binCount = lo === hi ? 1 : Math.min(6, Math.max(2, Math.ceil(Math.sqrt(values.length))));
        const width = (hi - lo) / binCount || 1;
        const bins = Array.from({ length: binCount }, (_, i) => ({ from: lo + i * width, to: lo + (i + 1) * width, items: [] }));
        values.forEach((v, i) => { bins[Math.min(binCount - 1, Math.floor((v - lo) / width))].items.push(ds.labels[i]); });

        const W = 340, H = 205, pad = { l: 32, b: 42 }, top = 18;
        const max = Math.ceil(Math.max(...bins.map((b) => b.items.length)) / 4) * 4;
        const slot = (W - pad.l - 8) / binCount, plotH = H - top - pad.b;
        const tick = (v) => String(Math.round(v * 10) / 10);
        const bars = bins.map((bin, i) => {
            const h = plotH * bin.items.length / max, x = pad.l + i * slot, y = H - pad.b - h;
            const range = lo === hi ? ds.fmt(lo) : `${ds.fmt(bin.from)} – ${ds.fmt(bin.to)}`;
            const body = h > 0 ? `<path d="${roundedTop(x + 1.5, y, slot - 3, h, 4)}" fill="url(#${id}0)" ${tipAttr(`${range}: ${bin.items.length} item(s) – ${bin.items.join(", ")}`)}/>` : "";
            return `<g class="fic-grow" style="animation-delay:${i * 70}ms">${body}</g>
                <text x="${x + slot / 2}" y="${y - 5}" text-anchor="middle" font-size="10" font-weight="700" fill="currentColor">${bin.items.length}</text>
                <text x="${x + slot / 2}" y="${H - 24}" text-anchor="middle" font-size="8" fill="currentColor" opacity=".6">${esc(shortLabel(range, 15))}</text>`;
        }).join("");
        return `<svg viewBox="0 0 ${W} ${H}" class="fic-columns"><defs>${gradDef(id + "0", "#6366f1", 1, 0.55)}</defs>${axis(max, tick, W, H, pad, top)}${bars}
            <text x="${W / 2}" y="${H - 7}" text-anchor="middle" font-size="8.5" fill="currentColor" opacity=".45" letter-spacing=".6">VALUE RANGE → NUMBER OF ITEMS</text></svg>`;
    }

    function renderChart(ds, type) {
        if (type === "pie") return pieSVG(ds, false);
        if (type === "donut") return pieSVG(ds, true);
        if (type === "bar") return barSVG(ds);
        if (type === "line") return lineSVG(ds);
        return histSVG(ds);
    }

    /* floating tooltip for anything with data-tip */
    let tipBox = null;
    document.addEventListener("mousemove", (event) => {
        const target = event.target.closest ? event.target.closest("[data-tip]") : null;
        if (!target) { if (tipBox) tipBox.style.opacity = 0; return; }
        if (!tipBox) { tipBox = document.createElement("div"); tipBox.className = "fic-tip"; document.body.appendChild(tipBox); }
        tipBox.textContent = target.dataset.tip;
        tipBox.style.opacity = 1;
        const w = tipBox.offsetWidth;
        tipBox.style.left = Math.min(window.innerWidth - w - 8, event.clientX + 14) + "px";
        tipBox.style.top = event.clientY + 16 + "px";
    });


    /* ======================================================================
       ACTIVITY HEATMAP  (File x Day / Calendar / Day x Hour)
       ====================================================================== */

    const heatRegistry = {};
    const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const dayKey = (d) => d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
    const mondayIndex = (d) => (d.getDay() + 6) % 7;
    const lerp = (a, b, t) => Math.round(a + (b - a) * t);

    function heatColor(value, max, metric) {
        if (!value) return "rgba(128,140,165,.13)";
        const t = Math.min(1, value / Math.max(1, max));
        const [from, to] = metric === "bad" ? [[251, 191, 36], [239, 68, 68]] : [[56, 189, 248], [99, 102, 241]];
        return `rgba(${lerp(from[0], to[0], t)},${lerp(from[1], to[1], t)},${lerp(from[2], to[2], t)},${(0.5 + 0.5 * t).toFixed(2)})`;
    }

    function heatLegend(metric) {
        const steps = [0, 0.25, 0.5, 0.75, 1].map((t) => `<i style="background:${heatColor(t ? t * 10 : 0, 10, metric)}"></i>`).join("");
        return `<div class="fic-heat-scale"><span>Less</span>${steps}<span>More</span></div>`;
    }

    function heatInner(st) {
        const bad = st.metric === "bad";
        const list = st.checks.filter((c) => c.time && (!bad || c.status !== "safe"));
        const today = new Date(); today.setHours(0, 0, 0, 0);
        const noun = bad ? "change(s)" : "check(s)";
        let body = "", peak = null;

        if (st.mode === "files") {
            const N = st.range;
            const days = Array.from({ length: N }, (_, i) => { const d = new Date(today); d.setDate(d.getDate() - (N - 1 - i)); return d; });
            const first = dayKey(days[0]);
            const per = {};
            list.forEach((c) => {
                const k = dayKey(c.time); if (k < first) return;
                const f = per[c.file] = per[c.file] || { total: 0, days: {} };
                f.days[k] = (f.days[k] || 0) + 1; f.total++;
            });
            const rows = Object.entries(per).sort((a, b) => b[1].total - a[1].total).slice(0, 8);
            if (!rows.length) return heatEmpty(bad);
            const max = Math.max(...rows.flatMap(([, f]) => Object.values(f.days)));
            const head = days.map((d, i) => `<span class="fic-hh">${N <= 14 || i % 5 === 0 || i === N - 1 ? (d.getDate() === 1 ? d.toLocaleDateString([], { month: "short" }) : d.getDate()) : ""}</span>`).join("");
            body = `<div class="fic-hgrid" style="grid-template-columns:minmax(80px,120px) repeat(${N},minmax(8px,1fr))">
                <span></span>${head}
                ${rows.map(([name, f]) => `<span class="fic-hl" title="${esc(name)}">${esc(shortLabel(name, 16))}</span>` + days.map((d, i) => {
                    const v = f.days[dayKey(d)] || 0;
                    return `<b class="fic-hc" style="background:${heatColor(v, max, st.metric)};animation-delay:${i * 12}ms" data-tip="${esc(name)} · ${d.toLocaleDateString([], { day: "numeric", month: "short" })}: ${v} ${noun}"></b>`;
                }).join("")).join("")}</div>`;
            const topFile = rows[0];
            peak = `Most active file: <b>${esc(shortLabel(topFile[0], 22))}</b> (${topFile[1].total})`;
        } else if (st.mode === "calendar") {
            const weeks = 38, start = new Date(today);
            start.setDate(start.getDate() - mondayIndex(today) - (weeks - 1) * 7);
            const counts = {};
            list.forEach((c) => { const k = dayKey(c.time); counts[k] = (counts[k] || 0) + 1; });
            const max = Math.max(1, ...Object.values(counts));
            let cells = "", months = "", lastMonth = -1, best = null;
            for (let w = 0; w < weeks; w++) {
                const d0 = new Date(start); d0.setDate(d0.getDate() + w * 7);
                months += `<span>${d0.getMonth() !== lastMonth ? d0.toLocaleDateString([], { month: "short" }) : ""}</span>`;
                lastMonth = d0.getMonth();
                for (let r = 0; r < 7; r++) {
                    const d = new Date(start); d.setDate(d.getDate() + w * 7 + r);
                    if (d > today) { cells += `<b class="fic-hc fic-hide"></b>`; continue; }
                    const v = counts[dayKey(d)] || 0;
                    if (v && (!best || v > best[1])) best = [d, v];
                    cells += `<b class="fic-hc" style="background:${heatColor(v, max, st.metric)};animation-delay:${(w * 7 + r) * 4}ms" data-tip="${d.toLocaleDateString([], { weekday: "short", day: "numeric", month: "short" })}: ${v} ${noun}"></b>`;
                }
            }
            if (!Object.keys(counts).length) return heatEmpty(bad);
            body = `<div class="fic-cal"><div class="fic-cal-days"><span>Mon</span><span></span><span>Wed</span><span></span><span>Fri</span><span></span><span></span></div>
                <div><div class="fic-cal-months" style="grid-template-columns:repeat(${weeks},20px)">${months}</div>
                <div class="fic-cal-grid" style="grid-template-columns:repeat(${weeks},16px)">${cells}</div></div></div>`;
            peak = best ? `Busiest day: <b>${best[0].toLocaleDateString([], { weekday: "long", day: "numeric", month: "short" })}</b> (${best[1]})` : "";
        } else {
            const m = Array.from({ length: 7 }, () => new Array(24).fill(0));
            list.forEach((c) => { m[mondayIndex(c.time)][c.time.getHours()]++; });
            const max = Math.max(...m.flat());
            if (!max) return heatEmpty(bad);
            let best = [0, 0, 0];
            m.forEach((row, r) => row.forEach((v, h) => { if (v > best[2]) best = [r, h, v]; }));
            const head = Array.from({ length: 24 }, (_, h) => `<span class="fic-hh">${h % 3 === 0 ? h : ""}</span>`).join("");
            body = `<div class="fic-hgrid" style="grid-template-columns:40px repeat(24,minmax(8px,1fr))"><span></span>${head}
                ${m.map((row, r) => `<span class="fic-hl">${DAY_NAMES[r]}</span>` + row.map((v, h) =>
                    `<b class="fic-hc" style="background:${heatColor(v, max, st.metric)};animation-delay:${(r * 24 + h) * 3}ms" data-tip="${DAY_NAMES[r]} ${String(h).padStart(2, "0")}:00 – ${v} ${noun}"></b>`).join("")).join("")}</div>`;
            peak = `Peak time: <b>${DAY_NAMES[best[0]]} ${String(best[1]).padStart(2, "0")}:00</b> (${best[2]})`;
        }
        const total = list.length;
        return `<div class="fic-heat-body">${body}</div>
            <div class="fic-heat-foot">${heatLegend(st.metric)}<div class="fic-heat-ins"><span>${total} ${noun} in total</span>${peak ? `<span>${peak}</span>` : ""}</div></div>`;
    }

    const heatEmpty = (bad) => `<div class="fic-empty-chart"><span>🗓</span>${bad ? "No changes detected – everything is intact." : "No checks yet – verify a file to fill the heatmap."}</div>`;

    function heatControls(st) {
        const seg = (attr, items, cur) => `<div class="fic-chart-tabs">${items.map(([v, l]) => `<button type="button" ${attr}="${v}" class="${String(cur) === String(v) ? "on" : ""}">${l}</button>`).join("")}</div>`;
        return `${seg("data-heat-metric", [["bad", "Changes"], ["all", "All checks"]], st.metric)}
                ${st.mode === "files" ? seg("data-heat-range", [[7, "7 days"], [14, "14 days"], [30, "30 days"]], st.range) : ""}`;
    }

    function heatCard(checks) {
        const id = "heat" + (++uid);
        const st = heatRegistry[id] = { checks, mode: "files", metric: "bad", range: 14 };
        return `<div class="fic-card fic-heat-card" data-fic-heat-card="${id}">${heatShell(st)}</div>`;
    }

    function heatShell(st) {
        const modes = [["files", "File × Day"], ["calendar", "Calendar"], ["hours", "Day × Hour"]];
        return `<div class="fic-card-head fic-chart-head"><span class="fic-chart-title">🔥 Activity heatmap</span>
                <div class="fic-chart-tabs">${modes.map(([v, l]) => `<button type="button" data-heat-mode="${v}" class="${st.mode === v ? "on" : ""}">${l}</button>`).join("")}</div></div>
            <div class="fic-heat-bar">${heatControls(st)}</div>${heatInner(st)}`;
    }

    document.addEventListener("click", (event) => {
        const button = event.target.closest("[data-heat-mode],[data-heat-metric],[data-heat-range]");
        if (!button) return;
        const card = button.closest("[data-fic-heat-card]");
        const st = card && heatRegistry[card.dataset.ficHeatCard];
        if (!st) return;
        if (button.dataset.heatMode) st.mode = button.dataset.heatMode;
        if (button.dataset.heatMetric) st.metric = button.dataset.heatMetric;
        if (button.dataset.heatRange) st.range = parseInt(button.dataset.heatRange, 10);
        card.innerHTML = heatShell(st);
    });

    function chartCard(id, title, ds) {
        ds.fmt = ds.fmt || fmtDefault;
        ds.colors = ds.colors || ds.labels.map((_, i) => PALETTE[i % PALETTE.length]);
        chartRegistry[id] = ds;
        const tabs = ds.types.map((t) => `<button type="button" data-fic-chart="${t}" class="${t === ds.type ? "on" : ""}">${TYPE_NAMES[t]}</button>`).join("");
        return `<div class="fic-card" data-fic-chart-card="${id}">
            <div class="fic-card-head fic-chart-head"><span class="fic-chart-title">${esc(title)}</span><div class="fic-chart-tabs">${tabs}</div></div>
            <div class="fic-chart-body">${renderChart(ds, ds.type)}</div></div>`;
    }

    document.addEventListener("click", (event) => {
        const button = event.target.closest("[data-fic-chart]");
        if (!button) return;
        const card = button.closest("[data-fic-chart-card]");
        const ds = chartRegistry[card.dataset.ficChartCard];
        if (!ds) return;
        card.querySelectorAll("[data-fic-chart]").forEach((b) => b.classList.toggle("on", b === button));
        card.querySelector(".fic-chart-body").innerHTML = renderChart(ds, button.dataset.ficChart);
    });

    /**
     * Report charts - every card can be switched between Pie / Donut / Bar / H-Bar / Line / Area.
     * files:  [{ name, size, status, algorithms: [..] }]
     * checks: [{ time: Date, status, percent: number|null, file }]
     */
    FIC.reportCharts = ({ files, checks, kpis = true, heat = true }) => {
        const count = (status) => files.filter((f) => f.status === status).length;
        const ALL = ["pie", "donut", "bar", "hist", "line"];

        const statusDs = {
            labels: ["Safe", "Modified", "Tampered"], colors: ["#10b981", "#f59e0b", "#ef4444"],
            series: [{ name: "Files", values: [count("safe"), count("modified"), count("tampered")] }],
            types: ALL, type: "donut", empty: "No files yet."
        };

        const byType = {};
        files.forEach((f) => { const k = CATEGORY[FIC.kind(f.name)]; byType[k] = (byType[k] || 0) + 1; });
        const typeEntries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
        const typeDs = { labels: typeEntries.map((e) => e[0]), series: [{ name: "Files", values: typeEntries.map((e) => e[1]) }], types: ALL, type: "pie", empty: "No files yet." };

        const byAlgo = {};
        files.forEach((f) => (f.algorithms || []).forEach((a) => { byAlgo[a] = (byAlgo[a] || 0) + 1; }));
        const algoEntries = Object.entries(byAlgo).sort((a, b) => b[1] - a[1]);
        const algoDs = { labels: algoEntries.map((e) => e[0]), series: [{ name: "Files", values: algoEntries.map((e) => e[1]) }], types: ALL, type: "bar", empty: "No hashes yet." };

        const days = {};
        checks.forEach((c) => {
            if (!c.time) return;
            const key = c.time.getFullYear() + "-" + String(c.time.getMonth() + 1).padStart(2, "0") + "-" + String(c.time.getDate()).padStart(2, "0");
            days[key] = days[key] || { key, time: c.time, safe: 0, bad: 0 };
            if (c.status === "safe") days[key].safe++; else days[key].bad++;
        });
        const dayList = Object.values(days).sort((a, b) => a.key.localeCompare(b.key)).slice(-7);
        const dayDs = {
            labels: dayList.map((d) => d.time.toLocaleDateString([], { day: "numeric", month: "short" })),
            series: [{ name: "Safe", color: "#10b981", values: dayList.map((d) => d.safe) },
                     { name: "Modified / tampered", color: "#ef4444", values: dayList.map((d) => d.bad) }],
            types: ["bar", "line", "pie", "donut"], type: "line", empty: "No checks yet."
        };

        const big = files.slice().sort((a, b) => b.size - a.size).slice(0, 6);
        const sizeDs = { labels: big.map((f) => "File " + (files.indexOf(f) + 1)), series: [{ name: "Size", values: big.map((f) => f.size) }], fmt: FIC.size, types: ALL, type: "hist", empty: "No files yet." };
        sizeDs.labels = big.map((f) => f.name);

        const diff = checks.filter((c) => c.percent !== null && c.percent !== undefined).slice(-8);
        const diffDs = { labels: diff.map((c) => c.file), series: [{ name: "% changed", values: diff.map((c) => c.percent) }], fmt: (v) => fmtDefault(v) + "%", types: ["bar", "line", "hist", "pie"], type: "bar", empty: "Verify a file to see the % changed." };

        const safeCount = count("safe"), badCount = files.length - safeCount;
        const score = files.length ? Math.round(100 * safeCount / files.length) : 100;
        const pcts = checks.filter((c) => c.percent !== null && c.percent !== undefined).map((c) => c.percent);
        const avg = pcts.length ? fmtDefault(pcts.reduce((a, b) => a + b, 0) / pcts.length) + "%" : "—";
        const kpi = (icon, label, value, tone) => `<div class="fic-kpi ${tone}"><span class="fic-kpi-ico">${icon}</span><div><b>${value}</b><small>${label}</small></div></div>`;

        return `<div class="fic">${kpis ? `<div class="fic-kpis">
            ${kpi("📁", "Total files", files.length, "blue")}
            ${kpi("🛡", "Integrity score", score + "%", score === 100 ? "green" : "amber")}
            ${kpi("⚠", "Modified / tampered", badCount, badCount ? "red" : "green")}
            ${kpi("🔍", "Checks run", checks.length, "violet")}
            ${kpi("🧬", "Avg bytes changed", avg, "cyan")}
        </div>` : ""}<div class="fic-chart-grid">
            ${heat ? heatCard(checks) : ""}
            ${chartCard("status", "File status", statusDs)}
            ${chartCard("types", "Files by type", typeDs)}
            ${chartCard("algos", "Hash algorithms used", algoDs)}
            ${chartCard("days", "Checks per day", dayDs)}
            ${chartCard("sizes", "Largest files", sizeDs)}
            ${chartCard("diff", "How much changed (bytes)", diffDs)}
        </div></div>`;
    };


    /**
     * Compare users with each other (admin).
     * users: [{ name, files, storage (bytes), score (0-100), checks, bad }]
     */
    FIC.userCharts = (users) => {
        const label = users.map((u) => u.name);
        const mk = (name, values, extra) => Object.assign({ labels: label, series: [{ name, values }], empty: "No users yet." }, extra);
        const TYPES = ["bar", "pie", "donut", "hist", "line"];
        return `<div class="fic"><div class="fic-chart-grid">
            ${chartCard("u-storage", "Storage used per user", mk("Storage", users.map((u) => u.storage), { fmt: FIC.size, types: TYPES, type: "bar" }))}
            ${chartCard("u-files", "Files per user", mk("Files", users.map((u) => u.files), { types: TYPES, type: "donut" }))}
            ${chartCard("u-score", "Integrity score per user (%)", mk("Score", users.map((u) => u.score), { fmt: (v) => fmtDefault(v) + "%", types: ["bar", "line", "hist", "pie"], type: "bar" }))}
            ${chartCard("u-checks", "Checks vs problems per user", {
                labels: label,
                series: [{ name: "Checks", color: "#6366f1", values: users.map((u) => u.checks) },
                         { name: "Problems", color: "#ef4444", values: users.map((u) => u.bad) }],
                types: ["bar", "line"], type: "bar", empty: "No users yet."
            })}
        </div></div>`;
    };

    /** pulls "12.5% bytes changed" out of a remarks text */
    FIC.percentFromRemarks = (text) => {
        const match = /([\d.]+)% bytes changed/.exec(text || "");
        return match ? parseFloat(match[1]) : null;
    };
})();
