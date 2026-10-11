/* ==========================================================================
   uploader.js  -  upload that SURVIVES a page refresh

   How it works
     1. The chosen file is saved in the browser (IndexedDB).
     2. It is sent to the server in 4 MB parts, 4 parts at a time (fast).
     3. If the page is refreshed / closed / the internet drops, nothing is lost:
        when the dashboard opens again the saved file is found and only the
        missing parts are sent.  The progress bar comes back where it was.

   Uses:  Uploader.add(files, algorithms)    start uploads
          Uploader.init(userKey)             call once after login data is known
          Uploader.html() / Uploader.paint(el)   progress panel
   ========================================================================== */
(function () {
    "use strict";

    const PARALLEL = 4;
    const RETRIES = 4;
    const DB_NAME = "fic-uploads";

    const Uploader = (window.Uploader = {
        jobs: [],
        userKey: "guest",
        renderDone: null,          // (job) => html  for a finished upload
        onDone: null,              // (job) => void  called once per finished upload
        onChange: null             // () => void     called on every progress change
    });

    const running = new Set();
    const memoryBlobs = new Map();           // used when IndexedDB is not available

    /* ---------- tiny IndexedDB helper ---------- */

    let dbPromise = null;
    function db() {
        if (!dbPromise) {
            dbPromise = new Promise((resolve) => {
                try {
                    const request = indexedDB.open(DB_NAME, 1);
                    request.onupgradeneeded = () => {
                        request.result.createObjectStore("jobs", { keyPath: "id" });
                        request.result.createObjectStore("blobs");
                    };
                    request.onsuccess = () => resolve(request.result);
                    request.onerror = () => resolve(null);
                } catch (error) { resolve(null); }
            });
        }
        return dbPromise;
    }

    async function idb(store, mode, action) {
        const database = await db();
        if (!database) return null;
        return new Promise((resolve) => {
            try {
                const request = action(database.transaction(store, mode).objectStore(store));
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => resolve(null);
            } catch (error) { resolve(null); }
        });
    }

    const saveJob = (job) => {
        const { blob, ...plain } = job;                 // the file itself lives in its own store
        return idb("jobs", "readwrite", (s) => s.put(JSON.parse(JSON.stringify(plain))));
    };
    const loadJobs = () => idb("jobs", "readonly", (s) => s.getAll());
    const removeJob = (id) => idb("jobs", "readwrite", (s) => s.delete(id));
    const saveBlob = async (id, blob) => {
        memoryBlobs.set(id, blob);
        return idb("blobs", "readwrite", (s) => s.put(blob, id));
    };
    const loadBlob = async (id) => memoryBlobs.get(id) || (await idb("blobs", "readonly", (s) => s.get(id)));
    const removeBlob = (id) => { memoryBlobs.delete(id); return idb("blobs", "readwrite", (s) => s.delete(id)); };

    /* ---------- helpers ---------- */

    const size = (bytes) => (window.FIC ? FIC.size(bytes) : bytes + " B");
    const kindOf = (name) => (window.FIC ? FIC.kind(name) : "file");
    const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

    let paintQueued = false;
    function changed() {
        if (paintQueued) return;
        paintQueued = true;
        requestAnimationFrame(() => {
            paintQueued = false;
            if (Uploader.onChange) Uploader.onChange();
        });
    }

    async function api(url, options) {
        const response = await fetch(url, Object.assign({ credentials: "same-origin" }, options));
        if (response.status === 401) { window.location.reload(); throw new Error("Session expired"); }
        let data = {};
        try { data = await response.json(); } catch (e) { /* not json */ }
        if (!response.ok) {
            const error = new Error(data.error || "Server error (" + response.status + ")");
            error.status = response.status;
            error.data = data;
            throw error;
        }
        return data;
    }

    function sendChunk(url, blob, onProgress) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", url);
            xhr.withCredentials = true;
            xhr.upload.onprogress = (event) => { if (event.lengthComputable) onProgress(event.loaded); };
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) resolve();
                else if (xhr.status === 401) { window.location.reload(); reject(new Error("Session expired")); }
                else {
                    let message = "Server error (" + xhr.status + ")";
                    try { message = JSON.parse(xhr.responseText).error || message; } catch (e) { /* ignore */ }
                    const error = new Error(message);
                    error.fatal = xhr.status >= 400 && xhr.status < 500;
                    reject(error);
                }
            };
            xhr.onerror = () => reject(Object.assign(new Error("Connection lost"), { network: true }));
            xhr.ontimeout = xhr.onerror;
            xhr.send(blob);
        });
    }

    /* ---------- the upload itself ---------- */

    async function run(job) {
        if (running.has(job.id)) return;
        running.add(job.id);
        job.status = "uploading";
        job.error = "";
        job.phase = "Starting…";
        changed();
        saveJob(job);

        try {
            const blob = job.blob || (await loadBlob(job.id));
            if (!blob) throw Object.assign(new Error("The saved file is gone – please choose it again."), { fatal: true });
            job.blob = blob;

            const init = await api("/api/user/upload/init", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: job.name, size: job.size, key: job.key, algorithms: job.algorithms })
            });
            job.serverId = init.upload_id;
            job.chunkSize = init.chunk_size;
            job.total = init.total_chunks;

            const have = new Set(init.received);
            const lengthOf = (i) => Math.min(job.chunkSize, job.size - i * job.chunkSize);
            let doneBytes = 0;
            have.forEach((i) => { doneBytes += lengthOf(i); });
            const inflight = {};
            const update = () => {
                job.sent = Math.min(job.size, doneBytes + Object.values(inflight).reduce((a, b) => a + b, 0));
                job.parts = have.size;
                changed();
            };
            job.phase = have.size ? "Resuming…" : "Uploading…";
            update();

            const queue = [];
            for (let i = 0; i < job.total; i++) if (!have.has(i)) queue.push(i);

            const worker = async () => {
                while (queue.length) {
                    const index = queue.shift();
                    const piece = blob.slice(index * job.chunkSize, index * job.chunkSize + lengthOf(index));
                    let attempt = 0;
                    for (;;) {
                        try {
                            job.phase = "Uploading…";
                            await sendChunk(`/api/user/upload/${job.serverId}/chunk/${index}`, piece, (loaded) => { inflight[index] = loaded; update(); });
                            break;
                        } catch (error) {
                            inflight[index] = 0;
                            if (error.fatal || ++attempt >= RETRIES) throw error;
                            job.phase = "Connection problem – retrying…";
                            changed();
                            await new Promise((r) => setTimeout(r, 600 * attempt));
                        }
                    }
                    delete inflight[index];
                    doneBytes += lengthOf(index);
                    have.add(index);
                    update();
                }
            };
            await Promise.all(Array.from({ length: Math.min(PARALLEL, Math.max(1, queue.length)) }, worker));

            job.phase = "Hashing on server…";
            job.sent = job.size;
            changed();
            job.result = await api(`/api/user/upload/${job.serverId}/complete`, { method: "POST" });
            job.status = "done";
            job.phase = "Done";
            job.blob = null;
            await removeBlob(job.id);
            saveJob(job);
            changed();
            if (Uploader.onDone) Uploader.onDone(job);
        } catch (error) {
            job.status = error.network || /Connection|Failed to fetch|NetworkError/i.test(error.message) ? "paused" : "error";
            job.error = error.message;
            job.phase = job.status === "paused" ? "Paused – will continue when you are online" : "Failed";
            saveJob(job);
            changed();
        } finally {
            running.delete(job.id);
        }
    }

    /* ---------- public API ---------- */

    Uploader.add = async (files, algorithms) => {
        for (const file of files) {
            const job = {
                id: "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
                user: Uploader.userKey, name: file.name, size: file.size,
                kind: kindOf(file.name), algorithms: algorithms.slice(),
                key: [file.name, file.size, file.lastModified].join("_"),
                status: "queued", phase: "Saving…", sent: 0, parts: 0, total: 0, error: "", result: null,
                created: Date.now(), blob: file
            };
            Uploader.jobs.unshift(job);
            changed();
            await saveBlob(job.id, file);
            await saveJob(job);
            run(job);
        }
    };

    /** Call once the logged-in user is known: brings back uploads that a refresh interrupted. */
    Uploader.init = async (userKey) => {
        Uploader.userKey = userKey || "guest";
        const saved = (await loadJobs()) || [];
        const mine = saved.filter((j) => j.user === Uploader.userKey).sort((a, b) => b.created - a.created);
        const known = new Set(Uploader.jobs.map((j) => j.id));
        mine.forEach((job) => { if (!known.has(job.id)) Uploader.jobs.push(job); });
        changed();
        Uploader.jobs
            .filter((j) => ["uploading", "queued", "paused"].includes(j.status) && !running.has(j.id))
            .forEach((j) => { j.phase = "Resuming…"; run(j); });
    };

    Uploader.retry = (id) => { const job = Uploader.jobs.find((j) => j.id === id); if (job) run(job); };

    Uploader.cancel = async (id) => {
        const job = Uploader.jobs.find((j) => j.id === id);
        if (!job) return;
        if (job.serverId && job.status !== "done") { try { await api("/api/user/upload/" + job.serverId, { method: "DELETE" }); } catch (e) { /* ignore */ } }
        Uploader.jobs = Uploader.jobs.filter((j) => j.id !== id);
        running.delete(id);
        await removeJob(id);
        await removeBlob(id);
        changed();
    };

    Uploader.clearFinished = async () => {
        const finished = Uploader.jobs.filter((j) => j.status === "done");
        Uploader.jobs = Uploader.jobs.filter((j) => j.status !== "done");
        for (const job of finished) await removeJob(job.id);
        changed();
    };

    window.addEventListener("online", () => {
        Uploader.jobs.filter((j) => j.status === "paused").forEach((j) => run(j));
    });

    /* ---------- progress panel ---------- */

    const ICON = { image: "🖼", video: "🎬", pdf: "📄", audio: "🎵", document: "📝", other: "📦" };

    function card(job) {
        if (job.status === "done" && Uploader.renderDone) return `<div data-job="${job.id}" data-state="done">${Uploader.renderDone(job)}</div>`;
        const percent = job.size ? Math.min(100, Math.round((100 * job.sent) / job.size)) : 0;
        const busy = job.status === "uploading" && job.sent >= job.size;
        const chip = { uploading: "Uploading", queued: "Waiting", paused: "Paused", error: "Failed", done: "Done" }[job.status];
        return `
            <div class="up-job ${job.status}" data-job="${job.id}" data-state="${job.status}">
                <div class="up-ico">${ICON[job.kind] || ICON.other}</div>
                <div class="up-body">
                    <div class="up-top">
                        <b>${esc(job.kind)} · ${size(job.size)}</b>
                        <span class="up-chip ${job.status}">${chip}</span>
                    </div>
                    <div class="up-bar ${busy ? "busy" : ""}"><i style="width:${busy ? 100 : percent}%"></i></div>
                    <div class="up-meta">
                        <span class="up-phase">${esc(job.error && job.status === "error" ? job.error : job.phase)}</span>
                        <span><b class="up-pct">${busy ? "…" : percent + "%"}</b>${job.total ? ` · <span class="up-parts">${job.parts || 0}/${job.total} parts</span>` : ""}</span>
                    </div>
                </div>
                <div class="up-actions">
                    ${job.status === "error" || job.status === "paused" ? `<button type="button" class="btn btn-small" data-up-retry="${job.id}">Retry</button>` : ""}
                    <button type="button" class="btn btn-light btn-small" data-up-cancel="${job.id}" title="Cancel">✕</button>
                </div>
            </div>`;
    }

    Uploader.html = () => {
        if (!Uploader.jobs.length) return "";
        const active = Uploader.jobs.some((j) => ["uploading", "queued", "paused"].includes(j.status));
        const finished = Uploader.jobs.some((j) => j.status === "done");
        return `
            <div class="up-panel">
                <div class="up-head">
                    <h3>Uploads</h3>
                    ${finished ? `<button type="button" class="btn btn-light btn-small" data-up-clear>Clear finished</button>` : ""}
                </div>
                ${active ? `<div class="up-note">🔄 You can refresh or close this page – the upload continues from where it stopped.</div>` : ""}
                ${Uploader.jobs.map(card).join("")}
            </div>`;
    };

    function bindPanel(root) {
        root.querySelectorAll("[data-up-retry]").forEach((b) => { b.onclick = () => Uploader.retry(b.dataset.upRetry); });
        root.querySelectorAll("[data-up-cancel]").forEach((b) => { b.onclick = () => Uploader.cancel(b.dataset.upCancel); });
        root.querySelectorAll("[data-up-clear]").forEach((b) => { b.onclick = () => Uploader.clearFinished(); });
    }

    /** Draw the panel into `el`. Only the numbers change while an upload runs (no flicker). */
    Uploader.paint = (el) => {
        if (!el) return;
        const signature = Uploader.jobs.map((j) => j.id + ":" + j.status).join("|");
        if (el.dataset.signature !== signature) {
            el.dataset.signature = signature;
            el.innerHTML = Uploader.html();
            bindPanel(el);
            if (window.bindCopyButtons) window.bindCopyButtons();
            return;
        }
        Uploader.jobs.forEach((job) => {
            const node = el.querySelector(`[data-job="${job.id}"]`);
            if (!node || job.status === "done") return;
            const percent = job.size ? Math.min(100, Math.round((100 * job.sent) / job.size)) : 0;
            const busy = job.status === "uploading" && job.sent >= job.size;
            const bar = node.querySelector(".up-bar");
            bar.classList.toggle("busy", busy);
            bar.firstElementChild.style.width = (busy ? 100 : percent) + "%";
            node.querySelector(".up-pct").textContent = busy ? "…" : percent + "%";
            node.querySelector(".up-phase").textContent = job.error && job.status === "error" ? job.error : job.phase;
            const parts = node.querySelector(".up-parts");
            if (parts) parts.textContent = (job.parts || 0) + "/" + job.total + " parts";
        });
    };
})();
