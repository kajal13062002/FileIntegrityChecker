/* =========================================================
   FILE INTEGRITY CHECKER - DASHBOARD JAVASCRIPT
   ========================================================= */

const ALGORITHMS = [
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-512/224",
    "SHA-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512"
];

/* =========================
   HELPERS
========================= */

const $ = (id) => document.getElementById(id);

const escapeHTML = (value) =>
    String(value).replace(/[&<>"]/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;"
    }[char]));

const formatDate = (date) =>
    date.toLocaleString([], {
        dateStyle: "medium",
        timeStyle: "short"
    });

const formatTime = (date) =>
    date.toLocaleTimeString([], {
        timeStyle: "short"
    });

const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
};

let currentUser = null;

const state = {
    page: "dash",
    files: [],
    history: [],
    activity: [],
    result: "",
    welcome: true,
    uploadResult: "",
    timer: null
};

function logActivity(message, alert = false) {
    state.activity.push({
        time: new Date(),
        message,
        alert
    });
}

function statusPill(value) {
    return `<span class="pill ${value}">${value}</span>`;
}

function table(headers, rows, emptyMessage = "No data available.") {
    return `
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        ${headers.map((h) => `<th>${h}</th>`).join("")}
                    </tr>
                </thead>
                <tbody>
                    ${
                        rows.length
                            ? rows.join("")
                            : `<tr><td class="empty" colspan="${headers.length}">${emptyMessage}</td></tr>`
                    }
                </tbody>
            </table>
        </div>
    `;
}

/* =========================
   UI HELPERS
========================= */

function pageTitle(title, description) {
    return `
        <div class="page-title">
            <h2>${title}</h2>
            <p>${description}</p>
        </div>
    `;
}

function algorithmPicker(selected) {
    return `
        <div class="algorithm-grid">
            ${ALGORITHMS.map((algorithm) => `
                <label>
                    <input
                        type="checkbox"
                        name="algorithm"
                        value="${algorithm}"
                        ${selected.includes(algorithm) ? "checked" : ""}
                    >
                    ${algorithm}
                </label>
            `).join("")}
        </div>

        <div class="row" style="margin-bottom:16px;">
            <button class="btn btn-light" data-algorithm-action="sha2">
                SHA-2 only
            </button>

            <button class="btn btn-light" data-algorithm-action="all">
                Select all
            </button>

            <button class="btn btn-light" data-algorithm-action="none">
                Clear
            </button>
        </div>
    `;
}

function copyButton(text) {
    return `
        <button
            class="btn btn-light btn-small"
            data-copy="${escapeHTML(text)}"
        >
            Copy
        </button>
    `;
}

function hashRows(hashes) {
    return Object.entries(hashes).map(([algorithm, hash]) => `
        <tr>
            <td>
                <span class="algorithm">${algorithm}</span>
            </td>

            <td>
                <span class="hash">${hash}</span>
            </td>

            <td>
                ${copyButton(hash)}
            </td>
        </tr>
    `);
}

function securityScore() {
    if (!state.files.length) return 100;

    const safe = state.files.filter((file) => file.status === "safe").length;
    return Math.round((100 * safe) / state.files.length);
}

function countStatus(status) {
    return state.files.filter((file) => file.status === status).length;
}

/* =========================
   SECURITY RING
========================= */

function securityRing(percent) {
    const radius = 44;
    const circumference = 2 * Math.PI * radius;
    const progress = circumference * percent / 100;

    return `
        <svg width="120" height="120" viewBox="0 0 120 120">
            <circle
                cx="60"
                cy="60"
                r="${radius}"
                fill="none"
                stroke="rgba(255,255,255,.12)"
                stroke-width="10"
            />

            <circle
                cx="60"
                cy="60"
                r="${radius}"
                fill="none"
                stroke="url(#securityGradient)"
                stroke-width="10"
                stroke-linecap="round"
                stroke-dasharray="${progress} ${circumference}"
                transform="rotate(-90 60 60)"
            />

            <defs>
                <linearGradient id="securityGradient">
                    <stop offset="0" stop-color="#38bdf8"/>
                    <stop offset="1" stop-color="#22d3ee"/>
                </linearGradient>
            </defs>

            <text
                x="60"
                y="58"
                text-anchor="middle"
                fill="#fff"
                font-size="26"
                font-weight="800"
            >
                ${percent}
            </text>

            <text
                x="60"
                y="76"
                text-anchor="middle"
                fill="#9db4e0"
                font-size="10"
            >
                SECURITY SCORE
            </text>
        </svg>
    `;
}

/* =========================
   DONUT
========================= */

function donutChart(data) {
    const total = data.reduce((sum, item) => sum + item[1], 0);
    const radius = 40;
    const circumference = 2 * Math.PI * radius;

    if (!total) {
        return `
            <svg width="130" height="130" viewBox="0 0 120 120">
                <circle
                    cx="60"
                    cy="60"
                    r="40"
                    fill="none"
                    stroke="var(--line)"
                    stroke-width="16"
                />
            </svg>
        `;
    }

    let offset = 0;

    const segments = data.map((item) => {
        const length = circumference * item[1] / total;

        const segment = `
            <circle
                cx="60"
                cy="60"
                r="${radius}"
                fill="none"
                stroke="${item[2]}"
                stroke-width="16"
                stroke-dasharray="${length} ${circumference - length}"
                stroke-dashoffset="${-offset}"
                transform="rotate(-90 60 60)"
            />
        `;

        offset += length;
        return segment;
    }).join("");

    return `
        <svg width="130" height="130" viewBox="0 0 120 120">
            ${segments}

            <text
                x="60"
                y="66"
                text-anchor="middle"
                fill="var(--ink)"
                font-size="22"
                font-weight="800"
            >
                ${total}
            </text>
        </svg>
    `;
}

/* =========================
   VIEWS
========================= */

const Views = {

    dash() {
        const usage = {};

        state.files.forEach((file) => {
            Object.keys(file.hashes).forEach((algorithm) => {
                usage[algorithm] = (usage[algorithm] || 0) + 1;
            });
        });

        const maxUsage = Math.max(1, ...Object.values(usage));

        const tiles = [
            ["upload", "Upload File", "☁", "Register & hash a file"],
            ["verify", "Verify File", "✓", "Compare with baseline"],
            ["tool", "Hash Tool", "🔐", "Step-by-step SHA hashing"],
            ["cmp", "Compare Files", "⚖", "Image, PDF & hash compare"],
            ["mon", "Monitor", "📡", "Tamper & restore a file"],
            ["hist", "History", "🕘", "Past verifications"],
            ["rep", "Reports", "📊", "Summary & CSV"],
            ["prof", "Profile", "👤", "Account details"]
        ];

        return `
            <div class="hero">
                <div>
                    <span class="tag">● SYSTEM PROTECTED</span>

                    <h2>Welcome ${escapeHTML(currentUser?.name || "User")}</h2>

                    <p>
                        Multi-algorithm file integrity verification & monitoring.
                    </p>

                    ${
                        state.welcome
                            ? `
                                <div
                                    class="tag"
                                    style="
                                        background:rgba(56,189,248,.18);
                                        color:#bae6fd;
                                        border-color:rgba(56,189,248,.4);
                                    "
                                >
                                    User Login Successful.
                                    <a id="closeWelcome" style="cursor:pointer;margin-left:6px;">✕</a>
                                </div>
                            `
                            : ""
                    }
                </div>

                ${securityRing(securityScore())}
            </div>

            <div class="grid grid-4" style="margin-top:20px;">
                <div class="stat stat-blue">
                    <b>${state.files.length}</b>
                    <span>Total Files</span>
                </div>

                <div class="stat stat-green">
                    <b>${countStatus("safe")}</b>
                    <span>Safe</span>
                </div>

                <div class="stat stat-purple">
                    <b>${countStatus("modified")}</b>
                    <span>Modified</span>
                </div>

                <div class="stat stat-red">
                    <b>${countStatus("tampered")}</b>
                    <span>Tampered</span>
                </div>
            </div>

            <div class="grid grid-4" style="margin-top:20px;">
                ${tiles.map((tile) => `
                    <div class="tile" data-go="${tile[0]}">
                        <div class="tile-icon">${tile[2]}</div>
                        <h3>${tile[1]}</h3>
                        <p>${tile[3]}</p>
                    </div>
                `).join("")}
            </div>

            <div class="grid grid-2">
                <div class="card">
                    <div class="card-header">
                        Integrity status
                    </div>

                    <div class="card-body" style="display:flex;gap:24px;align-items:center;flex-wrap:wrap;">
                        ${donutChart([
                            ["Safe", countStatus("safe"), "#22d3ee"],
                            ["Modified", countStatus("modified"), "#fbbf24"],
                            ["Tampered", countStatus("tampered"), "#fb7185"]
                        ])}

                        <div style="color:var(--muted);">
                            <div>● <b style="color:#22d3ee;">Safe</b> ${countStatus("safe")}</div>
                            <div>● <b style="color:#fbbf24;">Modified</b> ${countStatus("modified")}</div>
                            <div>● <b style="color:#fb7185;">Tampered</b> ${countStatus("tampered")}</div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        Algorithm usage
                    </div>

                    <div class="card-body">
                        ${
                            Object.keys(usage).length
                                ? Object.entries(usage).map(([algorithm, count]) => `
                                    <div style="display:flex;justify-content:space-between;font-size:13px;">
                                        <span class="algorithm">${algorithm}</span>
                                        <span>${count}</span>
                                    </div>

                                    <div class="progress-bar">
                                        <i style="width:${100 * count / maxUsage}%;"></i>
                                    </div>
                                `).join("")
                                : `<div class="empty">Upload files to see usage.</div>`
                        }
                    </div>
                </div>
            </div>

            <div class="grid grid-2">
                <div class="card">
                    <div class="card-header">Recent files</div>

                    ${table(
                        ["ID", "File", "Size", "Status"],
                        state.files
                            .slice(-5)
                            .reverse()
                            .map((file) => `
                                <tr>
                                    <td>${file.id}</td>
                                    <td><b>${escapeHTML(file.name)}</b></td>
                                    <td>${formatSize(file.size)}</td>
                                    <td>${statusPill(file.status)}</td>
                                </tr>
                            `),
                        "No files yet."
                    )}
                </div>

                <div class="card">
                    <div class="card-header">Activity log</div>

                    <div class="activity">
                        ${
                            state.activity.length
                                ? state.activity
                                    .slice(-6)
                                    .reverse()
                                    .map((item) => `
                                        <div>
                                            <small>${formatTime(item.time)}</small>
                                            ${escapeHTML(item.message)}
                                        </div>
                                    `)
                                    .join("")
                                : `<div class="empty" style="display:block;">No activity yet.</div>`
                        }
                    </div>
                </div>
            </div>
        `;
    },

    upload() {
        return `
            ${pageTitle(
                "Upload File",
                "Select files (PDF, image, video or any other type) and the SHA algorithms to generate."
            )}

            <div class="card card-body no-margin">
                ${FIC.drop("uploadFiles", { multiple: true, hint: "PDF, image, video or any file" })}

                <p style="font-weight:700;margin:20px 0 0;">
                    Hash algorithms
                </p>

                ${algorithmPicker(["SHA-256", "SHA-512", "SHA3-256"])}

                <button class="btn" id="generateHashes">
                    Upload & Generate Hashes
                </button>
            </div>

            <div id="uploadJobs" class="up-wrap"></div>
        `;
    },

    verify() {
        return `
            ${pageTitle(
                "Verify File",
                "Re-upload a copy and compare it with the stored baseline."
            )}

            <div class="card card-body no-margin">
                ${
                    state.files.length
                        ? `
                            <select id="verifyFile">
                                ${state.files.map((file) => `
                                    <option value="${file.id}">
                                        #${file.id} · ${escapeHTML(file.name)} (${file.status})
                                    </option>
                                `).join("")}
                            </select>

                            ${FIC.drop("verifyInput", { hint: "Choose the current copy of the file" })}

                            <button class="btn" id="verifyBtn">
                                Verify Integrity
                            </button>
                        `
                        : `
                            <div class="empty">
                                Upload a file first.
                            </div>
                        `
                }
            </div>

            ${FIC.progress("verifyProg")}

            ${state.result}
        `;
    },

    tool() {
        return `
            ${pageTitle(
                "Hash Tool",
                "Hash text, PDF, image, video or any file. Pick one algorithm for its step-by-step working, or select all."
            )}

            ${FIC.hashToolHTML()}
        `;
    },

    cmp() {
        return `
            ${pageTitle(
                "Compare Files",
                "Compare two images or two PDFs and see how much is different, or match two files by hash."
            )}

            ${FIC.compareHTML()}
        `;
    },

    mon() {
        return `
            ${pageTitle(
                "Monitor",
                "Tamper a file to see the change get detected, then restore it."
            )}

            ${FIC.monitorHTML(state.files.map((file) => ({
                id: file.id,
                name: file.name,
                size: file.size,
                status: file.status,
                lastChecked: file.checked
            })), { empty: "Upload files to monitor them." })}
        `;
    },

    hist() {
        return `
            ${pageTitle(
                "Verification History",
                "All past verification results."
            )}

            <div class="card no-margin">
                ${table(
                    ["ID", "File", "Algorithm", "Stored", "Calculated", "Result", "When"],
                    state.history
                        .slice()
                        .reverse()
                        .map((item) => `
                            <tr>
                                <td>${item.id}</td>
                                <td><b>${escapeHTML(item.file)}</b></td>
                                <td><span class="algorithm">${item.algorithm}</span></td>
                                <td><span class="hash">${item.stored.slice(0, 14)}...</span></td>
                                <td><span class="hash">${(item.calculated || "n/a").slice(0, 14)}...</span></td>
                                <td>${statusPill(item.result)}</td>
                                <td>${formatDate(item.time)}</td>
                            </tr>
                        `),
                    "No verifications yet."
                )}
            </div>
        `;
    },

    rep() {
        return `
            ${pageTitle(
                "Reports",
                "Integrity summary for your files."
            )}

            <div class="report-actions top">
                <a class="btn" href="/api/user/report.pdf" download>⬇ Download PDF</a>
                <a class="btn btn-light" href="/api/user/report.csv" download>⬇ Download CSV</a>
            </div>

            <div class="grid grid-4">
                <div class="stat stat-blue">
                    <b>${state.files.length}</b>
                    <span>Files</span>
                </div>

                <div class="stat stat-green">
                    <b>${countStatus("safe")}</b>
                    <span>Safe</span>
                </div>

                <div class="stat stat-purple">
                    <b>${countStatus("modified")}</b>
                    <span>Modified</span>
                </div>

                <div class="stat stat-red">
                    <b>${checkGroups().length}</b>
                    <span>Verifications</span>
                </div>
            </div>

            ${FIC.reportCharts({
                kpis: false,
                heat: false,
                files: state.files.map((file) => ({
                    name: file.name,
                    size: file.size,
                    status: file.status,
                    algorithms: Object.keys(file.hashes)
                })),
                checks: checkGroups()
            })}

            <div class="card" style="margin-top:20px;">
                <div class="card-header">
                    Integrity report

                    <span class="report-actions">
                        <a class="btn" href="/api/user/report.pdf" download>⬇ Download PDF</a>
                        <a class="btn btn-light" href="/api/user/report.csv" download>⬇ Download CSV</a>
                    </span>
                </div>

                ${table(
                    ["ID", "File", "Size", "Algorithm", "Baseline hash", "Status"],
                    state.files.map((file) => {
                        const algorithm = Object.keys(file.hashes)[0] || "—";
                        const baseline = file.hashes[algorithm] || "";

                        return `
                            <tr>
                                <td>${file.id}</td>
                                <td><b>${escapeHTML(file.name)}</b></td>
                                <td>${formatSize(file.size)}</td>
                                <td><span class="algorithm">${algorithm}</span></td>
                                <td><span class="hash">${baseline.slice(0, 28)}${baseline ? "..." : ""}</span></td>
                                <td>${statusPill(file.status)}</td>
                            </tr>
                        `;
                    }),
                    "No data to report yet."
                )}
            </div>
        `;
    },

    prof() {
        const initial = (currentUser?.name || "U").trim().charAt(0).toUpperCase();
        const tile = (icon, label, value) => `
            <div class="profile-item">
                <div class="profile-icon">${icon}</div>

                <div>
                    <small>${label}</small>
                    <b>${value}</b>
                </div>
            </div>
        `;

        return `
            <div class="profile-hero">
            <div class="avatar">${initial}</div>    

                <div class="profile-name">
                    <h2>${escapeHTML(currentUser?.name || "User")}</h2>
                    <p>${escapeHTML(currentUser?.email || "")}</p>

                    <div class="row">
                        <span class="chip">👤 user</span>
                        <span class="chip">🟢 active</span>
                    </div>
                </div>
            </div>

            <h4 class="section-heading">Account details</h4>

            <div class="profile-grid">
                ${tile("✉", "Email", escapeHTML(currentUser?.email || "—"))}
                ${tile("📞", "Phone", escapeHTML(currentUser?.mobile || "—"))}
                ${tile("⚥", "Gender", escapeHTML(currentUser?.gender || "—"))}
                ${tile("🎂", "Date of Birth", escapeHTML(currentUser?.dob || "—"))}
                ${tile("🏙", "City", escapeHTML(currentUser?.city || "—"))}
                ${tile("📍", "State", escapeHTML(currentUser?.state || "—"))}
                ${tile("🛡", "Role", escapeHTML(currentUser?.role || "user"))}
                ${tile("●", "Status", escapeHTML(currentUser?.status || "active"))}
                ${tile("🗓", "Account Created", escapeHTML(currentUser?.created_at || "—"))}
            </div>

            <h4 class="section-heading">Last login</h4>

            <div class="card no-margin">
                <div class="last-login">
                    <div class="status-dot"></div>

                    <div style="flex:1;min-width:160px;">
                        <b>Login successful</b>
                    </div>

                    <div class="login-meta">
                        <small>IP ADDRESS</small>
                        <b>127.0.0.1</b>
                    </div>

                    <div class="login-meta">
                        <small>LOGIN TIME</small>
                        <b>${formatDate(new Date())}</b>
                    </div>

                    <div class="login-meta">
                        <small>LOGOUT TIME</small>
                        <b>Active session</b>
                    </div>
                </div>
            </div>
        `;
    }
};

/* =========================
   FILE HELPERS
========================= */

function selectedAlgorithms() {
    return [...document.querySelectorAll('input[name="algorithm"]:checked')]
        .map((input) => input.value);
}

/* One verification writes one history row per algorithm - group them back into one check. */
function checkGroups() {
    const groups = {};

    state.history.forEach((item) => {
        const key = `${item.fileId}|${item.time.getTime()}`;
        const group = groups[key] || (groups[key] = {
            time: item.time,
            status: "safe",
            percent: null,
            file: item.file
        });

        if (item.result !== "safe") group.status = item.result;

        const percent = FIC.percentFromRemarks(item.remarks);
        if (percent !== null) group.percent = percent;
    });

    return Object.values(groups).sort((a, b) => a.time - b.time);
}

/* =========================
   RENDER
========================= */

function render() {
    clearInterval(state.timer);

    document.querySelectorAll("[data-page]").forEach((link) => {
        link.classList.toggle(
            "active",
            link.dataset.page === state.page
        );
    });

    $("app").innerHTML = Views[state.page]();

    bindEvents();
}

/* =========================
   EVENTS
========================= */

function bindEvents() {

    document.querySelectorAll("[data-go]").forEach((element) => {
        element.onclick = () => goTo(element.dataset.go);
    });

    document.querySelectorAll("[data-copy]").forEach((button) => {
        button.onclick = async () => {
            await navigator.clipboard.writeText(button.dataset.copy);
            button.textContent = "✓";
        };
    });

    document.querySelectorAll("[data-algorithm-action]").forEach((button) => {
        button.onclick = () => {
            const action = button.dataset.algorithmAction;

            document.querySelectorAll('input[name="algorithm"]').forEach((input) => {
                if (action === "all") {
                    input.checked = true;
                } else if (action === "none") {
                    input.checked = false;
                } else if (action === "sha2") {
                    input.checked = /^SHA-(224|256|384|512)$/.test(input.value);
                }
            });
        };
    });

    FIC.bindDrops(document);

    if ($("closeWelcome")) {
        $("closeWelcome").onclick = () => {
            state.welcome = false;
            render();
        };
    }

    bindUpload();

    bindVerify();

    FIC.bindHashTool({ onDone: (message) => logActivity(message) });

    FIC.bindCompare({ onDone: (message) => logActivity(message) });

    bindMonitor();

    bindReports();
}

/* =========================
   UPLOAD
========================= */

function bindUpload() {
    Uploader.paint($("uploadJobs"));

    if (!$("generateHashes")) return;

    $("generateHashes").onclick = () => {
        const files = [...$("uploadFiles").files];
        const algorithms = selectedAlgorithms();

        if (!files.length || !algorithms.length) {
            alert("Choose a file and at least one algorithm.");
            return;
        }

        Uploader.add(files, algorithms);

        // empty the drop box so the next file can be chosen while these upload
        $("uploadFiles").value = "";
        $("uploadFiles").dispatchEvent(new Event("change", { bubbles: true }));
    };
}

/* finished upload card (hashes + copy buttons) */
Uploader.renderDone = (job) => {
    const data = job.result;
    return `<div class="card"><div class="card-header">${FIC.kind(data.name)} · ${formatSize(data.size)} · ID #${data.id}</div>${table(["Algorithm", "Hash", ""], hashRows(data.hashes))}</div>`;
};

Uploader.onChange = () => Uploader.paint($("uploadJobs"));

Uploader.onDone = async (job) => {
    logActivity(`Uploaded ${job.result.name}`);
    await loadDatabaseData();
    if (["dash", "rep", "mon"].includes(state.page)) render();
};

/* =========================
   VERIFY
========================= */

function bindVerify() {
    if (!$("verifyBtn")) return;

    $("verifyBtn").onclick = async () => {
        const fileId = $("verifyFile").value;
        const upload = FIC.file("verifyInput");

        if (!fileId || !upload) {
            alert("Choose a stored file and a file to compare.");
            return;
        }

        const button = $("verifyBtn");
        button.disabled = true;

        const form = new FormData();
        form.append("file_id", fileId);
        form.append("file", upload);

        FIC.setProgress("verifyProg", 0, "Uploading…");

        const result = await FIC.post("/api/user/verify", form, (loaded, total) => {
            FIC.setProgress(
                "verifyProg",
                loaded >= total ? null : Math.min(99, (100 * loaded) / total),
                loaded >= total ? "Verifying…" : "Uploading…"
            );
        });

        FIC.setProgress("verifyProg", false);
        button.disabled = false;

        if (!result.ok) {
            alert(result.data.error || "Verification failed");
            return;
        }

        state.result = FIC.verifyResultHTML(result.data);
        logActivity(
            `Verified ${result.data.file}: ${result.data.status}`,
            result.data.status !== "safe"
        );

        await loadDatabaseData();
        render();
    };
}

/* =========================
   MONITOR  (Tamper & Restore)
========================= */

function bindMonitor() {
    FIC.bindMonitor(
        (action, id) => `/api/user/monitor/${id}/${action}`,
        async () => {
            await loadDatabaseData();
            render();
        }
    );
}

/* =========================
   REPORT
========================= */

function bindReports() {
    if (!$("copyCSV")) return;

    $("copyCSV").onclick = async () => {
        const csv =
            "id,file,size,algorithm,hash,status\n" +
            state.files.map((file) => {
                const algorithm = Object.keys(file.hashes)[0];

                return [
                    file.id,
                    file.name,
                    file.size,
                    algorithm,
                    file.hashes[algorithm],
                    file.status
                ].join(",");
            }).join("\n");

        await navigator.clipboard.writeText(csv);

        $("copyCSV").textContent = "Copied ✓";
    };
}

function bindCopyButtons() {
    document.querySelectorAll("[data-copy]").forEach((button) => {
        button.onclick = async () => {
            await navigator.clipboard.writeText(button.dataset.copy);
            button.textContent = "✓";
        };
    });
}

/* =========================
   LOAD SCREEN  (shows how much has loaded)
========================= */

const LoadScreen = {
    steps: ["Your profile", "Your files", "Verification history", "Building dashboard"],
    done: 0, shown: 0, finished: false,

    init() {
        this.box = document.getElementById("loadScreen");
        if (!this.box) return;
        this.box.querySelector(".fic-load-list").innerHTML = this.steps
            .map((name, i) => `<li data-i="${i}"><span class="tick"></span>${name}</li>`).join("");
        this.tick();
    },

    step(index) {
        if (!this.box) return;
        this.done = Math.max(this.done, index + 1);
        const item = this.box.querySelector(`li[data-i="${index}"]`);
        if (item) item.classList.add("ok");
    },

    tick() {
        if (!this.box || this.finished) return;
        const target = (100 * this.done) / this.steps.length;
        this.shown += (target - this.shown) * 0.4 + 1;
        if (this.shown > target) this.shown = target;
        this.box.querySelector(".fic-load-pct").textContent = Math.round(this.shown) + "%";
        this.box.querySelector(".fic-load-bar i").style.width = this.shown + "%";
        this.box.querySelector(".fic-load-text").textContent =
            this.done >= this.steps.length ? "Ready" : "Loading " + this.steps[this.done].toLowerCase() + "…";
        if (this.shown >= 100) { this.finish(); return; }
        requestAnimationFrame(() => this.tick());
    },

    finish() {
        if (!this.box || this.finished) return;
        if (this.done < this.steps.length) {
            this.done = this.steps.length;
            this.steps.forEach((_, i) => this.step(i));
            return;
        }
        this.finished = true;
        this.box.querySelector(".fic-load-pct").textContent = "100%";
        this.box.querySelector(".fic-load-bar i").style.width = "100%";
        setTimeout(() => {
            this.box.classList.add("hide");
            setTimeout(() => this.box.remove(), 300);
        }, 100);
    }
};

LoadScreen.init();

async function loadDatabaseData(first) {
    try {
        const track = (index, request) => request.then((response) => {
            if (first) LoadScreen.step(index);
            return response;
        });

        const [userRes, filesRes, historyRes] = await Promise.all([
            track(0, fetch("/api/user/me")),
            track(1, fetch("/api/user/files")),
            track(2, fetch("/api/user/history"))
        ]);
        if (!userRes.ok) return;
        currentUser = await userRes.json();
        const files = filesRes.ok ? await filesRes.json() : [];
        const history = historyRes.ok ? await historyRes.json() : [];
        state.files = files.map(f => ({
            id: f.id, name: f.name, size: f.size || 0, hashes: f.hashes || {},
            status: f.status || "safe", filepath: f.filepath, upload_date: f.upload_date,
            type: f.type || "",
            checked: f.last_checked ? new Date(f.last_checked) : null
        }));
        state.history = history.map((h, i) => ({
            id: h.id || i + 1, fileId: h.file_id,
            file: h.filename || h.file || String(h.file_id || ""),
            remarks: h.remarks || "",
            algorithm: h.algorithm || "—", stored: h.stored_hash || h.stored || "",
            calculated: h.calculated_hash || h.calculated || "",
            result: h.result || h.status || "", time: new Date(h.verified_at || h.checked_at || h.created_at || Date.now())
        }));
    } catch (error) {
        console.error("Database load failed", error);
    }
}

/* =========================
   NAVIGATION
========================= */

const ROUTES = {
    upload: "upload", verify: "verify", "hash-tool": "tool",
    monitor: "mon", reports: "rep", compare: "cmp"
};
const ROUTE_OF = Object.fromEntries(Object.entries(ROUTES).map(([k, v]) => [v, k]));

function goTo(page) {
    clearInterval(state.timer);
    if (ROUTE_OF[page]) history.replaceState(null, "", "#" + ROUTE_OF[page]);

    state.page = page;
    state.result = "";

    render();
}

document.querySelectorAll("[data-page]").forEach((link) => {
    link.onclick = () => goTo(link.dataset.page);
});

/* =========================
   THEME
========================= */

$("themeBtn").onclick = () => {
    const html = document.documentElement;

    html.dataset.theme =
        html.dataset.theme === "dark"
            ? "light"
            : "dark";
};

/* =========================
   LOGOUT
========================= */

if ($("logoutBtn")) {
    $("logoutBtn").onclick = () => { window.location.href = "/logout"; };
}

/* =========================
   INITIAL LOAD
========================= */

state.page = ROUTES[location.hash.slice(1)] || state.page;
loadDatabaseData(true).then(() => {
    render();
    LoadScreen.step(3);
    Uploader.init(currentUser && currentUser.email);
});
document.addEventListener("DOMContentLoaded", () => {
    if (!currentUser) currentUser = { name: "User" };
});
