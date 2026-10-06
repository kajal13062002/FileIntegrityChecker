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
   HASH FUNCTIONS
========================= */

const bytesToHex = (buffer) =>
    [...new Uint8Array(buffer)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");

async function calculateHash(buffer, algorithm) {
    try {
        if (["SHA-1", "SHA-256", "SHA-384", "SHA-512"].includes(algorithm)) {
            return bytesToHex(await crypto.subtle.digest(algorithm, buffer));
        }

        const custom = {
            "SHA-224": () => sha256.sha224(buffer),
            "SHA-512/224": () => sha512.sha512_224(buffer),
            "SHA-512/256": () => sha512.sha512_256(buffer),
            "SHA3-224": () => sha3_224(buffer),
            "SHA3-256": () => sha3_256(buffer),
            "SHA3-384": () => sha3_384(buffer),
            "SHA3-512": () => sha3_512(buffer)
        };

        return custom[algorithm] ? custom[algorithm]() : null;
    } catch (error) {
        console.error(error);
        return null;
    }
}

async function calculateAllHashes(buffer, algorithms) {
    const result = {};

    for (const algorithm of algorithms) {
        const hash = await calculateHash(buffer, algorithm);

        if (hash) {
            result[algorithm] = hash;
        }
    }

    return result;
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

function fileDrop(inputId, label, multiple = false) {
    return `
        <div class="drop-zone" data-drop-zone>
            <div style="font-size:30px;">☁</div>
            <b class="drop-label">${label}</b>
            <br>
            <small>Processed locally in your browser — nothing is uploaded</small>

            <input
                type="file"
                id="${inputId}"
                ${multiple ? "multiple" : ""}
                hidden
            >
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
            ["tool", "Hash Tool", "🔐", "Hash text or any file"],
            ["cmp", "Compare Files", "⚖", "Check two files match"],
            ["mon", "Monitor", "📡", "Detect tampering live"],
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
                "Select files and the SHA algorithms to generate."
            )}

            <div class="card card-body no-margin">
                ${fileDrop("uploadFiles", "Click or drag files here", true)}

                <p style="font-weight:700;margin:20px 0 0;">
                    Hash algorithms 
                </p>

                ${algorithmPicker(["SHA-256", "SHA-512", "SHA3-256"])}

                <button class="btn" id="generateHashes">
                    Upload & Generate Hashes
                </button>
            </div>

            <div id="uploadResult">
                ${state.uploadResult}
            </div>
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

                            ${fileDrop("verifyInput", "Choose the current copy to compare")}

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

            ${state.result}
        `;
    },

    tool() {
        return `
            ${pageTitle(
                "Hash Tool",
                "Instantly hash any text or file with every SHA algorithm."
            )}

            <div class="card card-body no-margin">
                <textarea
                    id="hashText"
                    placeholder="Type or paste text..."
                ></textarea>

                <div class="row">
                    <b style="color:var(--muted);">or</b>
                    ${fileDrop("hashFile", "Choose a file")}
                </div>

                <div class="row" style="margin-top:14px;">
                    <button class="btn" id="hashToolBtn">
                        Generate hashes
                    </button>
                </div>
            </div>

            <div id="hashToolResult"></div>
        `;
    },

    cmp() {
        return `
            ${pageTitle(
                "Compare Files",
                "Check whether two files are byte-identical across all algorithms."
            )}

            <div class="grid grid-2">
                <div class="card card-body no-margin">
                    ${fileDrop("compareFileA", "File A")}
                </div>

                <div class="card card-body no-margin">
                    ${fileDrop("compareFileB", "File B")}
                </div>
            </div>

            <div class="row" style="margin-top:18px;">
                <button class="btn" id="compareBtn">
                    Compare
                </button>
            </div>

            <div id="compareResult"></div>
        `;
    },

    mon() {
        return `
            ${pageTitle(
                "Real-time Monitor",
                "Rescans stored files and detects content changes."
            )}

            <div class="card card-body no-margin">
                <div class="row">
                    <button class="btn btn-green" id="scanBtn">
                        Scan now
                    </button>

                    <label style="display:flex;align-items:center;gap:8px;color:var(--muted);font-weight:600;">
                        <input type="checkbox" id="autoScan">
                        Auto-scan every 5s
                    </label>

                    <span id="scanInfo" style="color:var(--muted);"></span>
                </div>
            </div>

            <div class="card">
                ${table(
                    ["File", "Primary hash", "Status", "Last checked", "Demo"],
                    state.files.map((file) => {
                        const algorithm = Object.keys(file.hashes)[0];

                        return `
                            <tr>
                                <td><b>${escapeHTML(file.name)}</b></td>

                                <td>
                                    <span class="algorithm">${algorithm}</span>
                                    <span class="hash">${file.hashes[algorithm].slice(0, 18)}...</span>
                                </td>

                                <td>${statusPill(file.status)}</td>

                                <td>${file.checked ? formatDate(file.checked) : "—"}</td>

                                <td>
                                    <div class="row">
                                        <button
                                            class="btn btn-red btn-small"
                                            data-tamper="${file.id}"
                                        >
                                            Tamper
                                        </button>

                                        <button
                                            class="btn btn-light btn-small"
                                            data-restore="${file.id}"
                                        >
                                            Restore
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }),
                    "Upload files to monitor them."
                )}
            </div>

            <div class="card">
                <div class="card-header">Alerts</div>

                <div class="activity">
                    ${
                        state.activity.filter((item) => item.alert).length
                            ? state.activity
                                .filter((item) => item.alert)
                                .reverse()
                                .map((item) => `
                                    <div>
                                        <small>${formatTime(item.time)}</small>
                                        🚨 ${escapeHTML(item.message)}
                                    </div>
                                `)
                                .join("")
                            : `
                                <div class="empty" style="display:block;">
                                    No alerts. Press "Tamper" on a file, then scan.
                                </div>
                            `
                    }
                </div>
            </div>
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
                    <b>${state.history.length}</b>
                    <span>Verifications</span>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    Integrity report

                    <button class="btn" id="copyCSV">
                        Copy as CSV
                    </button>
                </div>

                ${table(
                    ["ID", "File", "Size", "Algorithm", "Baseline hash", "Status"],
                    state.files.map((file) => {
                        const algorithm = Object.keys(file.hashes)[0];

                        return `
                            <tr>
                                <td>${file.id}</td>
                                <td><b>${escapeHTML(file.name)}</b></td>
                                <td>${formatSize(file.size)}</td>
                                <td><span class="algorithm">${algorithm}</span></td>
                                <td><span class="hash">${file.hashes[algorithm].slice(0, 28)}...</span></td>
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

function selectedFile(inputId) {
    const input = $(inputId);
    return input && input.files.length ? input.files[0] : null;
}

function selectedAlgorithms() {
    return [...document.querySelectorAll('input[name="algorithm"]:checked')]
        .map((input) => input.value);
}

/* =========================
   MONITOR SCAN
========================= */

async function scanFiles() {
    let newAlerts = 0;

    for (const file of state.files) {
        const primaryAlgorithm = Object.keys(file.hashes)[0];
        const currentHash = await calculateHash(file.buffer, primaryAlgorithm);

        file.checked = new Date();

        if (currentHash !== file.hashes[primaryAlgorithm]) {
            if (file.status !== "modified") {
                file.status = "modified";
                newAlerts++;

                logActivity(
                    `${file.name} was modified (${primaryAlgorithm} mismatch)`,
                    true
                );
            }
        } else {
            file.status = "safe";
        }
    }

    logActivity(
        `Scan complete: ${state.files.length} checked, ${newAlerts} new alerts`
    );

    return newAlerts;
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

    bindDropZones();

    if ($("closeWelcome")) {
        $("closeWelcome").onclick = () => {
            state.welcome = false;
            render();
        };
    }

    bindUpload();

    bindVerify();

    bindHashTool();

    bindCompare();

    bindMonitor();

    bindReports();
}

/* =========================
   DROP ZONES
========================= */

function bindDropZones() {
    document.querySelectorAll("[data-drop-zone]").forEach((zone) => {
        const input = zone.querySelector("input");
        const label = zone.querySelector(".drop-label");
        const originalLabel = label.textContent;

        zone.onclick = (event) => {
            if (event.target !== input) {
                input.click();
            }
        };

        input.onchange = () => {
            label.textContent =
                [...input.files].map((file) => file.name).join(", ") ||
                originalLabel;
        };

        zone.ondragover = (event) => {
            event.preventDefault();
            zone.classList.add("dragging");
        };

        zone.ondragleave = () => {
            zone.classList.remove("dragging");
        };

        zone.ondrop = (event) => {
            event.preventDefault();
            zone.classList.remove("dragging");

            input.files = event.dataTransfer.files;
            input.dispatchEvent(new Event("change"));
        };
    });
}

/* =========================
   UPLOAD
========================= */

function bindUpload() {
    if (!$("generateHashes")) return;

    $("generateHashes").onclick = async () => {
        const files = [...$("uploadFiles").files];
        const algorithms = selectedAlgorithms();

        if (!files.length || !algorithms.length) {
            $("uploadResult").innerHTML = `<div class="card card-body empty">Choose a file and at least one algorithm.</div>`;
            return;
        }

        let output = "";
        for (const file of files) {
            const form = new FormData();
            form.append("file", file);
            algorithms.forEach(a => form.append("algorithms", a));

            const response = await fetch("/api/user/upload", { method: "POST", body: form });
            const data = await response.json();
            if (!response.ok) {
                output += `<div class="card card-body empty">${escapeHTML(data.error || "Upload failed")}</div>`;
                continue;
            }

            output += `<div class="card"><div class="card-header">${escapeHTML(data.name)} · ${formatSize(data.size)} · ID #${data.id}</div>${table(["Algorithm","Hash",""], hashRows(data.hashes))}</div>`;
        }

        state.uploadResult = output;
        await loadDatabaseData();
        $("uploadResult").innerHTML = output;
    };
}

/* =========================
   VERIFY
========================= */

function bindVerify() {
    if (!$("verifyBtn")) return;

    $("verifyBtn").onclick = async () => {
        const fileId = $("verifyFile").value;
        const upload = selectedFile("verifyInput");
        if (!fileId || !upload) { alert("Choose a stored file and a file to compare."); return; }

        const form = new FormData();
        form.append("file_id", fileId);
        form.append("file", upload);
        const response = await fetch("/api/user/verify", { method: "POST", body: form });
        const data = await response.json();
        if (!response.ok) { alert(data.error || "Verification failed"); return; }

        state.result = `<div class="verify-result ${data.result === "Original" ? "verify-safe" : "verify-tampered"}"><h3>File is ${escapeHTML(data.result)}</h3>${escapeHTML(data.file)} · ${data.matched}/${data.total} hashes matched</div><div class="card">${table(["Algorithm","Stored","Calculated","Result"], data.rows.map(row => `<tr><td><span class="algorithm">${escapeHTML(row.algorithm)}</span></td><td><span class="hash">${row.stored}</span></td><td><span class="hash">${row.calculated}</span></td><td>${statusPill(row.match ? "match" : "mismatch")}</td></tr>`))}</div>`;
        await loadDatabaseData();
        render();
    };
}

/* =========================
   HASH TOOL
========================= */

function bindHashTool() {
    if (!$("hashToolBtn")) return;

    $("hashToolBtn").onclick = async () => {
        const file = selectedFile("hashFile");

        const buffer = file
            ? await file.arrayBuffer()
            : new TextEncoder().encode($("hashText").value);

        if (!buffer.byteLength) {
            $("hashToolResult").innerHTML = `
                <div class="card card-body empty">
                    Enter text or choose a file.
                </div>
            `;
            return;
        }

        const hashes = await calculateAllHashes(buffer, ALGORITHMS);

        logActivity(
            `Hashed ${file ? file.name : "text input"} with Hash Tool`
        );

        $("hashToolResult").innerHTML = `
            <div class="card">
                <div class="card-header">
                    ${file ? escapeHTML(file.name) : "Text input"}
                    · ${formatSize(buffer.byteLength)}
                </div>

                ${table(
                    ["Algorithm", "Hash", ""],
                    hashRows(hashes)
                )}
            </div>
        `;

        bindCopyButtons();
    };
}

/* =========================
   COMPARE
========================= */

function bindCompare() {
    if (!$("compareBtn")) return;

    $("compareBtn").onclick = async () => {
        const fileA = selectedFile("compareFileA");
        const fileB = selectedFile("compareFileB");

        if (!fileA || !fileB) {
            alert("Choose both files.");
            return;
        }

        const hashesA = await calculateAllHashes(
            await fileA.arrayBuffer(),
            ALGORITHMS
        );

        const hashesB = await calculateAllHashes(
            await fileB.arrayBuffer(),
            ALGORITHMS
        );

        const algorithms = Object.keys(hashesA);
        let matched = 0;

        const rows = algorithms.map((algorithm) => {
            const match = hashesA[algorithm] === hashesB[algorithm];

            if (match) matched++;

            return `
                <tr>
                    <td><span class="algorithm">${algorithm}</span></td>
                    <td><span class="hash">${hashesA[algorithm].slice(0, 20)}...</span></td>
                    <td><span class="hash">${hashesB[algorithm].slice(0, 20)}...</span></td>
                    <td>${statusPill(match ? "same" : "diff")}</td>
                </tr>
            `;
        });

        logActivity(
            `Compared ${fileA.name} with ${fileB.name}`
        );

        const identical = matched === algorithms.length;

        $("compareResult").innerHTML = `
            <div class="verify-result ${
                identical ? "verify-safe" : "verify-tampered"
            }">
                <h3>
                    ${identical ? "Files are identical" : "Files differ"}
                </h3>

                ${escapeHTML(fileA.name)}
                vs
                ${escapeHTML(fileB.name)}
                · ${matched}/${algorithms.length} hashes equal
            </div>

            <div class="card">
                ${table(
                    ["Algorithm", "File A", "File B", "Result"],
                    rows
                )}
            </div>
        `;

        bindCopyButtons();
    };
}

/* =========================
   MONITOR
========================= */

function bindMonitor() {
    if ($("scanBtn")) {
        $("scanBtn").onclick = async () => {
            await scanFiles();
            render();
        };
    }

    if ($("autoScan")) {
        $("autoScan").onchange = (event) => {
            clearInterval(state.timer);

            if (event.target.checked) {
                state.timer = setInterval(async () => {
                    await scanFiles();

                    if (state.page === "mon") {
                        render();
                    }
                }, 5000);
            }
        };
    }

    document.querySelectorAll("[data-tamper]").forEach((button) => {
        button.onclick = () => {
            const file = state.files.find(
                (item) => item.id == button.dataset.tamper
            );

            if (!file) return;

            const bytes = new Uint8Array(file.buffer.slice(0));
            bytes[0] ^= 1;

            file.buffer = bytes.buffer;

            logActivity(
                `Simulated tampering on ${file.name}`
            );

            render();
        };
    });

    document.querySelectorAll("[data-restore]").forEach((button) => {
        button.onclick = () => {
            const file = state.files.find(
                (item) => item.id == button.dataset.restore
            );

            if (!file) return;

            file.buffer = file.original.slice(0);
            file.status = "safe";

            logActivity(
                `Restored ${file.name}`
            );

            render();
        };
    });
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

async function loadDatabaseData() {
    try {
        const [userRes, filesRes, historyRes] = await Promise.all([
            fetch("/api/user/me"),
            fetch("/api/user/files"),
            fetch("/api/user/history")
        ]);
        if (!userRes.ok) return;
        currentUser = await userRes.json();
        const files = filesRes.ok ? await filesRes.json() : [];
        const history = historyRes.ok ? await historyRes.json() : [];
        state.files = files.map(f => ({
            id: f.id, name: f.name, size: f.size || 0, hashes: f.hashes || {},
            status: f.status || "safe", filepath: f.filepath, upload_date: f.upload_date
        }));
        state.history = history.map((h, i) => ({
            id: h.id || i + 1, file: h.filename || h.file || String(h.file_id || ""),
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

function goTo(page) {
    clearInterval(state.timer);

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

loadDatabaseData().then(() => render());
document.addEventListener("DOMContentLoaded", async () => {
    try {
        const res = await fetch("/api/user/me");
        currentUser = res.ok ? await res.json() : { name: "User" };
    } catch (error) {
        console.error(error);
        currentUser = { name: "User" };
    }

    document.querySelectorAll(".nav-link").forEach((link) => {
        link.addEventListener("click", () => go(link.dataset.page));
    });

    render();
});