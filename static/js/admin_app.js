/* ==========================================================================
   Admin console  -  app.js
   Needs ../shared/common.js (hashing + helpers).

   Sections:
     1. State & data        (loaded from MySQL through /api/admin/...)
     2. Small helpers
     3. Pages               - one function per sidebar item
     4. Actions             - what each button does
     5. Rendering           - draw page + connect buttons
   ========================================================================== */


/* ---------- 1. STATE & DATA ---------------------------------------------- */

const state = {
    page: 'dash',
    settingsTab: 'password',   // password | login | activity | system
    search: '',                // text typed in a search box
    statusFilter: '',          // Manage Files status filter
    expandedFiles: {},         // file ids whose full hash list is open
    editingUserId: null,       // null = adding a new user
    formDraft: null,           // what the admin typed (kept if validation fails)
    formError: '',
    loading: true,
    loadError: '',

    // everything below is filled from MySQL by loadData()
    users: [], files: [], integrityLogs: [], monitorEvents: [],
    activities: [], logins: [], reports: [],
    me: { id: 0, name: 'Admin', email: '', role: 'admin', status: 'active', lastLogin: null },
    system: { database: '-', backend: '-' }
};

/** Call the Flask API. Throws Error(message) when the server says no. */
async function api(method, url, body) {
    const options = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    let data = {};
    try { data = await response.json(); } catch (error) { /* no JSON body */ }
    if (response.status === 401) { window.location.href = '/admin'; throw new Error('Session expired'); }
    if (!response.ok) throw new Error(data.error || 'Request failed (' + response.status + ')');
    return data;
}

const toDate = value => value ? new Date(value) : null;

/** Fetch every table the console shows and turn date strings into Dates. */
async function loadData() {
    const data = await api('GET', '/api/admin/data');
    state.users         = data.users.map(user => ({ ...user, createdAt: toDate(user.createdAt) }));
    state.files         = data.files.map(file => ({ ...file, uploadedAt: toDate(file.uploadedAt), lastChecked: toDate(file.lastChecked) }));
    state.integrityLogs = data.integrityLogs.map(log => ({ ...log, checkedAt: toDate(log.checkedAt) }));
    state.monitorEvents = data.monitorEvents.map(event => ({ ...event, detectedAt: toDate(event.detectedAt) }));
    state.activities    = data.activities.map(activity => ({ ...activity, time: toDate(activity.time) }));
    state.logins        = data.logins.map(login => ({ ...login, time: toDate(login.time), logout: toDate(login.logout) }));
    state.reports       = data.reports.map(report => ({ ...report, createdAt: toDate(report.createdAt) }));
    state.me            = { ...data.me, createdAt: toDate(data.me.createdAt),
                            lastLogin: data.me.lastLogin
                                ? { ...data.me.lastLogin, time: toDate(data.me.lastLogin.time), logout: toDate(data.me.lastLogin.logout) }
                                : null };
    state.system        = data.system;
    state.loading = false;
    state.loadError = '';
}

/** Run a server action, reload the tables, redraw. Errors are shown in an alert. */
async function runAction(action) {
    try {
        await action();
        await loadData();
    } catch (error) {
        alert(error.message);
    }
    render();
}


/* ---------- 2. SMALL HELPERS -------------------------------------------- */

const findUser = id => state.users.find(user => user.id == id);
const findFile = id => state.files.find(file => file.id == id);
const userName = id => (findUser(id) || { name: '—' }).name;
const countFiles = status => state.files.filter(file => file.status === status).length;

const rolePill = role => `<span class="pill ${role === 'admin' ? 'adm' : 'usr'}">${role}</span>`;

const statCard = (colour, icon, label, value) =>
    `<div class="st ${colour}"><i>${icon}</i><span>${label}</span><b>${value}</b></div>`;

/** Hash cell in Manage Files: first hash, plus "+n more" to open the rest. */
function hashList(file) {
    const algorithms = Object.keys(file.hashes);
    if (algorithms.length === 0) return '<span class="mini">computing…</span>';

    const isOpen = state.expandedFiles[file.id];
    const visible = isOpen ? algorithms : algorithms.slice(0, 1);
    const lines = visible.map(algorithm => `
        <div style="margin:3px 0">
            ${algorithmChip(algorithm)}${hashBox(file.hashes[algorithm], isOpen ? undefined : 20)}
        </div>`).join('');

    const toggle = algorithms.length > 1
        ? `<button class="more" data-more="${file.id}">${isOpen ? 'Show less' : '+' + (algorithms.length - 1) + ' more'}</button>`
        : '';
    return lines + toggle;
}

/** Search box + optional dropdown shown above the Users / Files tables. */
const searchBar = (placeholder, extraHtml = '') => `
    <div class="bar2">
        <input type="text" id="searchBox" placeholder="${placeholder}" value="${escapeHtml(state.search)}">
        ${extraHtml}
    </div>`;


/* ---------- 3. PAGES ----------------------------------------------------- */

const pages = {

    dash() {
        const filesPerUser = {};
        state.files.forEach(file => filesPerUser[file.userId] = (filesPerUser[file.userId] || 0) + 1);
        const mostFiles = Math.max(1, ...Object.values(filesPerUser));

        const recentUsers = state.users.slice(-5).reverse().map(user => `
            <tr>
                <td>${user.id}</td>
                <td><b>${escapeHtml(user.name)}</b></td>
                <td>${escapeHtml(user.email)}</td>
                <td>${rolePill(user.role)}</td>
            </tr>`);

        const recentFiles = state.files.slice(-5).reverse().map(file => `
            <tr>
                <td>${file.id}</td>
                <td><b>${escapeHtml(file.name)}</b></td>
                <td>${hashList(file)}</td>
                <td>${pill(file.status)}</td>
            </tr>`);

        const perUserBars = Object.entries(filesPerUser).map(([userId, count]) => `
            <div style="display:flex;justify-content:space-between;font-size:13px">
                <span>${escapeHtml(userName(userId))}</span><b>${count}</b>
            </div>
            ${progressBar(100 * count / mostFiles)}`).join('');

        return `
            <div class="grid g4">
                ${statCard('a', '👥', 'Total Users',    state.users.filter(user => user.role === 'user').length)}
                ${statCard('b', '📁', 'Total Files',    state.files.length)}
                ${statCard('c', '⚠️', 'Modified Files', state.files.length - countFiles('safe'))}
                ${statCard('d', '📊', 'Reports',        state.reports.length)}
            </div>

            <div class="card">
                <div class="ch">Recent Users <button class="btn lt bs" data-go="users">View all</button></div>
                ${table(['ID', 'Name', 'Email', 'Role'], recentUsers, 'No Records Found')}
            </div>

            <div class="card">
                <div class="ch">Recent Uploaded Files <button class="btn lt bs" data-go="files">View all</button></div>
                ${table(['ID', 'File Name', 'Hash', 'Status'], recentFiles, 'No Files Uploaded')}
            </div>

            <div class="grid g2">
                <div class="card">
                    <div class="ch">Integrity status</div>
                    <div class="cb row" style="gap:24px">
                        ${donutChart([
                            ['Safe',     countFiles('safe'),     '#22c55e'],
                            ['Modified', countFiles('modified'), '#f59e0b'],
                            ['Tampered', countFiles('tampered'), '#ef4444']
                        ])}
                        <div style="color:var(--mut)">
                            ● <b style="color:#16a34a">Safe</b> ${countFiles('safe')}<br>
                            ● <b style="color:#d97706">Modified</b> ${countFiles('modified')}<br>
                            ● <b style="color:#dc2626">Tampered</b> ${countFiles('tampered')}
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="ch">Files per user</div>
                    <div class="cb">${perUserBars}</div>
                </div>
            </div>`;
    },

    users() {
        const query = state.search.toLowerCase();
        const visibleUsers = state.users.filter(user =>
            !query || (user.name + user.email).toLowerCase().includes(query));

        const rows = visibleUsers.map(user => `
            <tr>
                <td>${user.id}</td>
                <td><b>${escapeHtml(user.name)}</b></td>
                <td>${escapeHtml(user.email)}</td>
                <td>${escapeHtml(user.phone || '—')}</td>
                <td>${escapeHtml(user.city || '—')}</td>
                <td>${state.files.filter(file => file.userId === user.id).length}</td>
                <td>${rolePill(user.role)}</td>
                <td>${pill(user.status)}</td>
                <td>
                    <button class="btn bs ye" data-edit-user="${user.id}">Edit</button>
                    ${user.id === state.me.id ? '' : `<button class="btn bs rd" data-delete-user="${user.id}">Delete</button>`}
                </td>
            </tr>`);

        return `
            ${pageTitle('Manage Users', 'Add, edit or remove system users.', '<button class="btn" id="addUser">+ Add New User</button>')}
            ${searchBar('Search name or email…')}
            <div class="card nw" style="margin-top:0">
                ${table(['ID', 'Name', 'Email', 'Phone', 'City', 'Files', 'Role', 'Status', 'Action'], rows, 'No users found.')}
            </div>`;
    },

    /** Add / Edit user - one field under another (vertical form). */
    userForm() {
        const isEditing = state.editingUserId !== null;
        const user = state.formDraft || findUser(state.editingUserId) ||
                     { name: '', email: '', role: 'user', status: 'active' };

        const field = (label, inputHtml) => `<div><label class="fl">${label}</label>${inputHtml}</div>`;
        const option = (value, selected, text) =>
            `<option value="${value}" ${value === selected ? 'selected' : ''}>${text}</option>`;
        const textInput = (id, value, maxLength) =>
            `<input type="text" id="${id}" maxlength="${maxLength}" value="${escapeHtml(value || '')}">`;

        return `
            ${pageTitle(isEditing ? 'Edit User' : 'Add New User', 'Fill in the account details.')}
            <div class="card cb" style="margin-top:0;max-width:560px">
                ${field('Full name', textInput('formName',  user.name,  50))}
                ${field('Email',     textInput('formEmail', user.email, 50))}
                ${field(isEditing ? 'New password (leave empty to keep)' : 'Password',
                        '<input type="password" id="formPassword" maxlength="64" autocomplete="new-password">')}
                ${field('Phone',     textInput('formPhone', user.phone, 10))}
                ${field('Gender', `<select id="formGender">
                    ${option('', user.gender || '', '—')}
                    ${option('Male', user.gender, 'Male')}
                    ${option('Female', user.gender, 'Female')}
                    ${option('Other', user.gender, 'Other')}
                    ${option('Prefer not to say', user.gender, 'Prefer not to say')}
                </select>`)}
                ${field('Date of birth', `<input type="date" id="formDob" value="${user.dob || ''}">`)}
                ${field('City',  textInput('formCity',  user.city,  25))}
                ${field('State', textInput('formState', user.state, 25))}
                ${field('Role', `<select id="formRole">
                    ${option('user', user.role, 'user')}
                    ${option('admin', user.role, 'admin')}
                </select>`)}
                ${field('Status', `<select id="formStatus">
                    ${option('active', user.status, 'active')}
                    ${option('inactive', user.status, 'inactive')}
                </select>`)}

                <div style="color:#dc2626;min-height:20px;margin:2px 0 10px">${state.formError}</div>
                <div class="row">
                    <button class="btn" id="saveUser">Save</button>
                    <button class="btn lt" data-go="users">Cancel</button>
                </div>
            </div>`;
    },

    files() {
        const query = state.search.toLowerCase();
        const visibleFiles = state.files.filter(file =>
            (!query || (file.name + userName(file.userId)).toLowerCase().includes(query)) &&
            (!state.statusFilter || file.status === state.statusFilter));

        const statusOptions = ['safe', 'modified', 'tampered']
            .map(status => `<option ${state.statusFilter === status ? 'selected' : ''}>${status}</option>`).join('');

        const rows = visibleFiles.map(file => `
            <tr>
                <td>${file.id}</td>
                <td>${escapeHtml(userName(file.userId))}</td>
                <td><b>${escapeHtml(file.name)}</b><div class="mini">${formatSize(file.size)}</div></td>
                <td style="min-width:260px">${hashList(file)}</td>
                <td>${pill(file.status)}</td>
                <td>${formatDateTime(file.uploadedAt)}</td>
                <td><button class="btn bs rd" data-delete-file="${file.id}">Delete</button></td>
            </tr>`);

        return `
            ${pageTitle('Manage Files', 'All registered files with their SHA-family hashes.')}
            ${searchBar('Search file or user…',
                `<select id="statusFilter"><option value="">All status</option>${statusOptions}</select>`)}
            <div class="card" style="margin-top:0">
                ${table(['ID', 'User', 'File Name', 'Hashes', 'Status', 'Upload Date', 'Action'], rows, 'No files found.')}
            </div>`;
    },

    logs() {
        const logRows = state.integrityLogs.slice().reverse().map(log => {
            const file = findFile(log.fileId);
            return `
                <tr>
                    <td>${log.id}</td>
                    <td><b>${escapeHtml(file ? file.name : '—')}</b></td>
                    <td>${escapeHtml(file ? userName(file.userId) : '—')}</td>
                    <td>${algorithmChip(log.algorithm)}</td>
                    <td>${pill(log.status)}</td>
                    <td>${escapeHtml(log.change)}</td>
                    <td>${escapeHtml(log.remarks)}</td>
                    <td>${formatDateTime(log.checkedAt)}</td>
                </tr>`;
        });

        const eventRows = state.monitorEvents.slice().reverse().map(event => `
            <tr>
                <td>${event.id}</td>
                <td><b>${escapeHtml(event.file)}</b></td>
                <td>${escapeHtml(event.event)}</td>
                <td>${pill(event.alert)}</td>
                <td>${formatDateTime(event.detectedAt)}</td>
            </tr>`);

        return `
            ${pageTitle('Integrity Logs', 'Results of integrity checks and monitoring events.',
                        '<button class="btn gn" id="scanAll">Scan all files</button>')}
            <div class="card" style="margin-top:0">
                ${table(['ID', 'File', 'User', 'Algorithm', 'Status', 'Change', 'Remarks', 'Checked'], logRows, 'No integrity checks yet.')}
            </div>
            <div class="card">
                <div class="ch">Monitoring events</div>
                ${table(['ID', 'File', 'Event', 'Alert', 'Detected'], eventRows, 'No events.')}
            </div>`;
    },

    reports() {
        const rows = state.reports.slice().reverse().map(report => `
            <tr>
                <td>${report.id}</td>
                <td><b>${escapeHtml(report.type)}</b></td>
                <td>${escapeHtml(report.by)}</td>
                <td>${report.total}</td>
                <td>${report.safe}</td>
                <td>${report.modified}</td>
                <td>${report.tampered}</td>
                <td>${formatDateTime(report.createdAt)}</td>
                <td>${pill(report.status)}</td>
                <td>
                    <a class="btn bs lt" href="/api/admin/reports/${report.id}/download">Download</a>
                    <button class="btn bs rd" data-delete-report="${report.id}">Delete</button>
                </td>
            </tr>`);

        const actions = `
            <select id="reportType" style="width:auto;margin:0 8px 0 0;display:inline-block">
                <option>System Integrity Report</option>
                <option>Security Audit Report</option>
            </select>
            <button class="btn" id="generateReport">Generate</button>
            <button class="btn lt" id="copyReports">Copy CSV</button>`;

        return `
            ${pageTitle('Reports', 'System-wide integrity reports.', actions)}
            <div class="card" style="margin-top:0">
                ${table(['ID', 'Type', 'Generated By', 'Total', 'Safe', 'Modified', 'Tampered', 'Generated', 'Status', 'Action'], rows, 'No reports yet.')}
            </div>`;
    },

    /** Admin profile - vertical rows (same style as the user Profile). */
    profile() {
        const admin = state.me;
        const born = admin.dob ? new Date(admin.dob).toLocaleDateString([], { dateStyle: 'medium' }) : '—';
        const last = admin.lastLogin;

        return `
            ${pageTitle('Profile', 'Administrator account information.')}
            <div class="card" style="margin-top:0">
                <div class="ch">Account details</div>
                ${keyValueRows([
                    ['Full Name',       escapeHtml(admin.name)],
                    ['Email',           escapeHtml(admin.email)],
                    ['Role',            admin.role],
                    ['Phone',           escapeHtml(admin.phone || '—')],
                    ['Gender',          escapeHtml(admin.gender || '—')],
                    ['Date of Birth',   born],
                    ['City',            escapeHtml(admin.city || '—')],
                    ['State',           escapeHtml(admin.state || '—')],
                    ['Account Status',  admin.status],
                    ['Account Created', formatDateTime(admin.createdAt)]
                ])}
            </div>
            <div class="card" >
                <div class="ch">Last login</div>
                ${keyValueRows([
                    ['Login Status',  last ? last.status : '—'],
                    ['IP Address',    last ? escapeHtml(last.ip || '—') : '—'],
                    ['Login Time',    last ? formatDateTime(last.time) : '—'],
                    ['Logout Time',   last && last.logout ? formatDateTime(last.logout) : 'Active session']
                ])}
            </div>`;
    },

    settings() {
        const tabs = [['password', 'Password'], ['login', 'Login History'], ['activity', 'System Activity'], ['system', 'System Info']];
        let content = '';

        if (state.settingsTab === 'password') {
            content = `
                <div class="card cb" style="margin-top:0;max-width:520px">
                    <h4 style="margin-bottom:14px">Change password</h4>
                    <div><label class="fl">Current password</label><input type="password" id="currentPassword" autocomplete="current-password"></div>
                    <div><label class="fl">New password</label><input type="password" id="newPassword" autocomplete="new-password"></div>
                    <div id="passwordMessage" style="min-height:22px;margin:4px 0 10px"></div>
                    <button class="btn" id="changePassword">Update password</button>
                </div>`;
        } else if (state.settingsTab === 'login') {
            const rows = state.logins.map(login => `
                <tr>
                    <td>${login.id}</td><td>${escapeHtml(login.email)}</td><td>${login.role}</td>
                    <td>${pill(login.status)}</td><td>${escapeHtml(login.ip)}</td><td>${formatDateTime(login.time)}</td>
                    <td>${login.logout ? formatDateTime(login.logout) : '—'}</td>
                </tr>`);
            content = `<div class="card" style="margin-top:0">${table(['ID', 'Email', 'Role', 'Status', 'IP Address', 'Login Time', 'Logout Time'], rows, 'No logins recorded yet.')}</div>`;
        } else if (state.settingsTab === 'activity') {
            const rows = state.activities.slice().reverse().map(activity => `
                <tr>
                    <td>${activity.id}</td><td>${escapeHtml(activity.user)}</td><td>${escapeHtml(activity.text)}</td>
                    <td>${algorithmChip(activity.type)}</td><td>${formatDateTime(activity.time)}</td>
                </tr>`);
            content = `<div class="card" style="margin-top:0">${table(['ID', 'User', 'Activity', 'Type', 'Time'], rows, 'No activity recorded yet.')}</div>`;
        } else {
            content = `
                <div class="card" style="margin-top:0">
                    ${keyValueRows([
                        ['Database',        escapeHtml(state.system.database)],
                        ['Backend',         escapeHtml(state.system.backend)],
                        ['Frontend',        'HTML5 · CSS3 · Bootstrap 5 · JavaScript'],
                        ['Hash algorithms', ALGORITHMS.length + ' (SHA-1, SHA-2, SHA-3 family)'],
                        ['Version',         '1.0.0']
                    ])}
                </div>`;
        }

        const tabButtons = tabs.map(([key, label]) =>
            `<button data-tab="${key}" class="${state.settingsTab === key ? 'on' : ''}">${label}</button>`).join('');

        return `
            ${pageTitle('Settings', 'Security, login history and system information.')}
            <div class="tabs">${tabButtons}</div>
            ${content}`;
    }
};


/* ---------- 4. ACTIONS --------------------------------------------------- */

function goTo(page) {
    state.page = page;
    state.search = '';
    state.statusFilter = '';
    state.formDraft = null;
    state.formError = '';
    render();
}

function showUserForm(userId) {
    state.editingUserId = userId;     // null means "add new"
    state.formDraft = null;
    state.formError = '';
    state.page = 'userForm';
    render();
}

/** Read the Add/Edit form, validate it, then save to MySQL. */
async function saveUser() {
    const values = {
        name:     byId('formName').value.trim(),
        email:    byId('formEmail').value.trim().toLowerCase(),
        password: byId('formPassword').value,
        phone:    byId('formPhone').value.trim(),
        gender:   byId('formGender').value,
        dob:      byId('formDob').value,
        city:     byId('formCity').value.trim(),
        state:    byId('formState').value.trim(),
        role:     byId('formRole').value,
        status:   byId('formStatus').value
    };
    state.formDraft = { ...values, password: '' };   // keep what was typed if we show an error

    const fail = message => { state.formError = message; render(); };
    const isEditing = state.editingUserId !== null;

    if (!values.name || !/^\S+@\S+\.\S+$/.test(values.email)) return fail('Enter a name and a valid email.');
    if (state.users.some(user => user.email.toLowerCase() === values.email && user.id !== state.editingUserId)) return fail('Email already exists.');
    if (!isEditing && values.password.length < 6) return fail('Password must be at least 6 characters.');
    if (isEditing && values.password && values.password.length < 6) return fail('Password must be at least 6 characters.');
    if (values.phone && !/^\d{10}$/.test(values.phone)) return fail('Phone must be 10 digits.');
    if (values.role === 'user' && !(values.phone && values.gender && values.dob && values.city && values.state))
        return fail('Phone, gender, date of birth, city and state are required for user accounts.');

    try {
        if (isEditing) await api('PUT', '/api/admin/users/' + state.editingUserId, values);
        else           await api('POST', '/api/admin/users', values);
        await loadData();
    } catch (error) {
        return fail(error.message);
    }
    goTo('users');
}

/** Delete button asks "Sure?" first; the second click really deletes. */
function confirmThenDelete(button, deleteFunction) {
    button.onclick = () => {
        if (button.dataset.armed) { deleteFunction(); return; }
        button.dataset.armed = 'yes';
        button.textContent = 'Sure?';
        setTimeout(() => {
            if (button.isConnected) { delete button.dataset.armed; button.textContent = 'Delete'; }
        }, 2500);
    };
}

const deleteUser   = id => runAction(() => api('DELETE', '/api/admin/users/' + id));
const deleteFile   = id => runAction(() => api('DELETE', '/api/admin/files/' + id));
const deleteReport = id => runAction(() => api('DELETE', '/api/admin/reports/' + id));

/** Server re-hashes every stored file and compares it with the saved hashes. */
async function scanAllFiles() {
    const button = byId('scanAll');
    if (button) { button.disabled = true; button.textContent = 'Scanning…'; }
    await runAction(async () => {
        const result = await api('POST', '/api/admin/scan');
        alert('Scanned ' + result.scanned + ' files: ' + result.safe + ' safe, ' +
              result.modified + ' modified, ' + result.tampered + ' tampered.');
    });
}

const generateReport = () => runAction(() => api('POST', '/api/admin/reports', { type: byId('reportType').value }));

function copyReportsCsv() {
    const lines = state.reports.map(r => [r.id, r.type, r.total, r.safe, r.modified, r.tampered].join(','));
    const csv = 'id,type,total,safe,modified,tampered\n' + lines.join('\n');
    if (navigator.clipboard) navigator.clipboard.writeText(csv);
    byId('copyReports').textContent = 'Copied ✓';
}

async function changePassword() {
    const message = byId('passwordMessage');
    const show = (text, ok) => { message.style.color = ok ? '#16a34a' : '#dc2626'; message.textContent = text; };

    if (byId('newPassword').value.length < 6) return show('New password must be at least 6 characters.', false);
    try {
        await api('POST', '/api/admin/password', { current: byId('currentPassword').value, new: byId('newPassword').value });
        byId('currentPassword').value = '';
        byId('newPassword').value = '';
        show('Password updated successfully.', true);
    } catch (error) {
        show(error.message, false);
    }
}


/* ---------- 5. RENDERING & NAVIGATION ------------------------------------ */

function onClick(id, handler) {
    const element = byId(id);
    if (element) element.onclick = handler;
}

function connectPageButtons() {
    document.querySelectorAll('[data-go]').forEach(button => button.onclick = () => goTo(button.dataset.go));
    document.querySelectorAll('[data-tab]').forEach(button => button.onclick = () => { state.settingsTab = button.dataset.tab; render(); });
    document.querySelectorAll('[data-edit-user]').forEach(button => button.onclick = () => showUserForm(+button.dataset.editUser));
    document.querySelectorAll('[data-more]').forEach(button => button.onclick = () => {
        state.expandedFiles[button.dataset.more] = !state.expandedFiles[button.dataset.more];
        render();
    });
    document.querySelectorAll('[data-delete-user]').forEach(button => confirmThenDelete(button, () => deleteUser(button.dataset.deleteUser)));
    document.querySelectorAll('[data-delete-file]').forEach(button => confirmThenDelete(button, () => deleteFile(button.dataset.deleteFile)));
    document.querySelectorAll('[data-delete-report]').forEach(button => confirmThenDelete(button, () => deleteReport(button.dataset.deleteReport)));

    onClick('addUser',        () => showUserForm(null));
    onClick('saveUser',       saveUser);
    onClick('scanAll',        scanAllFiles);
    onClick('generateReport', generateReport);
    onClick('copyReports',    copyReportsCsv);
    onClick('changePassword', changePassword);

    const searchBox = byId('searchBox');
    if (searchBox) {
        searchBox.oninput = () => {
            state.search = searchBox.value;
            const caret = searchBox.selectionStart;
            render();                                   // redraw the table...
            byId('searchBox').focus();                  // ...and keep typing where we were
            byId('searchBox').setSelectionRange(caret, caret);
        };
    }
    const statusFilter = byId('statusFilter');
    if (statusFilter) statusFilter.onchange = () => { state.statusFilter = statusFilter.value; render(); };
}

function render() {
    if (state.loading || state.loadError) {
        byId('view').innerHTML = `<div class="card cb">${state.loadError
            ? 'Could not load data: ' + escapeHtml(state.loadError)
            : 'Loading…'}</div>`;
        return;
    }
    const activeLink = state.page === 'userForm' ? 'users' : state.page;
    document.querySelectorAll('[data-p]').forEach(link =>
        link.classList.toggle('on', link.dataset.p === activeLink));

    byId('view').innerHTML = pages[state.page]();
    connectPageButtons();
}

/* ---- theme: remember choice, otherwise follow the device ---- */
const root = document.documentElement;
let savedTheme = null;
try { savedTheme = localStorage.getItem('fic-theme'); } catch (error) { /* storage blocked */ }
root.dataset.theme = savedTheme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

byId('themeToggle').onclick = () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('fic-theme', root.dataset.theme); } catch (error) { /* ignore */ }
};

/* ---- start-up ---- */
document.querySelectorAll('[data-p]').forEach(link =>
    link.onclick = () => goTo(link.dataset.p)
);

byId('logout').onclick = () => {
    window.location.href = '/logout';
};

render();                                   // shows "Loading…"
loadData()
    .then(render)
    .catch(error => { state.loadError = error.message; render(); });
