/* ==========================================================================
   Admin console  -  app.js
   Needs ../shared/common.js (hashing + helpers).

   Sections:
     1. State & demo data   (in the real Flask app this comes from MySQL)
     2. Small helpers
     3. Pages               - one function per sidebar item
     4. Actions             - what each button does
     5. Rendering           - draw page + connect buttons
   ========================================================================== */


/* ---------- 1. STATE & DEMO DATA ----------------------------------------- */

const hoursAgo = hours => new Date(Date.now() - hours * 3600 * 1000);
const daysAgo  = days  => hoursAgo(days * 24);

const state = {
    page: 'dash',
    settingsTab: 'password',   // password | login | activity | system
    search: '',                // text typed in a search box
    statusFilter: '',          // Manage Files status filter
    expandedFiles: {},         // file ids whose full hash list is open
    editingUserId: null,       // null = adding a new user
    formDraft: null,           // what the admin typed (kept if validation fails)
    formError: '',

    users: [
        { id: 1, name: 'Admin',          email: 'admin@gmail.com', phone: '9000000001', gender: 'M', dob: '1995-04-10', city: 'Ahmedabad', state: 'Gujarat', role: 'admin', status: 'active',   createdAt: daysAgo(60) },
        { id: 2, name: 'Kajal Patel',    email: 'kajal@gmail.com', phone: '9876543210', gender: 'F', dob: '2002-08-12', city: 'Ahmedabad', state: 'Gujarat', role: 'user',  status: 'active',   createdAt: daysAgo(30) },
        { id: 3, name: 'Yash Prajapati', email: 'yash@gmail.com',  phone: '9876500011', gender: 'M', dob: '2001-11-03', city: 'Surat',     state: 'Gujarat', role: 'user',  status: 'active',   createdAt: daysAgo(21) },
        { id: 4, name: 'Riya Shah',      email: 'riya@gmail.com',  phone: '9876500022', gender: 'F', dob: '2002-02-20', city: 'Vadodara',  state: 'Gujarat', role: 'user',  status: 'active',   createdAt: daysAgo(9) },
        { id: 5, name: 'Aman Verma',     email: 'aman@gmail.com',  phone: '9876500033', gender: 'M', dob: '2000-06-15', city: 'Rajkot',    state: 'Gujarat', role: 'user',  status: 'inactive', createdAt: daysAgo(4) }
    ],

    files: [
        { id: 1, userId: 2, name: 'report_final.pdf',  size: 482113,   algorithms: ['SHA-256', 'SHA-512'],            status: 'safe',     uploadedAt: hoursAgo(70) },
        { id: 2, userId: 2, name: 'thesis_draft.docx', size: 913402,   algorithms: ['SHA-256', 'SHA3-256'],           status: 'safe',     uploadedAt: hoursAgo(60) },
        { id: 3, userId: 3, name: 'budget_2026.xlsx',  size: 55120,    algorithms: ['SHA-1', 'SHA-256', 'SHA-384'],   status: 'modified', uploadedAt: hoursAgo(40) },
        { id: 4, userId: 3, name: 'backup.zip',        size: 20481234, algorithms: ['SHA-512', 'SHA3-512'],           status: 'safe',     uploadedAt: hoursAgo(30) },
        { id: 5, userId: 4, name: 'logo.png',          size: 18220,    algorithms: ['SHA-256'],                       status: 'tampered', uploadedAt: hoursAgo(20) },
        { id: 6, userId: 4, name: 'notes.txt',         size: 1204,     algorithms: ['SHA-256', 'SHA-224'],            status: 'safe',     uploadedAt: hoursAgo(8) },
        { id: 7, userId: 2, name: 'db_dump.sql',       size: 3321100,  algorithms: ['SHA-256', 'SHA-512', 'SHA3-256'], status: 'safe',    uploadedAt: hoursAgo(2) }
    ],

    integrityLogs: [
        { id: 1, fileId: 3, algorithm: 'SHA-256', status: 'modified', change: 'Content modified',      remarks: '1/3 algorithms matched', checkedAt: hoursAgo(14) },
        { id: 2, fileId: 5, algorithm: 'SHA-256', status: 'tampered', change: 'Partial hash mismatch', remarks: '1/2 algorithms matched', checkedAt: hoursAgo(9) },
        { id: 3, fileId: 1, algorithm: 'SHA-256', status: 'safe',     change: 'No change',             remarks: '2/2 algorithms matched', checkedAt: hoursAgo(6) },
        { id: 4, fileId: 6, algorithm: 'SHA-256', status: 'safe',     change: 'No change',             remarks: '2/2 algorithms matched', checkedAt: hoursAgo(3) }
    ],

    monitorEvents: [
        { id: 1, event: 'Modified', file: 'budget_2026.xlsx', alert: 'generated',     detectedAt: hoursAgo(14) },
        { id: 2, event: 'Modified', file: 'logo.png',         alert: 'generated',     detectedAt: hoursAgo(9) },
        { id: 3, event: 'Created',  file: 'db_dump.sql',      alert: 'not_generated', detectedAt: hoursAgo(2) }
    ],

    activities: [
        { id: 1, user: 'Kajal Patel',    text: 'Uploaded db_dump.sql',                    type: 'UPLOAD', time: hoursAgo(2) },
        { id: 2, user: 'Administrator',  text: 'Generated System Integrity Report',       type: 'REPORT', time: hoursAgo(4) },
        { id: 3, user: 'Yash Prajapati', text: 'Verified budget_2026.xlsx -> modified',   type: 'VERIFY', time: hoursAgo(14) },
        { id: 4, user: 'Riya Shah',      text: 'Verified logo.png -> tampered',           type: 'VERIFY', time: hoursAgo(9) },
        { id: 5, user: 'Administrator',  text: 'Added user Aman Verma',                   type: 'USER',   time: hoursAgo(96) }
    ],

    logins: [
        { id: 1, email: 'admin@gmail.com',  role: 'admin', status: 'success', ip: '127.0.0.1', time: hoursAgo(1) },
        { id: 2, email: 'kajal@gmail.com',  role: 'user',  status: 'success', ip: '127.0.0.1', time: hoursAgo(5) },
        { id: 3, email: 'unknown@mail.com', role: '—',     status: 'failed',  ip: '127.0.0.1', time: hoursAgo(7) },
        { id: 4, email: 'yash@gmail.com',   role: 'user',  status: 'success', ip: '127.0.0.1', time: hoursAgo(12) },
        { id: 5, email: 'riya@gmail.com',   role: 'user',  status: 'success', ip: '127.0.0.1', time: hoursAgo(26) }
    ],

    reports: [
        { id: 1, type: 'System Integrity Report', by: 'Administrator', total: 7, safe: 5, modified: 1, tampered: 1, createdAt: hoursAgo(30),  status: 'completed' },
        { id: 2, type: 'Security Audit Report',   by: 'Administrator', total: 7, safe: 6, modified: 1, tampered: 0, createdAt: hoursAgo(100), status: 'completed' }
    ]
};

// Demo only: give every seeded file real hashes (computed from its name).
state.files.forEach(file => file.hashes = {});     // empty until the hashes below are ready
(async () => {
    for (const file of state.files) {
        for (const algorithm of file.algorithms) {
            const hash = await hashBytes(new TextEncoder().encode('FIC:' + file.name), algorithm);
            if (hash) file.hashes[algorithm] = hash;
        }
    }
    render();
})();


/* ---------- 2. SMALL HELPERS -------------------------------------------- */

const findUser = id => state.users.find(user => user.id == id);
const findFile = id => state.files.find(file => file.id == id);
const userName = id => (findUser(id) || { name: '—' }).name;
const countFiles = status => state.files.filter(file => file.status === status).length;
const nextId = list => Math.max(0, ...list.map(item => item.id)) + 1;

const GENDER_LABELS = { M: 'Male', F: 'Female', O: 'Other' };

function logActivity(text, type) {
    state.activities.push({ id: nextId(state.activities), user: 'Administrator', text, type, time: new Date() });
}

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
                <span>${userName(userId)}</span><b>${count}</b>
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
                    ${user.id === 1 ? '' : `<button class="btn bs rd" data-delete-user="${user.id}">Delete</button>`}
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
                ${field('Phone',     textInput('formPhone', user.phone, 10))}
                ${field('Gender', `<select id="formGender">
                    ${option('', user.gender || '', '—')}
                    ${option('M', user.gender, 'Male')}
                    ${option('F', user.gender, 'Female')}
                    ${option('O', user.gender, 'Other')}
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
                    <td>${log.change}</td>
                    <td>${log.remarks}</td>
                    <td>${formatDateTime(log.checkedAt)}</td>
                </tr>`;
        });

        const eventRows = state.monitorEvents.slice().reverse().map(event => `
            <tr>
                <td>${event.id}</td>
                <td><b>${escapeHtml(event.file)}</b></td>
                <td>${event.event}</td>
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
                <td><b>${report.type}</b></td>
                <td>${report.by}</td>
                <td>${report.total}</td>
                <td>${report.safe}</td>
                <td>${report.modified}</td>
                <td>${report.tampered}</td>
                <td>${formatDateTime(report.createdAt)}</td>
                <td>${pill(report.status)}</td>
                <td><button class="btn bs rd" data-delete-report="${report.id}">Delete</button></td>
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
        const admin = state.users[0];
        const born = admin.dob ? new Date(admin.dob).toLocaleDateString([], { dateStyle: 'medium' }) : '—';

        return `
            ${pageTitle('Profile', 'Administrator account information.')}
            <div class="card" style="margin-top:0">
                <div class="ch">Account details</div>
                ${keyValueRows([
                    ['Full Name',       escapeHtml(admin.name)],
                    ['Email',           escapeHtml(admin.email)],
                    ['Role',            admin.role],
                    ['Phone',           admin.phone || '—'],
                    ['Gender',          GENDER_LABELS[admin.gender] || '—'],
                    ['Date of Birth',   born],
                    ['City',            admin.city || '—'],
                    ['State',           admin.state || '—'],
                    ['Account Status',  admin.status],
                    ['Account Created', formatDateTime(admin.createdAt)]
                ])}
            </div>
            <div class="card" >
                <div class="ch">Last login</div>
                ${keyValueRows([
                    ['Login Status',  'success'],
                    ['IP Address',    '127.0.0.1'],
                    ['Login Time',    formatDateTime(new Date())],
                    ['Logout Time',   'Active session']
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
                    <div><label class="fl">Current password</label><input type="text" id="currentPassword"></div>
                    <div><label class="fl">New password</label><input type="text" id="newPassword"></div>
                    <div id="passwordMessage" style="min-height:22px;margin:4px 0 10px"></div>
                    <button class="btn" id="changePassword">Update password</button>
                </div>`;
        } else if (state.settingsTab === 'login') {
            const rows = state.logins.map(login => `
                <tr>
                    <td>${login.id}</td><td>${login.email}</td><td>${login.role}</td>
                    <td>${pill(login.status)}</td><td>${login.ip}</td><td>${formatDateTime(login.time)}</td>
                </tr>`);
            content = `<div class="card" style="margin-top:0">${table(['ID', 'Email', 'Role', 'Status', 'IP Address', 'Login Time'], rows, '')}</div>`;
        } else if (state.settingsTab === 'activity') {
            const rows = state.activities.slice().reverse().map(activity => `
                <tr>
                    <td>${activity.id}</td><td>${activity.user}</td><td>${escapeHtml(activity.text)}</td>
                    <td>${algorithmChip(activity.type)}</td><td>${formatDateTime(activity.time)}</td>
                </tr>`);
            content = `<div class="card" style="margin-top:0">${table(['ID', 'User', 'Activity', 'Type', 'Time'], rows, '')}</div>`;
        } else {
            content = `
                <div class="card" style="margin-top:0">
                    ${keyValueRows([
                        ['Database',        'MySQL 8.0'],
                        ['Backend',         'Python 3.11 · Flask 3.0'],
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

/** Read the Add/Edit form, validate it, then save. */
function saveUser() {
    const values = {
        name:   byId('formName').value.trim(),
        email:  byId('formEmail').value.trim().toLowerCase(),
        phone:  byId('formPhone').value.trim(),
        gender: byId('formGender').value,
        dob:    byId('formDob').value,
        city:   byId('formCity').value.trim(),
        state:  byId('formState').value.trim(),
        role:   byId('formRole').value,
        status: byId('formStatus').value
    };
    state.formDraft = values;       // keep what was typed if we show an error

    const fail = message => { state.formError = message; render(); };

    if (!values.name || !/^\S+@\S+\.\S+$/.test(values.email)) return fail('Enter a name and a valid email.');
    if (state.users.some(user => user.email === values.email && user.id !== state.editingUserId)) return fail('Email already exists.');
    if (values.phone && !/^\d{10}$/.test(values.phone)) return fail('Phone must be 10 digits.');

    if (state.editingUserId !== null) {
        Object.assign(findUser(state.editingUserId), values);
        logActivity('Updated user ' + values.name, 'USER');
    } else {
        state.users.push({ id: nextId(state.users), ...values, createdAt: new Date() });
        logActivity('Added user ' + values.name, 'USER');
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

function deleteUser(id) {
    const user = findUser(id);
    state.users = state.users.filter(item => item.id !== user.id);
    state.files = state.files.filter(file => file.userId !== user.id);   // their files go too
    logActivity('Deleted user ' + user.name, 'USER');
    render();
}

function deleteFile(id) {
    const file = findFile(id);
    state.files = state.files.filter(item => item.id !== file.id);
    logActivity('Deleted file ' + file.name, 'DELETE');
    render();
}

function deleteReport(id) {
    state.reports = state.reports.filter(report => report.id != id);
    render();
}

/** Demo scan: log the current status of every file. */
function scanAllFiles() {
    state.files.forEach(file => state.integrityLogs.push({
        id: nextId(state.integrityLogs),
        fileId: file.id,
        algorithm: file.algorithms[0],
        status: file.status,
        change: file.status === 'safe' ? 'No change' : 'Hash mismatch',
        remarks: 'Admin scan',
        checkedAt: new Date()
    }));
    state.monitorEvents.push({
        id: nextId(state.monitorEvents), event: 'Scan', file: state.files.length + ' files',
        alert: 'not_generated', detectedAt: new Date()
    });
    render();
}

function generateReport() {
    state.reports.push({
        id: nextId(state.reports),
        type: byId('reportType').value,
        by: 'Administrator',
        total: state.files.length,
        safe: countFiles('safe'),
        modified: countFiles('modified'),
        tampered: countFiles('tampered'),
        createdAt: new Date(),
        status: 'completed'
    });
    render();
}

function copyReportsCsv() {
    const lines = state.reports.map(r => [r.id, r.type, r.total, r.safe, r.modified, r.tampered].join(','));
    const csv = 'id,type,total,safe,modified,tampered\n' + lines.join('\n');
    if (navigator.clipboard) navigator.clipboard.writeText(csv);
    byId('copyReports').textContent = 'Copied ✓';
}

function changePassword() {
    const message = byId('passwordMessage');
    const isValid = byId('currentPassword').value && byId('newPassword').value.length >= 6;
    message.style.color = isValid ? '#16a34a' : '#dc2626';
    message.textContent = isValid ? 'Password updated successfully.' : 'New password must be at least 6 characters.';
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
/* ---- start-up ---- */
document.querySelectorAll('[data-p]').forEach(link =>
    link.onclick = () => goTo(link.dataset.p)
);

byId('logout').onclick = () => {
    window.location.href = '/logout';
};

render();