/* ==========================================================================
   ai_chat.js - floating "Cyber AI Assistant" chat (talks to /api/ai/chat)

   The API key is NEVER here - the browser only talks to your own Flask server.
   Include on any page:  <link ... ai_chat.css>  and  <script src=".../ai_chat.js"></script>
   ========================================================================== */
(function () {
    "use strict";

    const tag = document.currentScript || {};
    const ROLE = ((tag.dataset && tag.dataset.role) === "admin") ? "admin" : "user";
    const UID = (tag.dataset && tag.dataset.uid) || "0";
    /* separate history per role AND per account, so admin never sees a user's chat */
    const KEY = "fic-ai-chat-" + ROLE + "-" + UID;
    try { sessionStorage.removeItem("fic-ai-chat"); } catch (e) { /* ignore old shared key */ }
    const QUICK = ROLE === "admin"
        ? ["System summary?", "How many users and files are there?", "How do I handle tampered files?", "Where can I generate a report?"]
        : ["What is the status of my files?", "What is a hash?", "How is tampering detected?", "How do I verify a file?"];
    const TITLE = ROLE === "admin" ? "Admin AI Assistant" : "Cyber AI Assistant";
    const SUB = ROLE === "admin" ? "System, users, files, security" : "Ask about files, hashes, security";

    const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

    /* tiny, SAFE markdown: escape first, then **bold**, `code`, - lists, line breaks */
    function md(text) {
        const lines = esc(text).split("\n");
        let html = "", inList = false;
        for (const raw of lines) {
            let line = raw.replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*(.+?)\*/g, "<i>$1</i>");
            if (/^\s*[-•*]\s+/.test(line)) {
                if (!inList) { html += "<ul>"; inList = true; }
                html += "<li>" + line.replace(/^\s*[-•*]\s+/, "") + "</li>";
            } else {
                if (inList) { html += "</ul>"; inList = false; }
                html += line.trim() ? "<p>" + line + "</p>" : "";
            }
        }
        return html + (inList ? "</ul>" : "");
    }

    let history = [];
    try { history = JSON.parse(sessionStorage.getItem(KEY) || "[]"); } catch (e) { history = []; }
    const save = () => { try { sessionStorage.setItem(KEY, JSON.stringify(history.slice(-30))); } catch (e) { /* ignore */ } };

    const root = document.createElement("div");
    root.className = "aic";
    root.innerHTML = `
        <button class="aic-fab" type="button" aria-label="Open AI assistant" title="${TITLE}">🤖</button>
        <section class="aic-panel" hidden aria-label="${TITLE}">
            <header>
                <div class="aic-av">🤖</div>
                <div><b>${TITLE}</b><small id="aicMode">${SUB}</small></div>
                <button type="button" class="aic-x" id="aicClear" title="Clear chat">🗑</button>
                <button type="button" class="aic-x" id="aicClose" title="Close">✕</button>
            </header>
            <div class="aic-body" id="aicBody" aria-live="polite"></div>
            <div class="aic-faq" id="aicFaq" hidden></div>
            <div class="aic-quick" id="aicQuick"></div>
            <form class="aic-form" id="aicForm" autocomplete="off">
                <input id="aicInput" maxlength="800" placeholder="Type your question…" aria-label="Your question">
                <button type="submit" id="aicSend">Send</button>
            </form>
        </section>`;
    document.body.appendChild(root);

    const $ = (id) => root.querySelector("#" + id);
    const panel = root.querySelector(".aic-panel");
    const body = $("aicBody");
    let waiting = false;

    function bubble(who, html) {
        const node = document.createElement("div");
        node.className = "aic-m " + who;
        node.innerHTML = html;
        body.appendChild(node);
        body.scrollTop = body.scrollHeight;
        return node;
    }

    function welcome() {
        bubble("bot", md(ROLE === "admin"
            ? "Hello Admin! 👋 I am the **Admin AI Assistant**. Ask me about the system summary, users, files, tamper alerts and security."
            : "Hello! 👋 I am the **Cyber AI Assistant**. Ask me anything about your files, hashes, tamper detection or security."));
    }

    function restore() {
        body.innerHTML = "";
        if (!history.length) return welcome();
        history.forEach((m) => bubble(m.role === "user" ? "me" : "bot", m.role === "user" ? esc(m.text) : md(m.text)));
    }

    async function ask(text) {
        text = text.trim();
        if (!text || waiting) return;
        waiting = true;
        $("aicSend").disabled = true;
        $("aicInput").value = "";
        bubble("me", esc(text));
        const typing = bubble("bot", '<span class="aic-dots"><i></i><i></i><i></i></span>');

        try {
            const response = await fetch("/api/ai/chat", {
                method: "POST", credentials: "same-origin",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: text, history: history.slice(-8) })
            });
            const data = await response.json().catch(() => ({}));
            if (response.status === 401) { window.location.reload(); return; }
            if (!response.ok) throw new Error(data.error || "Something went wrong. Try again.");

            typing.innerHTML = md(data.answer);
            $("aicMode").textContent = data.source === "ai" ? "AI mode ✨" : "Basic mode (AI key not set / busy)";
            history.push({ role: "user", text }, { role: "assistant", text: data.answer });
            save();
        } catch (error) {
            typing.className = "aic-m bot err";
            typing.textContent = error.message;
        }
        body.scrollTop = body.scrollHeight;
        waiting = false;
        $("aicSend").disabled = false;
        $("aicInput").focus();
    }

    /* ---- Browse questions: categories -> questions -> answer (straight from the cyber_faq table) ---- */
    const BROWSE_OPEN = "📚 Browse questions", BROWSE_CLOSE = "✕ Hide questions";
    const faqBox = $("aicFaq");
    let faqData = null;

    async function loadFaq() {
        if (faqData) return faqData;
        const response = await fetch("/api/ai/faq", { credentials: "same-origin" });
        if (response.status === 401) { window.location.reload(); return null; }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || "Could not load questions. Try again.");
        faqData = data.categories || [];
        return faqData;
    }

    function showCategories() {
        faqBox.innerHTML = '<div class="aic-faq-grid">' + faqData.map((c, i) =>
            `<button type="button" data-cat="${i}"><span>${esc(c.name)}</span><small>${c.items.length}</small></button>`).join("") + "</div>";
    }

    function showQuestions(i) {
        const cat = faqData[i];
        faqBox.innerHTML = `<button type="button" class="aic-faq-back" data-back="1">← ${esc(cat.name)} (${cat.items.length})</button>` +
            '<div class="aic-faq-list">' + cat.items.map((it, n) =>
                `<button type="button" data-cat="${i}" data-q="${n}">${esc(it.q)}</button>`).join("") + "</div>";
    }

    function closeFaq() {
        faqBox.hidden = true;
        $("aicBrowse").textContent = BROWSE_OPEN;
    }

    function answerFromFaq(i, n) {
        const item = faqData[i].items[n];
        bubble("me", esc(item.q));
        bubble("bot", md(item.a));
        history.push({ role: "user", text: item.q }, { role: "assistant", text: item.a });
        save();
        $("aicMode").textContent = "Answered from FAQ";
        closeFaq();
    }

    async function toggleFaq() {
        if (!faqBox.hidden) return closeFaq();
        faqBox.hidden = false;
        $("aicBrowse").textContent = BROWSE_CLOSE;
        faqBox.innerHTML = '<div class="aic-faq-msg">Loading questions…</div>';
        try {
            await loadFaq();
            if (!faqData) return;
            if (faqData.length) showCategories();
            else faqBox.innerHTML = '<div class="aic-faq-msg">No questions yet.</div>';
        } catch (error) {
            faqBox.innerHTML = '<div class="aic-faq-msg">' + esc(error.message) + "</div>";
        }
    }

    faqBox.addEventListener("click", (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        if (btn.dataset.back) return showCategories();
        if (btn.dataset.q !== undefined) return answerFromFaq(+btn.dataset.cat, +btn.dataset.q);
        if (btn.dataset.cat !== undefined) showQuestions(+btn.dataset.cat);
    });

    $("aicQuick").innerHTML = `<button type="button" class="aic-browse" id="aicBrowse">${BROWSE_OPEN}</button>` +
        QUICK.map((q) => `<button type="button">${esc(q)}</button>`).join("");
    $("aicQuick").addEventListener("click", (e) => {
        if (e.target.id === "aicBrowse") return toggleFaq();
        if (e.target.tagName === "BUTTON") ask(e.target.textContent);
    });
    $("aicForm").addEventListener("submit", (e) => { e.preventDefault(); ask($("aicInput").value); });
    $("aicClear").onclick = () => { history = []; save(); restore(); };
    $("aicClose").onclick = () => { panel.hidden = true; };
    root.querySelector(".aic-fab").onclick = () => {
        panel.hidden = !panel.hidden;
        if (!panel.hidden) $("aicInput").focus();
    };

    restore();
})();
