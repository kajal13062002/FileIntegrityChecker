# Cyber AI Assistant – step by step

Sab kuch existing project me jud chuka hai (kuch purana nahi toota). Neeche batata hai kaunsi file me kya hai, aur chalane ke steps.

## A. Cyber AI Assistant (free-tier API)

### Files
| File | Kaam |
|---|---|
| `ai_assistant.py` (NAYI) | Backend: `/api/ai/chat`, free AI API call, rate limit, offline "basic mode" |
| `static/js/ai_chat.js` (NAYI) | Floating chat box (🤖 button) |
| `static/css/ai_chat.css` (NAYI) | Chat ka design |
| `app.py` (BADLI) | `import ai_assistant` + `ai_user_context()`, `ai_admin_context()`, `ai_assistant.init(...)` |
| `templates/user/dashboard.html`, `templates/admin/dashboard.html` (BADLI) | ai_chat.css / ai_chat.js ki 2 lines |
| `render.yaml` (BADLI) | env variables ke naam |

### Steps
1. **Free API key lo:** https://aistudio.google.com/apikey  (Google account se login → *Create API key*). Card nahi chahiye.
2. **Local PC par key set karo** (project folder ke terminal me):
   - Windows (CMD):  `set GEMINI_API_KEY=yahan_apni_key`
   - Windows (PowerShell):  `$env:GEMINI_API_KEY="yahan_apni_key"`
   - Mac/Linux:  `export GEMINI_API_KEY=yahan_apni_key`
3. `python app.py` chalao → user dashboard kholo → neeche-right 🤖 dabao.
   Header me **"AI mode ✨"** dikhe to AI chal raha hai. **"Basic mode"** dikhe to key set nahi hai / limit lagi hai (chat phir bhi chalta hai).
4. **Render par:** Dashboard → apna service → *Environment* → `GEMINI_API_KEY` = apni key → Save → redeploy.
   Key ko kabhi `app.py`, JavaScript ya GitHub me mat likho.

### Zaroori baatein (ek baar padh lo)
- **Model name badalta rehta hai.** Default `gemini-2.5-flash` hai. Agar error/basic mode aaye to AI Studio me dekho abhi kaunsa Flash model free hai, aur env me `GEMINI_MODEL=<naam>` set karo.
- **Free tier me aapka data Google training ke liye use kar sakta hai** aur free tier ki limits kam hoti hain (har minute/din ki). Isliye assistant ko sirf **chhota summary** jaata hai: files ki count, status, size, type. **Hash, file contents, email, password kabhi nahi jaate.** File ke asli naam bhi default me **nahi** jaate (`file #12 (pdf)` jaata hai). Naam bhejne ke liye `AI_SHARE_FILENAMES=1`.
- Free tier commercial use ke liye nahi hoti – college project / demo ke liye theek hai.
- Limits: har user ko 10 sawal/minute aur 150/din (`ai_assistant.py` me `REQUESTS_PER_MINUTE`, `REQUESTS_PER_DAY`).
- **Doosra free provider (OpenAI-compatible, jaise Groq):** `AI_PROVIDER=openai`, `AI_API_KEY=...`, `AI_BASE_URL=https://api.groq.com/openai/v1`, `AI_MODEL=<model naam>`.
- Assistant sirf jawab deta hai – file delete/restore jaise kaam **nahi** kar sakta (suraksha ke liye).
