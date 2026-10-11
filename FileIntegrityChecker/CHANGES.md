# Naye features (handwritten notes ke hisaab se)

User + Admin dono me: Hash Tool (steps), Compare Files (image/PDF/hash), Monitor (Tamper & Restore only), Reports (charts).
User: Upload (progress bar + preview, video/pdf/image), Verify (safe/modified % bar + Algo/Stored/Calculated/Result).

Naye files: compare_tools.py, static/js/hash_steps.js, static/js/fic_tools.js, static/css/fic_tools.css
Badle files: app.py, static/js/das.js, static/js/admin_app.js, templates/user/dashboard.html, templates/admin/dashboard.html, requirements.txt
Bug fixes: urlparse import (DATABASE_URL), /api/user/files ab db_user_id use karta hai.
Naya pip: Pillow, numpy, pypdf  ->  pip install -r requirements.txt

## AI assistant + cyber_faq
- ai_assistant.py: FAQ matching (rank_faq), REFERENCE_FAQ added to the AI prompt, FAQ answers used in Basic mode, user chats saved via chat_saver.
- app.py: ai_faq_loader() (cyber_faq, 5 min cache) and ai_chat_saver() (ai_chat_history); ai_assistant.init now receives both.
- database/cyber_faq_more.sql: 53 extra FAQ rows (INSERT IGNORE, safe to run twice).

## Browse questions (chat)
- ai_assistant.py: GET /api/ai/faq returns the cyber_faq table grouped by category.
- static/js/ai_chat.js + static/css/ai_chat.css: "Browse questions" button -> categories -> questions -> answer shown straight from the FAQ (no AI call, works even when the AI key/limit is unavailable).
