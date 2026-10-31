"""Supplier Security Questionnaire App (PoC)
Run:  pip install fastapi uvicorn jinja2 python-multipart
      uvicorn app:app --reload      -> http://127.0.0.1:8000
Logins: procurement@demo.com / security@demo.com, password demo1234
Vendor links are printed in the console at first start (and shown to Procurement on onboarding).
"""
import os, sqlite3, secrets, hashlib, csv, io, asyncio, datetime as dt
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse
from jinja2 import Environment, DictLoader, select_autoescape

DB, UP, SESS = "questionnaire.db", "uploads", {}
BASE = os.environ.get("BASE_URL", "http://127.0.0.1:8000")
MAX_BYTES, EXTS = 10 * 1024 * 1024, (".pdf", ".docx")
QUESTIONS = [  # (section, id, text, critical)
    ("Access Control", "AC1", "Is multi-factor authentication enforced for all staff?", False),
    ("Access Control", "AC2", "Are user access rights reviewed at least quarterly?", False),
    ("Access Control", "AC3", "Is access revoked within 24h of staff leaving?", False),
    ("Data Encryption", "DE1", "Is customer data encrypted at rest?", True),
    ("Data Encryption", "DE2", "Is data encrypted in transit (TLS 1.2+)?", True),
    ("Data Encryption", "DE3", "Are encryption keys managed in a KMS/HSM?", False),
    ("Incident Response", "IR1", "Is there a documented incident response plan?", False),
    ("Incident Response", "IR2", "Do you notify customers of breaches within 72 hours?", False),
    ("Incident Response", "IR3", "Is the plan tested at least annually?", False),
]
now = lambda: dt.datetime.utcnow().isoformat(sep=" ", timespec="seconds")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c

def hp(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

def send_email(to, subject, body):  # PoC: write to outbox.log instead of SMTP
    line = f"[{now()}] TO:{to} | {subject} | {body}\n"
    open("outbox.log", "a").write(line); print("EMAIL", line.strip())

def audit(c, vid, user, action, note=""):
    c.execute("INSERT INTO audit_log(vendor_id,user,action,note,at) VALUES(?,?,?,?,?)", (vid, user, action, note, now()))
    c.execute("UPDATE vendors SET last_updated_by=? WHERE id=?", (f"{user} @ {now()}: {action}", vid))

SCHEMA = """
CREATE TABLE IF NOT EXISTS vendors(id INTEGER PRIMARY KEY AUTOINCREMENT, company_name TEXT NOT NULL, contact_email TEXT NOT NULL,
 contact_name TEXT NOT NULL, token TEXT UNIQUE, overall_risk_score REAL DEFAULT 0.0, risk_tier TEXT DEFAULT 'Low',
 status TEXT DEFAULT 'Draft', last_submitted_at DATETIME, last_updated_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, hashed_password TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN('procurement','security','vendor')), vendor_id INTEGER REFERENCES vendors(id), created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS questionnaire_responses(id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER NOT NULL REFERENCES vendors(id),
 section_name TEXT NOT NULL, question_id TEXT NOT NULL, question_text TEXT NOT NULL, answer_bool BOOLEAN DEFAULT 0, evidence_text TEXT,
 is_critical BOOLEAN DEFAULT 0, points_earned INTEGER DEFAULT 0, max_points INTEGER DEFAULT 10);
CREATE TABLE IF NOT EXISTS document_uploads(id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER NOT NULL REFERENCES vendors(id),
 file_name TEXT NOT NULL, file_path TEXT NOT NULL, uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id INTEGER NOT NULL REFERENCES vendors(id),
 user TEXT, action TEXT, note TEXT, at TEXT);
"""

def tier_for(score, crit_fail):
    return "High" if score < 70 or crit_fail else ("Medium" if score < 85 else "Low")

def save_responses(c, vid, answers, evidence=None):
    c.execute("DELETE FROM questionnaire_responses WHERE vendor_id=?", (vid,))
    for s, q, t, crit in QUESTIONS:
        yes = answers.get(q, False)
        c.execute("INSERT INTO questionnaire_responses(vendor_id,section_name,question_id,question_text,answer_bool,evidence_text,is_critical,points_earned) VALUES(?,?,?,?,?,?,?,?)",
                  (vid, s, q, t, yes, (evidence or {}).get(q, ""), crit, 10 if yes else 0))

def calc(c, vid):
    r = c.execute("SELECT SUM(points_earned) p, SUM(max_points) m FROM questionnaire_responses WHERE vendor_id=?", (vid,)).fetchone()
    score = round((r["p"] or 0) / r["m"] * 100, 1) if r["m"] else 0.0
    crit = c.execute("SELECT COUNT(*) n FROM questionnaire_responses WHERE vendor_id=? AND is_critical=1 AND answer_bool=0", (vid,)).fetchone()["n"]
    return score, tier_for(score, crit > 0)

def seed():
    c = db(); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        for e, r in (("procurement@demo.com", "procurement"), ("security@demo.com", "security")):
            c.execute("INSERT INTO users(email,hashed_password,role) VALUES(?,?,?)", (e, hp("demo1234"), r))
        ago = lambda d: (dt.datetime.utcnow() - dt.timedelta(days=d)).isoformat(sep=" ", timespec="seconds")
        rows = [("Acme Corp", "Approved", 92, "Low", [], ago(30)),
                ("CloudTech Solutions", "In Security Review", 64, "High", ["AC1", "AC2", "IR1"], ago(5)),
                ("DataPipe Systems", "In Security Review", 85, "High", ["DE1"], ago(3)),
                ("LogiFlow Logistics", "Submitted", 78, "Medium", ["AC3", "IR3"], ago(2)),
                ("Omega Vendors", "Draft", 0, "Low", None, None)]
        for name, st, sc, tr, fails, sub in rows:
            slug = name.split()[0].lower()
            cur = c.execute("INSERT INTO vendors(company_name,contact_email,contact_name,token,overall_risk_score,risk_tier,status,last_submitted_at,last_updated_by) VALUES(?,?,?,?,?,?,?,?,'seed')",
                            (name, f"security@{slug}.example", f"{name.split()[0]} Contact", secrets.token_urlsafe(24), sc, tr, st, sub))
            if fails is not None:  # seeded scores are fixed to match the spec; responses show the failed controls
                save_responses(c, cur.lastrowid, {q: q not in fails for _, q, _, _ in QUESTIONS})
        for v in c.execute("SELECT company_name,token FROM vendors"): print(f"{v['company_name']}: {BASE}/vendor/{v['token']}")
    c.commit(); c.close()

def run_renewals():
    c, n = db(), 0
    for v in c.execute("SELECT * FROM vendors WHERE status IN('Approved','Submitted') AND last_submitted_at IS NOT NULL").fetchall():
        if (dt.datetime.utcnow() - dt.datetime.fromisoformat(v["last_submitted_at"])).days > 365:
            c.execute("UPDATE vendors SET status='Renewal Due' WHERE id=?", (v["id"],)); audit(c, v["id"], "system", "Annual renewal due")
            send_email(v["contact_email"], "Annual security re-assessment due", f"Please re-submit your questionnaire: {BASE}/vendor/{v['token']}"); n += 1
    c.commit(); c.close(); return n

@asynccontextmanager
async def lifespan(app):
    os.makedirs(UP, exist_ok=True); seed(); run_renewals()
    async def loop():
        while True: await asyncio.sleep(86400); run_renewals()  # daily cron-style job
    t = asyncio.create_task(loop()); yield; t.cancel()

app = FastAPI(lifespan=lifespan)

# ---------- auth / RBAC (enforced server-side) ----------
def user_of(req):
    return SESS.get(req.cookies.get("sid"))

def need(req, *roles):
    u = user_of(req)
    if not u: raise HTTPException(303, headers={"Location": "/login"})
    if u["role"] not in roles: raise HTTPException(403, "Your role cannot do this.")
    return u

def page(req, name, **ctx):
    return HTMLResponse(env.get_template(name).render(user=user_of(req), **ctx))

def go(url): return RedirectResponse(url, 303)

def get_vendor(c, vid):
    v = c.execute("SELECT * FROM vendors WHERE id=?", (vid,)).fetchone()
    if not v: raise HTTPException(404, "Vendor not found")
    return v

@app.get("/")
def home(req: Request):
    u = user_of(req); return go("/" + u["role"] if u else "/login")

@app.get("/login")
def login_form(req: Request): return page(req, "login.html", error=None)

@app.post("/login")
def login(req: Request, email: str = Form(...), password: str = Form(...)):
    c = db(); u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); c.close()
    if not u or u["hashed_password"] != hp(password, u["hashed_password"].split("$")[0]):
        return page(req, "login.html", error="Email or password is incorrect.")
    sid = secrets.token_urlsafe(32); SESS[sid] = {"id": u["id"], "email": u["email"], "role": u["role"]}
    r = go("/" + u["role"]); r.set_cookie("sid", sid, httponly=True, samesite="lax"); return r

@app.get("/logout")
def logout(req: Request):
    SESS.pop(req.cookies.get("sid"), None); r = go("/login"); r.delete_cookie("sid"); return r

# ---------- procurement ----------
@app.get("/procurement")
def procurement(req: Request, new: str = ""):
    need(req, "procurement"); c = db()
    vs = c.execute("SELECT * FROM vendors ORDER BY id").fetchall()
    stats = {"Total": len(vs), "Awaiting vendor": sum(v["status"] in ("Draft", "Invited") for v in vs),
             "In security review": sum(v["status"] == "In Security Review" for v in vs),
             "Approved": sum(v["status"] == "Approved" for v in vs), "Renewal due": sum(v["status"] == "Renewal Due" for v in vs)}
    link = f"{BASE}/vendor/{new}" if new else ""
    return page(req, "procurement.html", vendors=vs, stats=stats, link=link)

@app.post("/procurement/onboard")  # event-triggered automation: profile + token link + invite email
def onboard(req: Request, company_name: str = Form(...), contact_name: str = Form(...), contact_email: str = Form(...)):
    u = need(req, "procurement"); c = db(); tok = secrets.token_urlsafe(24)
    vid = c.execute("INSERT INTO vendors(company_name,contact_email,contact_name,token,status) VALUES(?,?,?,?, 'Invited')",
                    (company_name.strip(), contact_email.strip(), contact_name.strip(), tok)).lastrowid
    audit(c, vid, u["email"], "Vendor onboarded and invited")
    send_email(contact_email, f"Security questionnaire for {company_name}", f"Hi {contact_name}, please complete your questionnaire: {BASE}/vendor/{tok}")
    c.commit(); return go(f"/procurement?new={tok}")

@app.post("/run-renewals")
def renewals(req: Request):
    need(req, "procurement", "security"); run_renewals(); return go("/" + user_of(req)["role"])

# ---------- shared internal views ----------
@app.get("/security")
def security(req: Request):
    need(req, "security"); c = db()
    q = c.execute("SELECT * FROM vendors WHERE status='In Security Review' ORDER BY overall_risk_score").fetchall()
    fails = {v["id"]: c.execute("SELECT question_text,is_critical FROM questionnaire_responses WHERE vendor_id=? AND answer_bool=0", (v["id"],)).fetchall() for v in q}
    others = c.execute("SELECT * FROM vendors WHERE status!='In Security Review' ORDER BY id").fetchall()
    return page(req, "security.html", queue=q, fails=fails, others=others)

@app.get("/vendors/{vid}")
def detail(req: Request, vid: int):
    need(req, "procurement", "security"); c = db(); v = get_vendor(c, vid)
    return page(req, "detail.html", v=v,
                resp=c.execute("SELECT * FROM questionnaire_responses WHERE vendor_id=?", (vid,)).fetchall(),
                docs=c.execute("SELECT * FROM document_uploads WHERE vendor_id=?", (vid,)).fetchall(),
                log=c.execute("SELECT * FROM audit_log WHERE vendor_id=? ORDER BY id DESC", (vid,)).fetchall())

@app.get("/vendors/{vid}/report")  # printable summary: use Print > Save as PDF
def report(req: Request, vid: int):
    need(req, "procurement", "security"); c = db(); v = get_vendor(c, vid)
    return page(req, "report.html", v=v, fails=c.execute("SELECT * FROM questionnaire_responses WHERE vendor_id=? AND answer_bool=0", (vid,)).fetchall(),
                log=c.execute("SELECT * FROM audit_log WHERE vendor_id=? ORDER BY id", (vid,)).fetchall(), today=now())

@app.get("/export.csv")
def export(req: Request):
    need(req, "procurement", "security"); c = db(); out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Vendor", "Contact email", "Score %", "Risk tier", "Status"])
    for v in c.execute("SELECT * FROM vendors"): w.writerow([v["company_name"], v["contact_email"], v["overall_risk_score"], v["risk_tier"], v["status"]])
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=vendors.csv"})

@app.get("/files/{did}")
def file(req: Request, did: int):
    need(req, "procurement", "security"); c = db(); d = c.execute("SELECT * FROM document_uploads WHERE id=?", (did,)).fetchone()
    if not d: raise HTTPException(404)
    return FileResponse(d["file_path"], filename=d["file_name"])

# ---------- decisions ----------
@app.post("/vendors/{vid}/decision")
def decide(req: Request, vid: int, action: str = Form(...), note: str = Form("")):
    u = need(req, "procurement", "security"); c = db(); v = get_vendor(c, vid)
    if action not in ("Approved", "Rejected"): raise HTTPException(400)
    if v["risk_tier"] == "High" or v["status"] == "In Security Review":  # high-risk lock
        if u["role"] != "security": raise HTTPException(403, "High-risk vendors need Security sign-off.")
        if v["status"] != "In Security Review": raise HTTPException(400, "Vendor is not in the review queue.")
    else:
        if u["role"] != "procurement": raise HTTPException(403, "Only Procurement decides Low/Medium vendors.")
        if v["status"] != "Submitted": raise HTTPException(400, "Vendor has not submitted a questionnaire.")
    c.execute("UPDATE vendors SET status=? WHERE id=?", (action, vid)); audit(c, vid, u["email"], f"Marked {action}", note)
    send_email(v["contact_email"], f"Security review outcome: {action}", f"{v['company_name']} was {action.lower()}.")
    c.commit(); return go(f"/vendors/{vid}")

@app.post("/vendors/{vid}/override")
def override(req: Request, vid: int, tier: str = Form(...), justification: str = Form(...)):
    u = need(req, "security"); c = db(); v = get_vendor(c, vid)
    if tier not in ("Low", "Medium", "High") or not justification.strip(): raise HTTPException(400, "Tier and justification are required.")
    c.execute("UPDATE vendors SET risk_tier=? WHERE id=?", (tier, vid))
    audit(c, vid, u["email"], f"Risk override {v['risk_tier']} -> {tier}", justification.strip()); c.commit(); return go(f"/vendors/{vid}")

@app.post("/vendors/{vid}/note")
def note(req: Request, vid: int, text: str = Form(...)):
    u = need(req, "security"); c = db(); get_vendor(c, vid); audit(c, vid, u["email"], "Audit note", text); c.commit(); return go(f"/vendors/{vid}")

# ---------- vendor portal (token link) ----------
def by_token(c, tok):
    v = c.execute("SELECT * FROM vendors WHERE token=?", (tok,)).fetchone()
    if not v: raise HTTPException(404, "This link is not valid.")
    return v

@app.get("/vendor/{tok}")
def portal(req: Request, tok: str, done: int = 0):
    c = db(); v = by_token(c, tok); sections = {}
    for s, q, t, crit in QUESTIONS: sections.setdefault(s, []).append((q, t))
    return page(req, "vendor.html", v=v, sections=sections, editable=v["status"] in ("Draft", "Invited", "Renewal Due"), done=done,
                docs=c.execute("SELECT * FROM document_uploads WHERE vendor_id=?", (v["id"],)).fetchall())

@app.post("/vendor/{tok}/submit")
async def submit(req: Request, tok: str, files: list[UploadFile] = File(default=[])):
    c = db(); v = by_token(c, tok)
    if v["status"] not in ("Draft", "Invited", "Renewal Due"): raise HTTPException(400, "Already submitted.")
    f = await req.form()
    save_responses(c, v["id"], {q: f.get(f"a_{q}") == "yes" for _, q, _, _ in QUESTIONS}, {q: f.get(f"e_{q}", "")[:1000] for _, q, _, _ in QUESTIONS})
    for up in files:
        if not up.filename: continue
        data = await up.read()
        if not up.filename.lower().endswith(EXTS) or len(data) > MAX_BYTES: raise HTTPException(400, "Only PDF/DOCX files up to 10MB are accepted.")
        path = os.path.join(UP, f"{v['id']}_{secrets.token_hex(6)}{os.path.splitext(up.filename)[1].lower()}"); open(path, "wb").write(data)
        c.execute("INSERT INTO document_uploads(vendor_id,file_name,file_path) VALUES(?,?,?)", (v["id"], os.path.basename(up.filename), path))
    score, tier = calc(c, v["id"]); status = "In Security Review" if tier == "High" else "Submitted"  # human approval step
    c.execute("UPDATE vendors SET overall_risk_score=?,risk_tier=?,status=?,last_submitted_at=? WHERE id=?", (score, tier, status, now(), v["id"]))
    audit(c, v["id"], "vendor", f"Submitted questionnaire ({score}%, {tier})")
    c.commit(); return go(f"/vendor/{tok}?done=1")

@app.post("/vendor/{tok}/contact")
def contact(tok: str, contact_name: str = Form(...), contact_email: str = Form(...)):
    c = db(); v = by_token(c, tok)
    c.execute("UPDATE vendors SET contact_name=?,contact_email=? WHERE id=?", (contact_name.strip(), contact_email.strip(), v["id"]))
    audit(c, v["id"], "vendor", "Updated contact details"); c.commit(); return go(f"/vendor/{tok}")

# ---------- templates (Material-style) ----------
T = {}
T["base.html"] = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{% block title %}Supplier Security{% endblock %}</title>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel=stylesheet>
<style>
:root{--p:#00695c;--pd:#004d40;--bg:#f4f6f5;--card:#fff;--tx:#1d2b29;--mu:#5d6d6a;--ln:#dfe6e4;--red:#c62828;--amb:#b26a00;--grn:#2e7d32}
@media(prefers-color-scheme:dark){:root{--bg:#121a19;--card:#1b2625;--tx:#e6efed;--mu:#9bb0ac;--ln:#2d3b39;--p:#4db6ac;--pd:#26a69a}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 Roboto,system-ui,sans-serif;background:var(--bg);color:var(--tx)}
header{background:var(--pd);color:#fff;padding:0 24px;display:flex;align-items:center;gap:20px;height:56px;box-shadow:0 2px 4px #0003}
header b{font-size:18px;flex:1}header a{color:#fff;text-decoration:none;opacity:.9}header span{opacity:.75;font-size:13px}
main{max-width:1100px;margin:24px auto;padding:0 16px}h1{font-weight:500;margin:0 0 16px}h2{font-weight:500;margin:24px 0 8px;font-size:18px}
.card{background:var(--card);border-radius:8px;box-shadow:0 1px 3px #0002;padding:16px;margin-bottom:16px;overflow-x:auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}.stats .card{margin:0}.stats strong{font-size:28px;display:block}.stats span{color:var(--mu)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--ln)}th{color:var(--mu);font-weight:500;font-size:13px}
.btn{background:var(--p);color:#fff;border:0;border-radius:4px;padding:8px 16px;font:500 14px Roboto,sans-serif;cursor:pointer;text-decoration:none;display:inline-block}
.btn.o{background:none;color:var(--p);border:1px solid var(--p)}.btn.r{background:var(--red)}.btn:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #ffb300;outline-offset:1px}
.chip{border-radius:12px;padding:2px 10px;font-size:12px;font-weight:500;border:1px solid currentColor;white-space:nowrap}
.High,.Rejected{color:var(--red)}.Medium,.Renewal\\ Due,.In\\ Security\\ Review{color:var(--amb)}.Low,.Approved{color:var(--grn)}.Draft,.Invited,.Submitted{color:var(--mu)}
input,select,textarea{font:inherit;padding:8px;border:1px solid var(--ln);border-radius:4px;background:var(--card);color:var(--tx);width:100%;margin:4px 0 12px}
label{font-size:13px;color:var(--mu)}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row form{display:inline}.muted{color:var(--mu)}
dialog{border:0;border-radius:8px;padding:24px;width:min(420px,92vw);background:var(--card);color:var(--tx)}dialog::backdrop{background:#0006}
.q{padding:12px 0;border-bottom:1px solid var(--ln)}.q label{color:var(--tx);font-size:15px}.crit{color:var(--red);font-size:12px}
.q .row label{margin-right:12px}.q input[type=radio]{width:auto;margin:0 4px 0 0}.err{color:var(--red)}.ok{background:#e8f5e9;color:#1b5e20;padding:12px;border-radius:4px;margin-bottom:12px;word-break:break-all}
@media print{header,.noprint{display:none}body{background:#fff;color:#000}}
</style></head><body>
<header><b>Supplier Security</b>{% if user %}<a href="/{{user.role}}">Dashboard</a><span>{{user.email}}</span><a href="/logout">Sign out</a>{% endif %}</header>
<main>{% block body %}{% endblock %}</main></body></html>"""
chip = "{% macro chip(x) %}<span class='chip {{x}}'>{{x}}</span>{% endmacro %}"
T["login.html"] = """{% extends 'base.html' %}{% block body %}<div class=card style="max-width:380px;margin:60px auto"><h1>Sign in</h1>
{% if error %}<p class=err>{{error}}</p>{% endif %}<form method=post><label>Email</label><input name=email type=email required><label>Password</label>
<input name=password type=password required><button class=btn>Sign in</button></form>
<p class=muted>Demo: procurement@demo.com or security@demo.com, password demo1234. Vendors use the link from their invite email.</p></div>{% endblock %}"""
T["procurement.html"] = chip + """{% extends 'base.html' %}{% block body %}
<div class=row><h1 style="flex:1">Vendors</h1><a class="btn o" href="/export.csv">Export CSV</a>
<form method=post action="/run-renewals"><button class="btn o">Run renewal check</button></form>
<button class=btn onclick="document.getElementById('d').showModal()">Onboard vendor</button></div>
{% if link %}<div class=ok>Invite sent. Questionnaire link: {{link}}</div>{% endif %}
<div class=stats>{% for k,n in stats.items() %}<div class=card><strong>{{n}}</strong><span>{{k}}</span></div>{% endfor %}</div>
<div class=card><table><tr><th>Vendor<th>Contact<th>Score<th>Risk<th>Status<th>Last submitted<th></tr>
{% for v in vendors %}<tr><td><a href="/vendors/{{v.id}}">{{v.company_name}}</a><td>{{v.contact_email}}<td>{{v.overall_risk_score}}%<td>{{chip(v.risk_tier)}}<td>{{chip(v.status)}}
<td>{{(v.last_submitted_at or '-')[:10]}}<td><a href="/vendors/{{v.id}}/report">Report</a></tr>{% endfor %}</table></div>
<dialog id=d><form method=post action="/procurement/onboard"><h2 style="margin-top:0">Onboard vendor</h2><label>Company name</label><input name=company_name required>
<label>Contact name</label><input name=contact_name required><label>Contact email</label><input name=contact_email type=email required>
<div class=row><button class=btn>Send invite</button><button class="btn o" type=button onclick="d.close()">Cancel</button></div></form></dialog>{% endblock %}"""
T["security.html"] = chip + """{% extends 'base.html' %}{% block body %}<div class=row><h1 style="flex:1">High-risk review queue</h1>
<form method=post action="/run-renewals"><button class="btn o">Run renewal check</button></form></div>
{% for v in queue %}<div class=card><div class=row><h2 style="flex:1;margin:0">{{v.company_name}}</h2>{{chip(v.risk_tier)}}<strong>{{v.overall_risk_score}}%</strong></div>
<p class=muted>Failed controls:</p><ul>{% for f in fails[v.id] %}<li>{{f.question_text}}{% if f.is_critical %} <span class=crit>critical</span>{% endif %}</li>{% endfor %}</ul>
<div class=row><a class="btn o" href="/vendors/{{v.id}}">Documents and notes</a>
<form method=post action="/vendors/{{v.id}}/decision"><input type=hidden name=action value=Approved><button class=btn>Approve</button></form>
<form method=post action="/vendors/{{v.id}}/decision"><input type=hidden name=action value=Rejected><button class="btn r">Reject</button></form></div></div>
{% else %}<div class=card>No vendors are waiting for review.</div>{% endfor %}
<h2>All other vendors</h2><div class=card><table>{% for v in others %}<tr><td><a href="/vendors/{{v.id}}">{{v.company_name}}</a><td>{{v.overall_risk_score}}%<td>{{chip(v.risk_tier)}}<td>{{chip(v.status)}}</tr>{% endfor %}</table></div>{% endblock %}"""
T["detail.html"] = chip + """{% extends 'base.html' %}{% block body %}<div class=row><h1 style="flex:1">{{v.company_name}}</h1>{{chip(v.risk_tier)}}{{chip(v.status)}}<a class="btn o" href="/vendors/{{v.id}}/report">PDF report</a></div>
<div class=card><strong>{{v.overall_risk_score}}%</strong> score. Contact: {{v.contact_name}}, {{v.contact_email}}. Last submitted: {{(v.last_submitted_at or 'never')[:10]}}.</div>
{% set locked = v.risk_tier=='High' or v.status=='In Security Review' %}
{% if (user.role=='security' and v.status=='In Security Review') or (user.role=='procurement' and not locked and v.status=='Submitted') %}
<div class=card><h2 style="margin-top:0">Decision</h2><form method=post action="/vendors/{{v.id}}/decision"><label>Note</label><input name=note>
<div class=row><button class=btn name=action value=Approved>Approve</button><button class="btn r" name=action value=Rejected>Reject</button></div></form></div>
{% elif locked and user.role=='procurement' %}<div class=card>This vendor is high risk. Only Security can approve or reject it.</div>{% endif %}
{% if user.role=='security' %}<div class=card><h2 style="margin-top:0">Override risk tier</h2><form method=post action="/vendors/{{v.id}}/override"><label>New tier</label>
<select name=tier><option>Low<option>Medium<option>High</select><label>Justification (required)</label><input name=justification required><button class="btn o">Save override</button></form>
<h2>Add audit note</h2><form method=post action="/vendors/{{v.id}}/note"><input name=text required><button class="btn o">Add note</button></form></div>{% endif %}
<h2>Responses</h2><div class=card><table><tr><th>Section<th>Question<th>Answer<th>Evidence</tr>{% for r in resp %}<tr><td>{{r.section_name}}<td>{{r.question_text}}{% if r.is_critical %} <span class=crit>critical</span>{% endif %}
<td class="{{'Low' if r.answer_bool else 'High'}}">{{'Yes' if r.answer_bool else 'No'}}<td>{{r.evidence_text}}</tr>{% else %}<tr><td colspan=4 class=muted>No responses yet.</tr>{% endfor %}</table></div>
<h2>Documents</h2><div class=card>{% for d in docs %}<div><a href="/files/{{d.id}}">{{d.file_name}}</a> <span class=muted>{{d.uploaded_at[:10]}}</span></div>{% else %}<span class=muted>No documents uploaded.</span>{% endfor %}</div>
<h2>Audit log</h2><div class=card><table>{% for l in log %}<tr><td>{{l.at}}<td>{{l.user}}<td>{{l.action}}<td>{{l.note}}</tr>{% endfor %}</table></div>{% endblock %}"""
T["report.html"] = """{% extends 'base.html' %}{% block body %}<button class="btn noprint" onclick="print()">Print or save as PDF</button>
<div class=card><h1>Security evaluation: {{v.company_name}}</h1><p>Generated {{today}}. Score {{v.overall_risk_score}}%, risk tier {{v.risk_tier}}, status {{v.status}}.</p>
<h2>Failed security checks</h2><ul>{% for f in fails %}<li>{{f.section_name}}: {{f.question_text}}{% if f.is_critical %} (critical){% endif %}</li>{% else %}<li>None</li>{% endfor %}</ul>
<h2>Approval notes and history</h2><ul>{% for l in log %}<li>{{l.at}} {{l.user}}: {{l.action}} {{l.note}}</li>{% endfor %}</ul></div>{% endblock %}"""
T["vendor.html"] = """{% extends 'base.html' %}{% block body %}<h1>Security questionnaire for {{v.company_name}}</h1>
{% if done %}<div class=ok>Thanks. Your questionnaire was submitted and Procurement has been notified.</div>{% endif %}
{% if v.status=='Renewal Due' %}<div class=card>Your annual re-assessment is due. Please review and resubmit.</div>{% endif %}
{% if editable %}<form method=post action="/vendor/{{v.token}}/submit" enctype=multipart/form-data>
{% for s,qs in sections.items() %}<div class="card step" {% if not loop.first %}hidden{% endif %}><h2 style="margin-top:0">{{s}} ({{loop.index}} of {{sections|length}})</h2>
{% for q,t in qs %}<div class=q><label>{{t}}</label><div class=row><label><input type=radio name="a_{{q}}" value=yes required>Yes</label><label><input type=radio name="a_{{q}}" value=no>No</label></div>
<input name="e_{{q}}" placeholder="Evidence or comment (optional)"></div>{% endfor %}
<div class="row noprint">{% if not loop.first %}<button type=button class="btn o" onclick="go(-1)">Back</button>{% endif %}
{% if not loop.last %}<button type=button class=btn onclick="go(1)">Next</button>{% else %}</div><label>Attach SOC 2 / ISO certificates (PDF or DOCX, 10MB max each)</label>
<input type=file name=files multiple accept=".pdf,.docx"><button class=btn>Submit questionnaire</button><div>{% endif %}</div></div>{% endfor %}</form>
<script>let i=0;const st=[...document.querySelectorAll('.step')];function go(n){const cur=st[i];if(n>0&&![...cur.querySelectorAll('input[type=radio]')].every(r=>cur.querySelector(`input[name="${r.name}"]:checked`))){cur.querySelector('input[type=radio]:invalid')?.reportValidity();return}st[i].hidden=true;i+=n;st[i].hidden=false;scrollTo(0,0)}</script>
{% else %}<div class=card>Status: <strong>{{v.status}}</strong>. Score: {{v.overall_risk_score}}%. Uploaded documents: {{docs|length}}.</div>{% endif %}
<div class=card><h2 style="margin-top:0">Contact details</h2><form method=post action="/vendor/{{v.token}}/contact"><label>Name</label><input name=contact_name value="{{v.contact_name}}" required>
<label>Email</label><input name=contact_email type=email value="{{v.contact_email}}" required><button class="btn o">Update contact</button></form></div>{% endblock %}"""
env = Environment(loader=DictLoader(T), autoescape=select_autoescape())
