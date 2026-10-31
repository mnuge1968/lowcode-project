# Supplier Security Questionnaire App

Proof of Concept for Procurement and Security teams. The app automates vendor onboarding, scores security risk with a hybrid engine, requires human approval for high-risk vendors, and tracks annual reassessments.

**Tech stack:** Python (FastAPI with Jinja2 templates), SQLite, Material-style design.

## Quick start

```
cd supplier-app
python3 -m venv venv
source venv/bin/activate
python -m pip install fastapi uvicorn jinja2 python-multipart
python -m uvicorn app:app --reload
```

Open http://127.0.0.1:8000 and sign in with `procurement@demo.com` or `security@demo.com` (password `demo1234`). Vendor questionnaire links are printed in the console on first start, and Procurement sees the link after onboarding a vendor. Emails are written to `outbox.log`.

---

## Module 1: Architecture, Data Model and ERD

### Tables

At least four related tables, linked by primary and foreign keys.

**users**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| email | TEXT | UNIQUE, NOT NULL |
| hashed_password | TEXT | NOT NULL |
| role | TEXT | NOT NULL: `procurement`, `security`, `vendor` |
| vendor_id | INTEGER | NULLABLE, FK to vendors.id |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

**vendors**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| company_name | TEXT | NOT NULL |
| contact_email | TEXT | NOT NULL |
| contact_name | TEXT | NOT NULL |
| overall_risk_score | FLOAT | DEFAULT 0.0, range 0.0 to 100.0 |
| risk_tier | TEXT | DEFAULT `Low`: `Low`, `Medium`, `High` |
| status | TEXT | DEFAULT `Draft`: `Draft`, `Invited`, `Submitted`, `In Security Review`, `Approved`, `Rejected`, `Renewal Due` |
| last_submitted_at | DATETIME | NULLABLE |
| last_updated_by | TEXT | NULLABLE, audit metadata |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

**questionnaire_responses**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| vendor_id | INTEGER | NOT NULL, FK to vendors.id |
| section_name | TEXT | NOT NULL, e.g. Access Control, Data Encryption, Incident Response |
| question_id | TEXT | NOT NULL |
| question_text | TEXT | NOT NULL |
| answer_bool | BOOLEAN | DEFAULT 0, Yes/No |
| evidence_text | TEXT | NULLABLE |
| is_critical | BOOLEAN | DEFAULT FALSE, deal-breaker flag |
| points_earned | INTEGER | DEFAULT 0 |
| max_points | INTEGER | DEFAULT 10 |

**document_uploads**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| vendor_id | INTEGER | NOT NULL, FK to vendors.id |
| file_name | TEXT | NOT NULL |
| file_path | TEXT | NOT NULL, stored in `/uploads/` |
| uploaded_at | DATETIME | DEFAULT CURRENT_TIMESTAMP |

### Relationships

```
vendors 1 ---- * users                    (users.vendor_id)
vendors 1 ---- * questionnaire_responses  (vendor_id)
vendors 1 ---- * document_uploads         (vendor_id)
```

### Seed data

| Vendor | Status | Score | Tier | Reason |
|---|---|---|---|---|
| Acme Corp | Approved | 92% | Low | |
| CloudTech Solutions | In Security Review | 64% | High | Score below 70% |
| DataPipe Systems | In Security Review | 85% | High | Critical check failed: no encryption at rest |
| LogiFlow Logistics | Submitted | 78% | Medium | |
| Omega Vendors | Draft | 0% | Low | |

---

## Module 2: Automations, Access Control and Business Logic

### Automation workflows

1. **Event-triggered (vendor onboarding):** When Procurement submits new vendor details, the system creates the vendor profile, generates a unique token link, and emails the invitation to the vendor.
2. **Human approval step (high-risk lock):** When a submission results in the High tier (score below 70% or a critical check failure), status moves to *In Security Review*. Procurement cannot approve the vendor until a Security user signs off.
3. **Scheduled (annual re-assessment):** A background job checks whether `last_submitted_at` is more than 365 days old. If so, status changes to *Renewal Due* and a reminder is sent.

### Role-based access control

Enforced by backend checks on every request, not by hiding UI elements.

| Role | Create | Read | Update | Delete |
|---|---|---|---|---|
| Procurement | Vendor profile, invites | All vendor records, dashboard metrics | Low/Medium risk vendor status | None |
| Security | Audit comments and notes | All vendor records, high-risk queue | High-risk status (approve/reject), risk override | None |
| Vendor | Document uploads | Assigned vendor profile only | Questionnaire responses | None |

### Hybrid risk scoring

- **Base score:** `Score % = (sum of points earned / sum of max points) * 100`
- **High-risk triggers:** score below 70%, or any question with `is_critical = True` answered No.
- **Manual override:** Security can change the risk tier (Low, Medium, High). A justification is mandatory and is saved to the audit log.

---

## Module 3: Data Flow, STRIDE Threat Analysis and GDPR

### Data flow diagram (Level 1)

- **External entities:** External Vendor, Procurement User, Security Officer
- **Processes:** 1.0 Vendor Onboarding, 2.0 Assessment and Scoring Engine, 3.0 High-Risk Approval Workflow, 4.0 Scheduled Annual Re-assessment
- **Data stores:** SQLite database (users, vendors, responses), local storage directory (`/uploads/`)
- **Trust boundaries:** External vendor network boundary vs. internal application server boundary

### STRIDE threat analysis

| Category | Data flow / boundary | Identified risk | Mitigation |
|---|---|---|---|
| Spoofing | External Vendor to Portal | Unauthorised access to a questionnaire by guessing the link | Unique, cryptographically secure token per invite link |
| Tampering | Vendor to Assessment Engine | Risk scores modified in transit | Server-side score calculation and TLS (HTTPS) |
| Repudiation | Security Officer to Approval Flow | Denial of a high-risk approval decision | Audit log storing timestamp and user in `last_updated_by` |
| Information Disclosure | Data Store to UI | Unauthorised access to SOC 2 documents | RBAC restricting file access to authenticated Security and Procurement roles |
| Denial of Service | External Vendor to Local Storage | Storage exhaustion through excessive uploads | 10MB file size limit, PDF/DOCX only |
| Elevation of Privilege | Procurement to Approval API | Procurement approving a locked high-risk vendor | Server-side role check blocking status updates on high-risk vendors for non-Security roles |

### Data protection and GDPR

- **Lawful basis:** Article 6(1)(f) legitimate interest. Processing is necessary to assess third-party risk and maintain security controls.
- **Data minimisation:** Only business contact details (name, work email, company name) are collected. No special category data is processed.
- **Retention:** Vendor contact records and questionnaire data are kept for the active contract plus 3 years after termination, for audit compliance.
- **Visibility and rights:** Personal contact details are visible only to authorised Procurement and Security staff. Vendors can update outdated contact details through the portal.

---

## Module 4: Frontend Dashboards, Reporting and Deliverables

### Interfaces

| Page | Purpose |
|---|---|
| `/procurement` | Summary metrics, vendor directory, CSV export, "Onboard vendor" form |
| `/security` | High-risk review queue, failed controls, attached documents, approve/reject controls |
| `/vendor/{token}` | Multi-step questionnaire with SOC 2 / ISO file uploads |

### Reporting

- **CSV export:** Directory-wide report of vendor names, emails, scores, risk tiers and statuses.
- **PDF report:** Per-vendor evaluation summary showing failed checks and approval notes (a printable page; use Print, then Save as PDF).

---

## Implementation notes

- Vendors use a private token link (`/vendor/{token}`) rather than `/vendor/{id}`, and do not have user accounts.
- An extra `audit_log` table records approvals, overrides and notes alongside `last_updated_by`.
- Seeded vendor scores are fixed to match the specification and are not recalculated from their stored answers.
- Emails are written to `outbox.log` rather than sent over SMTP.
