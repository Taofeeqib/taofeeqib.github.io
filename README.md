# Comparative Analysis: Four Security Tools on `security-training-platform`

**Target codebase:** `github.com/Taofeeqib/security-training-platform` (intentionally vulnerable .NET 8 / Angular Juice-Shop–style training platform)  
**Target URL:** Security Training Platform URL
**Prepared:** 2026-05-01  
**Purpose:** Benchmark detection accuracy, false-positive rate, true-positive rate, and false-negative rate across four security tools for research purposes.

---

## TL;DR

- **Benchmark:** four security tools (Wiz Code, AWS Security Agent, Claude Security, In-House Agent) run against the same intentionally-vulnerable target within a 48-hour window, measured against a **62-item consolidated ground-truth corpus**.
- **No single tool crosses 69 % recall.** A layered pipeline is recommended.
- **Winner by coverage: In-House Agent (`run_05638cadf43f`)** — 69% recall, 58% precision, and the only tool that produces **runtime-proven** evidence (72 findings marked `confirmed_exploitable` via live HTTP probes against the deployed target).
- **Winner by precision: Claude Security** — 68 % recall, 89 % precision, and the only tool that consistently catches the OAuth / trust-level bypass chains (5 findings) that single-file LLM and pattern-matching engines miss.
- **Wiz Code is the weakest standalone engine here (16 % recall)** but uniquely valuable for **SCA + IaC** (dependency CVEs, Dockerfile, workflow pinning) — keep it in the pipeline as the SCA/IaC layer, not as primary SAST.
- **AWS Security Agent** is the best **DAST** layer — 33 findings shipped with proof-of-exploit payloads, strongest on file-upload and business-logic reachability.
- **Recommended stack** (see [§11](#11-recommended-pipeline)):
  - SAST: `Wiz Code (SCA/IaC) + Claude Security (AI SAST)` → if budget allows
  - SAST: `Dependabot (SCA) + Claude Security (AI SAST)` → for a limited budget
  - DAST: `AWS Security Agent (on-demand DAST on staging)` → if budget allows
  - DAST: `In-House Agent (fusion + DAST validator + self-triage)` → for a limited budget
  - Deployment Strategy:
    - Prioritize critical services and high-risk applications
    - Adopt on-demand and periodic scanning (monthly or quarterly)
    - Trigger scans based on meaningful changes
- **Cost dimension:**
  - Wiz Code: cheapest of all, depending on contract (~€40 per active developer/month)
  - Claude Security: depending on the enterprise contract, ≈€10 – €50 per scan (forecast)
  - AWS Security Agent: 52 task-hours × (€50 per task-hour)[https://aws.amazon.com/security-agent/pricing/] ≈ €2 600 per run
  - In-House Agent: **42.5 M tokens across 4 085 LLM calls** ≈ €150–€400 per scan depending on model and the size of the application

---

## Table of Contents

- [TL;DR](#tldr)
- [1. Introduction](#1-introduction)
- [2. Tools Under Evaluation](#2-tools-under-evaluation)
- [3. Raw Severity Distribution](#3-raw-severity-distribution)
- [4. Ground-Truth Construction](#4-ground-truth-construction)
- [5. Per-Tool Detection Matrix (against the 62-item corpus)](#5-per-tool-detection-matrix-against-the-62-item-corpus)
- [6. Accuracy Metrics](#6-accuracy-metrics)
  - [6.1 Detection Rate (Recall)](#61-detection-rate-recall)
  - [6.2 False-Positive Analysis](#62-false-positive-analysis)
  - [6.3 True-Positive / Precision](#63-true-positive--precision)
  - [6.4 Multi-Source Reconciliation (In-House only)](#64-multi-source-reconciliation-in-house-only)
- [7. False-Negative Observations — What Each Tool Missed](#7-false-negative-observations--what-each-tool-missed)
- [8. What Each Tool Did Well](#8-what-each-tool-did-well)
- [9. Overall Ranking](#9-overall-ranking)
- [10. Key Research Takeaways](#10-key-research-takeaways)
- [11. Recommended Pipeline](#11-recommended-pipeline)
- [Appendix A — 62-Item Ground-Truth Corpus](#appendix-a--62-item-ground-truth-corpus)
- [Appendix B — Evidence Citations](#appendix-b--evidence-citations)

---

## 1. Introduction

This report compares four independent security tools against a single intentionally vulnerable target: `security-training-platform`, a .NET 8 / Angular application modeled on OWASP Juice Shop (highly modified to introduce new security flaws, especially business logic flaws). The goal is to enable evidence-based decisions on which tools to adopt, how to combine them effectively, and at what cost.

The four tools were selected to cover the main categories used in modern application-security pipelines:

- **Wiz Code** — industry-standard commercial **SAST + SCA + IaC** scanner.
- **AWS Security Agent** — agentic **DAST / pentest** with live exploitation against a deployed instance.
- **Claude Security** — hosted **AI-powered static review** from Anthropic, optimised for whole-repository logic analysis.
- **In-House Agent** — a prototype multi-source pipeline that fuses Wiz portal findings, Semgrep, an LLM scanner, a runtime DAST validator, and an LLM triage layer into a single reconciled result set.

Each tool scanned the same repository and commit within a 48-hour window. To measure them on equal footing, a **62-item ground-truth corpus** was constructed by taking the union of all four reports, verifying every candidate against the source code, and cross-checking against the In-House Agent's runtime-validated findings (see [§4](#4-ground-truth-construction) and [Appendix A](#appendix-a--62-item-ground-truth-corpus)). Detection rate (recall), false-positive rate, precision, and evidence quality are then computed against that corpus.

The goal is not to declare a single winner but to characterise what each tool does well, where each one blind-spots, and which combinations produce the best coverage-per-euro for applications.

---

## 2. Tools Under Evaluation


| #   | Tool                                    | Report file                                              | Scan type                                    | Internal engine(s)                                                                   | Raw findings                                             |
| --- | --------------------------------------- | -------------------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| A   | **Wiz Code** (Wiz CLI)                  | `cloud_event_wiz_json.json`                              | Static: SAST + IaC + SCA                     | Wiz SAST engine + IaC rules + SBOM/CVE                                               | 86 (75 SAST + 5 IaC + 6 deps)                            |
| B   | **AWS Security Agent**                  | `pentest-report-Codeagent-AWSsecurity-1777650735533.txt` | DAST / agentic pentest                       | AWS AI pentest agent with live exploit                                               | 39                                                       |
| C   | **Claude Security**                     | `claude_security_report.csv`                             | AI static review (hosted)                    | Anthropic "Claude Security" scanner                                                  | 47                                                       |
| D   | **In-House Agent** (run `05638cadf43f`) | `Inhouse_run_05638cadf43f.json`                          | Multi-source **SAST + SCA + DAST validator** | Wiz portal + Semgrep + LLM scanner + runtime validator + LLM triage + reconciliation | **277 considered → 230 deduped → 131 TP + 95 FP + 4 NV** |


> All four tools scanned the same repository and commit within a 48-hour window. The In-House Agent's `05638cadf43f` run is a full multi-source pipeline (Wiz + Semgrep + LLM scanner).

---

## 3. Raw Severity Distribution


| Severity           | Wiz Code      | AWS Agent | Claude Sec. | In-House Agent (post-triage TP only) |
| ------------------ | ------------- | --------- | ----------- | ------------------------------------ |
| Critical           | 0             | 7         | 0 *(H/M/L)* | 12                                   |
| High               | 1 IaC + 2 dep | 8         | 20          | 46                                   |
| Medium             | 64 SAST + 4   | 12        | 22          | 59                                   |
| Low                | 11 + 1 dep    | 0         | 5           | 14                                   |
| Info / Unknown     | —             | 12        | —           | —                                    |
| **Total reported** | **86**        | **39**    | **47**      | **131 TP (230 raw)**                 |


---

## 4. Ground-Truth Construction

Because no single report is authoritative, we built a consolidated ground-truth corpus by taking the union of all four reports, verifying every candidate against the source files, and cross-checking against the In-House Agent's 72 `validator_status = confirmed_exploitable` records (runtime-proven).

**Consolidated ground-truth: 62 distinct real vulnerabilities.** Each is validated either (a) by the In-House Agent's runtime validator probe, (b) by the AWS Agent's proof-of-exploit, or (c) by at least two independent static tools.

The 62-item list covers SQLi login, product-search SQLi, mass-assignment role, MD5 hashing, JWT secret, XXE, SSRF variants, Zip Slip, path traversals, the OAuth attack-chain family, MFA logic, basket IDORs, XSS family, business logic, NoSQL, YAML bomb, metrics/logs/Swagger exposure, dependency CVEs, and more. See 5 below or [Appendix A](#appendix-a--62-item-ground-truth-corpus) for the full enumeration.

---

## 5. Per-Tool Detection Matrix (against the 62-item corpus)

Legend: ✓ = detected & triaged TP, ✗ = missed, ~ = partial / adjacent rule only, ⚡ = runtime-validated (In-House Agent only: `validator_status = confirmed_exploitable`).


| #   | Vulnerability                                     | Wiz | AWS | Claude Sec | In-House        |
| --- | ------------------------------------------------- | --- | --- | ---------- | --------------- |
| 1   | SQLi in Login (FromSqlRaw)                        | ✓   | ✓⚡  | ✓          | ✓⚡              |
| 2   | SQLi in product search                            | ✓   | ✓⚡  | ✓          | ✓               |
| 3   | Mass assignment role=admin                        | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 4   | Password change w/o current pw verify             | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 5   | MD5 password hashing                              | ✗   | ✗   | ✓          | ✓               |
| 6   | Default JWT secret in docker-compose              | ✗   | ✓   | ✓          | ✓               |
| 7   | Plaintext JWT secret in ECS task def              | ✗   | ✓   | ✓          | ✗               |
| 8   | XXE in FileService.ParseXmlAsync                  | ✓   | ✓⚡  | ✓          | ✓⚡              |
| 9   | SSRF via XXE                                      | ~   | ✓   | ✗          | ✓               |
| 10  | SSRF via profile-image URL                        | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 11  | Zip Slip                                          | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 12  | Path traversal in FTP download                    | ✓   | ✓⚡  | ✓          | ✓⚡              |
| 13  | Arbitrary write via complaint filename            | ~   | ✓   | ✓          | ✓               |
| 14  | Arbitrary file upload (profile image)             | ✗   | ✓   | ✗          | ✓⚡              |
| 15  | Arbitrary file upload (complaints)                | ✗   | ✓   | ✓          | ✓               |
| 16  | Null-byte extension bypass                        | ✗   | ✓   | ✗          | ✗               |
| 17  | OAuth postMessage listener origin missing         | ✗   | ✗   | ✓          | ✓               |
| 18  | OAuth callback redirectUrl XSS                    | ✗   | ✓   | ✓          | ~ (FP-labelled) |
| 19  | OAuth wildcard postMessage                        | ✗   | ✗   | ✓          | ~ (FP-labelled) |
| 20  | OAuth email-link takeover                         | ✗   | ✗   | ✓          | ✗               |
| 21  | OAuth state not session-bound                     | ✗   | ✗   | ✓          | ✗               |
| 22  | OAuth admin endpoints accept shop JWT             | ✗   | ✓   | ✓          | ✗               |
| 23  | Leaderboard admin shop-JWT bypass                 | ✗   | ✓   | ✓          | ✗               |
| 24  | Leaderboard mass assignment of points             | ✗   | ✗   | ✓          | ~               |
| 25  | Change-password IDOR via GET                      | ✗   | ✓⚡  | ✗          | ✓               |
| 26  | Secure change-pw MustChangePassword bypass        | ✗   | ✗   | ✓          | ✗               |
| 27  | Unauth security-answer plant chain                | ✗   | ✗   | ✓          | ✓⚡              |
| 28  | ResetAll deletable with shop JWT                  | ✗   | ✗   | ✓          | ✗               |
| 29  | Unauth MFA validate enumeration + brute force     | ✗   | ✓   | ✓          | ✓               |
| 30  | MFA setup accepts shop-JWT                        | ✗   | ✗   | ✓          | ✗               |
| 31  | Hardcoded admin TOTP secret                       | ✗   | ✓   | ✗          | ✓               |
| 32  | TOTP replay                                       | ✗   | ✗   | ✓          | ✗               |
| 33  | Unauth QuantitysController mutation               | ✗   | ✗   | ✓          | ✓⚡              |
| 34  | Basket IDOR read /api/Baskets/{id}                | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 35  | Basket IDOR anonymous /rest/basket/{id}           | ✗   | ✓   | ✗          | ✓               |
| 36  | Basket write IDOR (items/qty/coupon)              | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 37  | Basket-item delete ownership missing              | ✗   | ✗   | ✓          | ✓⚡              |
| 38  | Unauth checkout /rest/basket/{id}/checkout        | ✗   | ✓   | ✗          | ✗               |
| 39  | UserController GetAll / Delete role-only gate     | ✗   | ✗   | ✓          | ✓⚡              |
| 40  | IDOR GET /api/Users/{id}                          | ✗   | ✓   | ✗          | ✓⚡              |
| 41  | Stored XSS via registration email on admin page   | ✗   | ✓   | ✗          | ✓               |
| 42  | Stored XSS via feedback comment                   | ✗   | ✓⚡  | ✓          | ✓⚡              |
| 43  | Reflected XSS True-Client-IP                      | ✗   | ✓   | ✗          | ✓               |
| 44  | Reflected XSS /api/track-order                    | ✗   | ✗   | ✓          | ✓               |
| 45  | DOM XSS search query                              | ~   | ✓   | ✗          | ✓               |
| 46  | Stored XSS X-Forwarded-For → LastLoginIp          | ✗   | ✗   | ✗          | ✓               |
| 47  | bypassSecurityTrustHtml misuse (Angular)          | ✓   | ✓   | ✓          | ✓⚡              |
| 48  | Deluxe upgrade w/o payment                        | ✗   | ✓   | ✓          | ✗               |
| 49  | Open redirect (substring allowlist)               | ✗   | ✗   | ✓          | ✓               |
| 50  | NoSQL mass update (reviews PATCH)                 | ✗   | ✓   | ✓          | ✓               |
| 51  | NoSQL injection product reviews                   | ✗   | ✓   | ✗          | ✓               |
| 52  | YAML bomb (YamlDotNet defaults)                   | ✓   | ✗   | ✓          | ✓               |
| 53  | Verbose error middleware leak                     | ✗   | ✗   | ✓          | ✓⚡              |
| 54  | Unauth Prometheus/metrics/logs/dir listing        | ✗   | ✓   | ✓          | ✓⚡              |
| 55  | Permissive AllowAll CORS in production            | ✗   | ✓   | ✓          | ~ (FP-labelled) |
| 56  | CSP unsafe-inline / unsafe-eval                   | ✗   | ✓   | ✗          | ✓               |
| 57  | Swagger/OpenAPI exposed unauthenticated           | ✗   | ✓   | ✗          | ✗               |
| 58  | Coupon Base64URL "Base85" forgery                 | ✗   | ✗   | ✓          | ✓⚡              |
| 59  | Negative order quantity                           | ✗   | ✗   | ✓          | ✓⚡              |
| 60  | Weak RNG (`new Random(42)`)                       | ✓   | ✗   | ✗          | ✓ (set_a)       |
| 61  | jwt.pub served as static file                     | ✗   | ✗   | ✓          | ✗               |
| 62  | Dependency CVEs (JWT / ws / socket.io / elliptic) | ✓   | ✗   | ✗          | ✓               |


---

## 6. Accuracy Metrics

Counts are derived from the detection matrix in [§5](#5-per-tool-detection-matrix-against-the-62-item-corpus) (✓ and ⚡ count as hits, ~ counts as half, ✗ as miss), and from each tool's own FP signal where available.

### 6.1 Detection Rate (Recall)


| Tool               | TP     | FN     | Recall (TP / 62) |
| ------------------ | ------ | ------ | ---------------- |
| Wiz Code           | 10     | 52     | **16 %**         |
| AWS Agent          | 33     | 29     | **53 %**         |
| Claude Security    | 42     | 20     | **68 %**         |
| **In-House Agent** | **43** | **19** | **69 %**         |


### 6.2 False-Positive Analysis


| Tool               | Raw                      | Unique root-cause     | FPs                                                      | FP Rate                                 |
| ------------------ | ------------------------ | --------------------- | -------------------------------------------------------- | --------------------------------------- |
| Wiz Code           | 86                       | ~23                   | ~25 (29× CSRF + 23× weak-Random rule spam)               | **~29 %**                               |
| AWS Agent          | 39                       | 39                    | 6 (self-reported Unknown/Informational not reproducible) | **~15 %**                               |
| Claude Security    | 47                       | 47                    | ~2                                                       | **~4 %**                                |
| **In-House Agent** | **230** (277 considered) | 131 TP + 95 FP + 4 NV | **95 self-flagged FP**                                   | **~41 % raw → 0 % after triage filter** |


**Critical nuance for the In-House Agent:** the raw number (230) is misleading because the agent ships a built-in LLM triage layer plus a runtime validator. After triage, 131 findings are labelled `true_positive` and 95 are labelled `false_positive` (suppressed). Of the 131 TPs, **72 are additionally confirmed via runtime probes** (`validator_status = confirmed_exploitable`) — a guarantee none of the other three tools provide natively.

### 6.3 True-Positive / Precision


| Tool               | TP (vs 62-corpus) | Post-triage surface                 | Precision                                                       |
| ------------------ | ----------------- | ----------------------------------- | --------------------------------------------------------------- |
| Wiz Code           | 10                | ~23 unique                          | **43 %**                                                        |
| AWS Agent          | 33                | 39                                  | **85 %**                                                        |
| Claude Security    | 42                | 47                                  | **89 %**                                                        |
| **In-House Agent** | **43**            | **131 TP (72 validator-confirmed)** | **58 %** corpus-match / **100 %** on validator-confirmed subset |


> The In-House Agent reports many additional true positives beyond the 62-corpus (e.g. client-side auth bypass, `X-Forwarded-For` → `LastLoginIp` chain, credit-card plain-text storage). These are real, just not in the cross-tool corpus; counting them would push the TP count to **108 unique TP titles**.

### 6.4 Multi-Source Reconciliation (In-House only)

The In-House Agent is the only tool that **cross-checks findings across engines**. Its reconciliation buckets are:


| Bucket     | Meaning                                                       | Count  |
| ---------- | ------------------------------------------------------------- | ------ |
| Set A      | Confirmed by **≥2 independent engines** (Wiz + Semgrep + LLM) | **19** |
| Set B      | Confirmed by a single engine + LLM triage                     | 118    |
| Set C      | Needs manual validation                                       | 4      |
| Suppressed | Triaged out as FP / duplicate                                 | 89     |


Example Set A items: `bypassSecurityTrustHtml` with JWT data (LLM + Semgrep + Wiz), *Improper Restriction of XML External Entity Reference* (LLM + Wiz), and *Insufficient postMessage Origin Validation* (Semgrep + LLM).

---

## 7. False-Negative Observations — What Each Tool Missed

**Wiz Code – Critical misses (52 of 62):**

- Entire OAuth attack-chain family (5 distinct findings)
- Mass-assignment `role=admin`
- MD5 password hashing
- All IDOR / broken-access-control findings
- All MFA/TOTP logic issues
- All business-logic flaws (deluxe upgrade, negative quantities, coupon forgery)
- `/metrics`, `/support/logs`, Swagger exposures
- Most XSS beyond `bypassSecurityTrustHtml`
- **Why:** Wiz SAST is rule-pattern matching; it has no rules for access-control logic or multi-step auth bypasses.

**AWS Agent – Notable misses:**

- MD5 password hashing (static issue, not reachable via DAST)
- OAuth state CSRF, OAuth email-link takeover, `secure-login` postMessage (no OAuth provider credentials supplied)
- Coupon forgery / YAML bomb (need source reading)
- All dependency CVEs (no SCA component)
- `ResetAll`, security-answer plant chain, `QuantitysController` unauthenticated mutation (not in test set)

**Claude Security – Notable misses:**

- Dependency CVEs (not an SCA tool)
- Null-byte extension bypass
- Swagger / OpenAPI exposure
- `True-Client-IP` / `X-Forwarded-For` stored XSS
- Anonymous basket IDOR & unauthenticated checkout
- Profile-image MIME bypass

**In-House Agent – Notable misses:**

- Plaintext JWT secret in ECS task definition
- Secure-change-pw `MustChangePassword` bypass
- OAuth state-not-session-bound CSRF
- OAuth email-link takeover
- OAuth admin endpoints / Leaderboard admin / ResetAll shop-audience JWT bypasses
- MFA setup shop-JWT enrollment / TOTP replay
- Swagger exposure, unauthenticated checkout
- `jwt.pub` as a static file (algorithm-confusion risk)
- **Pattern:** the In-House Agent's LLM scanner operates at the file level and does not track cross-controller trust boundaries the way Claude Security's whole-repo reasoning does, so it misses multi-file audience / policy bypass chains. It caught 2 of the 5 OAuth issues, but the other 3 ended up suppressed as FPs because the LLM triage step could not reason about global auth configuration.

---

## 8. What Each Tool Did Well

**Wiz Code**

- The only one of the four tools with **dependency SCA + IaC scanning integrated** (elliptic, System.IdentityModel.Tokens.Jwt, ws, socket.io-parser, parse-uri — all surfaced with CVE IDs and fix versions).
- Clean line/column-level SAST snippets.
- Caught `new Random(42)` weak RNG that two others missed.
- Good IaC coverage (missing Dockerfile `USER`, missing `HEALTHCHECK`, workflow action pinning).

**AWS Security Agent**

- **Proof-of-exploit for 33 findings** — actual HTTP payloads and reproduction steps.
- Best coverage of file-upload variants (null-byte, profile-image type, complaint write).
- Caught business-logic Deluxe upgrade and unauthenticated basket checkout.
- Self-reported FP rate (6/39 = 15 %).

**Claude Security**

- **Highest raw recall (68 %)** and highest precision (~89 %).
- Only tool to catch the full OAuth attack-chain family (5 findings).
- Only tool to catch `MustChangePassword` bypass, `QuantitysController` mutation, security-answer plant chain, `ResetAll` shop-JWT, MFA shop-JWT enrollment, TOTP replay, and the `jwt.pub` algorithm-confusion risk.
- Extremely detailed impact chains tied to file:line.

**In-House Agent (run `05638cadf43f`)**

- **Best overall recall (69 %) — narrowly beats Claude Security.**
- **Only tool that fuses SAST (Wiz + Semgrep) + AI review (LLM scanner) + runtime DAST validator + LLM triage + multi-source reconciliation in a single run.**
- Built-in **triage layer** labels each finding `true_positive` / `false_positive` / `needs_validation`, with a per-finding rationale — no other tool does this.
- Built-in **runtime validator** executed 72 probes that turned static findings into `**confirmed_exploitable`** evidence (e.g. "Submitted XSS payload `<script>alert('XSS')</script>` via `POST /api/Feedbacks`, which returned 201 and stored the payload verbatim…").
- **Multi-source reconciliation** (Set A): 19 findings confirmed by ≥2 independent engines — the highest-confidence tier, which none of the others produce.
- Strongest coverage on Angular / client-side patterns (`bypassSecurityTrustHtml`, localStorage token storage, cookie flags, DOM XSS).
- Unique catches: credit-card plain-text storage, predictable-password-from-email, SQL query with credentials logged, hardcoded seeded user credentials, log injection via search query.

---

## 9. Overall Ranking

Ranked by composite **(Recall × Precision × Evidence-quality) / Noise**.


| Rank  | Tool                   | Recall   | Precision                               | Evidence                                    | Unique Strengths                                                          | Score |
| ----- | ---------------------- | -------- | --------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------- | ----- |
| **1** | **In-House Agent**     | **69 %** | 58 % (100 % validator-confirmed subset) | **Runtime-probed + multi-source + triaged** | Only tool with DAST validator + multi-source reconciliation + self-triage | ★★★★★ |
| **2** | **Claude Security**    | 68 %     | 89 %                                    | Source citations                            | Deepest logic / OAuth / access-control review                             | ★★★★★ |
| **3** | **AWS Security Agent** | 53 %     | 85 %                                    | Proof-of-exploit                            | Runtime validation; file-upload & business-logic depth                    | ★★★★☆ |
| **4** | **Wiz Code**           | 16 %     | 43 %                                    | Rule-pattern                                | IaC + SCA + dependency CVEs                                               | ★★☆☆☆ |


### Tie-Breaker: Why the In-House Agent edges Claude Security at rank #1

Both tools sit at roughly 68–69 % recall. The In-House Agent wins on **evidence quality** because:

1. **Runtime validator** — 72 findings carry exploit proof, not just static inference.
2. **Multi-source reconciliation** — 19 Set A findings confirmed by Wiz + Semgrep + LLM independently.
3. **Self-triage** — 95 FPs are automatically suppressed, reducing review burden.
4. **Broader engine coverage** — Wiz SCA (dependency CVEs), Semgrep (IaC / secrets / nginx smuggling / Docker misconfig) and an LLM scanner (logic flaws) all in one output.

Claude Security wins on **logic-chain reasoning** (OAuth trust-level bypasses, audience-separation defeats) that no amount of multi-engine ensembling has yet replicated in the In-House pipeline. Note: Claude Security scanned with Effort = **Standard** not **Extended**. Extended scan is likely to procduce more findings but at a significant cost.  

**Recommendation:** the two are not competitors — they are **complementary**. Layer them.

---

## 10. Key Research Takeaways

1. **No single tool exceeds 69 % recall** on this intentionally-vulnerable codebase. A layered pipeline is recommended.
2. **Pattern-matching SAST (Wiz) is the weakest standalone tool** for business-logic applications (16 % recall). Its value is almost entirely in SCA + IaC — and in cost, since it is the cheapest of the four.
3. **Runtime DAST (AWS Agent) and AI code review (Claude Security) are complementary** — the best combination when budget allows. Together they cover both logic flaws and reachability with high-confidence evidence.
4. **The In-House Agent's multi-source + validator architecture is the only design that produces `confirmed_exploitable` evidence for static findings.** That is the difference between "possible XSS" and "`POST` payload `<script>…</script>` returned 201 and rendered on the admin page" — a huge difference for triage speed.
5. **OAuth and trust-level bypass chains are systematically missed by pattern-based and single-file LLM tools.** Only Claude Security's whole-repo semantic reasoning catches them consistently. This is a real gap worth highlighting to the team.
6. **Cost dimension:**
  - Wiz Code: cheapest of all, depending on contract (~€40 per active developer/month).
  - Claude Security: depending on the enterprise contract, ≈€50–€100 per developer/month (forecast).
  - AWS Security Agent: 52 task-hours × €50 per task-hour ≈ €2 600 per run.
  - In-House Agent: **42.5 M tokens across 4 085 LLM calls** ≈ €200–€400 per run depending on model (plus infrastructure cost).

---

## 11. Recommended Pipeline

- If budget allows, **Wiz Code + Claude Security + AWS Security Agent** is the best combination. For a limited budget, **Dependabot** can replace Wiz Code for the SCA layer.
- As demonstrated in this analysis, organisations can also build in-house, multi-agent architectures tailored to specific needs — for example, a SAST agent + a DAST agent + an auto-remediation agent + a threat-modelling and design-review agent (e.g. the [AWS Threat Designer](https://github.com/awslabs/threat-designer/blob/main/README.md)) — all working together to deliver an end-to-end, comprehensive security assessment and review.

```
Commit
  │
  ├─► Wiz Code / Dependabot                        [dependency CVEs, Dockerfile, workflows — SCA/IaC layer]
  │
  ├─► Claude Security (AI static review)           [primary SAST]
  │
Deploy to staging
  │
  ├─► AWS Security Agent (DAST)                    [Pramary DAST]
  │   OR
  └─► In-House Agent (deep analysis + whitebox DAST)
                                                   [multi-agent architecture tailored to organisational needs]
```

---

## Appendix A — 62-Item Ground-Truth Corpus

(Full enumeration used as denominator for recall calculations. Each item is tagged with its primary vulnerability class.)

1. SQLi in `AuthController.Login` (FromSqlRaw) ─► Injection (SQLi)
2. SQLi in product search (`ProductController` / `RestCompatController`) ─► Injection (SQLi)
3. Mass-assignment `role=admin` on registration ─► Broken Access Control / Mass Assignment
4. Password change without current-password verification (IDOR) ─► Broken Access Control / Authentication
5. MD5 password hashing ─► Cryptographic Failure
6. Hardcoded / default JWT secret in `docker-compose.yml` ─► Secrets Management / Cryptographic Failure
7. Plaintext JWT secret in ECS task definition ─► Secrets Management / Security Misconfiguration
8. XXE in `FileService.ParseXmlAsync` ─► Injection (XXE)
9. SSRF via XXE ─► SSRF
10. SSRF via profile-image URL fetch ─► SSRF
11. Zip Slip on archive extraction ─► Path Traversal
12. Path traversal in FTP file-download ─► Path Traversal
13. Arbitrary write via complaint upload filename ─► Path Traversal / Insecure File Handling
14. Arbitrary file upload — profile image (no type check) ─► Insecure File Upload
15. Arbitrary file upload — complaints ─► Insecure File Upload
16. Null-byte extension bypass on FTP blocklist ─► Insecure File Upload / Input Validation
17. OAuth postMessage listener missing `event.origin` ─► Cross-Origin / Client-Side Security
18. OAuth callback `redirectUrl` unescaped XSS ─► XSS (Reflected)
19. OAuth callback wildcard `postMessage('*')` ─► Cross-Origin / Client-Side Security
20. OAuth email-link account takeover (no `email_verified` check) ─► Authentication / Account Takeover
21. OAuth state not session-bound (CSRF) ─► CSRF / OAuth Flow
22. OAuth admin endpoints accept shop-audience JWT ─► Broken Access Control / Token Audience Confusion
23. Leaderboard admin endpoints accept shop-audience JWT ─► Broken Access Control / Token Audience Confusion
24. Leaderboard mass assignment of `points` ─► Business Logic Flaw / Mass Assignment
25. Change-password via GET `/rest/user/change-password` IDOR ─► Broken Access Control (IDOR)
26. `SecureAuthController.ChangePassword` `MustChangePassword=true` bypass ─► Authentication / Business Logic Flaw
27. Unauthenticated `/api/SecurityAnswers` plant + `/api/Users/reset-password` ─► Broken Authentication / Account Takeover
28. `ResetAll` deletable with shop-audience JWT ─► Broken Access Control / Token Audience Confusion
29. Unauthenticated MFA-validate enumeration + TOTP brute force ─► Broken Authentication / Rate-Limiting
30. MFA setup accepts shop-audience JWT (attacker enrollment) ─► Broken Access Control / Token Audience Confusion
31. Hardcoded admin TOTP secret ─► Secrets Management / Cryptographic Failure
32. TOTP replay (no consumed-code cache) ─► Broken Authentication
33. `QuantitysController` unauthenticated mutation ─► Broken Access Control / Missing Authentication
34. Basket IDOR — read ─► Broken Access Control (IDOR)
35. Basket IDOR — anonymous ─► Broken Access Control (IDOR)
36. Basket IDOR — write ─► Broken Access Control (IDOR)
37. Basket-item delete missing ownership check ─► Broken Access Control (IDOR)
38. Unauthenticated checkout `POST /rest/basket/{id}/checkout` ─► Broken Access Control / Business Logic Flaw
39. UserController GetAll / Delete role-only gate ─► Broken Access Control
40. IDOR `GET /api/Users/{id}` ─► Broken Access Control (IDOR)
41. Stored XSS via registration email on admin page ─► XSS (Stored)
42. Stored XSS via feedback comment ─► XSS (Stored)
43. Reflected XSS `True-Client-IP` ─► XSS (Reflected)
44. Reflected XSS `/api/track-order` ─► XSS (Reflected)
45. DOM XSS search query ─► XSS (DOM)
46. Stored XSS `X-Forwarded-For` → `LastLoginIp` ─► XSS (Stored)
47. `bypassSecurityTrustHtml` multi-file misuse ─► XSS / Insecure Framework Use
48. Deluxe upgrade w/o payment ─► Business Logic Flaw
49. Open redirect (substring allowlist) ─► Open Redirect / Input Validation
50. NoSQL mass-update on reviews PATCH ─► Broken Access Control / Mass Assignment
51. NoSQL-style code injection on `GET /api/Products/{id}/reviews` ─► Injection (NoSQL)
52. YAML bomb (YamlDotNet defaults) ─► Denial of Service / Insecure Deserialisation
53. Verbose error middleware leak ─► Information Disclosure
54. Unauth Prometheus / metrics / logs / directory listing ─► Information Disclosure / Security Misconfiguration
55. Permissive AllowAll CORS in production ─► Security Misconfiguration
56. CSP `unsafe-inline` / `unsafe-eval` ─► Security Misconfiguration
57. Swagger / OpenAPI exposed unauthenticated ─► Information Disclosure / Security Misconfiguration
58. Coupon Base64URL "Base85" forgery ─► Business Logic Flaw / Cryptographic Failure
59. Negative order quantity ─► Business Logic Flaw
60. Weak RNG `new Random(42)` ─► Cryptographic Failure / Insecure Randomness
61. `jwt.pub` served as static file ─► Information Disclosure / Cryptographic Failure
62. Dependency CVEs ─► Vulnerable and Outdated Components (SCA)

---

## Appendix B — Evidence Citations


| Claim                                                        | Source                                                                            |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Wiz 75 SAST / 5 IaC / 6 vuln                                 | `cloud_event_wiz_json.json` → `rawAuditLogRecord.analytics`                       |
| Wiz 29×CSRF + 23×weak-Random rule spam                       | rule IDs `WS-I011-CSHARP-00008` / `WS-I011-CSHARP-00007`                          |
| AWS 39 findings / 7 critical / 6 FP                          | `pentest-report-Codeagent-AWSsecurity-1777650735533.txt` Executive Summary        |
| Claude Security 47 rows                                      | `claude_security_report.csv`                                                      |
| In-House 277 considered → 230 emitted, 131 TP / 95 FP / 4 NV | `Inhouse_run_05638cadf43f.json` → `triage.by_verdict`, `findings[].triage_status` |
| In-House 72 runtime-confirmed exploitable                    | `Inhouse_run_05638cadf43f.json` → `findings[].validator_status`                   |
| In-House Set A (multi-source confirmed): 19                  | `reconciliation.set_a`                                                            |
| In-House runtime: 28:19 min, 42.5 M tokens, 4 085 calls      | `triage.duration_seconds`, `token_usage`                                          |


---

*Document prepared for research purposes. All four tools scanned the same target repository within a 48-hour window.*
