# IBM Bob Hackathon — Official Guide Notes

**Source:** Lablab-IBM-Bob-hackathon-guide-May-2026.pdf (47 pages, IBM Corporation 2026)
**Read date:** 2026-05-17

---

## 🚨 CRITICAL ISSUES vs OUR CURRENT FORGE SUBMISSION

### Issue #1: Bob IDE is MANDATORY, Bob Shell is OPTIONAL

**Guide states (page 8 + page 18):**
> "You must use Bob IDE for this hackathon. You will have to export the Bob task session report for judging."
>
> "1. Bob IDE (Required)"
> "2. Bob Shell (Optional)"

**What we did:** Used Bob Shell exclusively (5 sessions, 20.64/40 Bobcoins)
**Risk:** Judges may disqualify or downrank because we didn't use the MANDATORY tool

### Issue #2: Bob IDE export procedure ≠ Bob Shell JSON files

**Guide specifies (pages 18-19) the EXACT export procedure for Bob IDE:**

1. Create folder `bob_sessions/` in repo ✅ (we did this)
2. Open Bob IDE chat interface → **Views and More Actions** icon → **History**
3. Confirm correct project workspace
4. Select task in history → opens in chat panel
5. Select task header → **task session consumption summary** displayed
6. **Take screenshot** of task session consumption summary
7. From same summary view → select **Export task history icon** → downloads as **markdown file**
8. Upload BOTH screenshots AND markdown files into `bob_sessions/`

**What we did:** Copied raw JSON files from `~/.bob/tmp/<hash>/chats/` (Bob Shell native format)
**Risk:** Judges expect:
- ✅ `.md` markdown task reports (we have `.json` instead)
- ✅ `.png` screenshots of task session consumption summary
- ✅ Specific format with cost/duration/file count metrics

### Issue #3: Solution must showcase Bob IDE as CORE COMPONENT

**Guide (page 4):** "to be eligible for judging, your solution must showcase IBM Bob IDE as a core component."

**What we did:** FORGE solution is independent; Bob (Shell) was used as build tool only
**Mitigation:** Demo/video should explicitly show "Bob IDE was the development partner" — but we never actually ran Bob IDE

---

## 📋 OFFICIAL HACKATHON RULES (from guide)

### Account & access
- Team: `ibm-coding-challenge-xxx` (Enterprise plan) ✓ we used this
- 40 Bobcoins per team member (we have 20.64 used, 19+ remaining)
- $80 IBM Cloud credits available (we didn't use this — optional)
- Hackathon end deadline: project submissions

### Required deliverables
1. **Code repository** (public, GitHub) ✓ github.com/SRKRZ23/ibm-bob-forge
2. **`bob_sessions/` folder** with:
   - ✅ Task session consumption summary screenshots
   - ✅ Exported task history markdown files
3. **Video demonstration** (separate field on lablab)
4. **Slide deck PDF** (separate field on lablab)
5. **Cover image** (separate field on lablab)
6. **Written description** (lablab Step 1)

### Out-of-scope (DO NOT USE)
- llama-3-405b-instruct
- mistral-medium-2505
- mistral-small-3-1-24b-instruct-2503
- Build with AI (Preview)
- Agent Lab (Beta)
- Bring your own model
- Fine tuning models
- AutoAI pipeline
- AI governance
- Evaluation Studio
- SPSS Modeler

### Theme: "Turn idea into impact faster"
> Use IBM Bob as your intelligent development partner. Bob understands intent, reads complete repository context, explains logic with clarity, automates complex transformations, and streamlines multi-step work.

### Example use cases mentioned in guide (Appendix p47)
1. **Code understanding and onboarding accelerator** ← FORGE FITS HERE
2. **Automated documentation and test companion** ← FORGE ALSO FITS (Bob generated 90 tests + 60K docs)
3. **Repetitive task and boilerplate reduction assistant**
4. **Intelligent debugging and issue insight solution**
5. **Guided modernization and improvement planner**

**Our FORGE story aligns with #1 + #2 strongly.**

---

## 🎯 REMEDIATION PLAN (URGENT — ~4h to deadline)

### Path A: Install Bob IDE NOW + replay 2-3 sessions (recommended, ~1h)

1. **Install Bob IDE** (10 min)
   - Download from bob.ibm.com (separate from Bob Shell)
   - macOS .dmg installer

2. **Login to hackathon instance** (5 min)
   - Same IBMid (razikovs777@gmail.com)
   - Select team `ibm-coding-challenge-uat` (same as Bob Shell)
   - Use Settings → switch to hackathon team

3. **Open FORGE folder in Bob IDE** (2 min)
   - File → Open Folder → `/Users/sardorrazikov1/Alish/competitions/ibmbob/forge`

4. **Run 2-3 productive tasks** (30 min, ~5-8 Bobcoins of remaining 19)
   - Task 1: "Add new pattern detection for LLM07 System Prompt Leakage (OWASP 2025 v2 category)"
   - Task 2: "Generate API reference docs for the BobShell module"
   - Task 3: "Review the codebase and propose one architectural improvement"

5. **Export task history per guide** (15 min)
   - Each task → Views and More Actions → History → click task → task header → screenshot + Export task history (markdown)
   - Save to `bob_sessions/` folder

6. **Update bob_sessions/README.md** (5 min)
   - Note: Bob Shell JSON files = supplementary historical record
   - Bob IDE markdown + screenshots = official judging artifacts per guide

7. **Commit + push** (2 min)

### Path B: Submit what we have (NOT recommended)

- Risk: disqualification or significant judge downrank
- Mitigation in video: explicitly show Bob IDE running on the repo briefly

### Path C: Do nothing, blame compressed timeline

- Highest risk of disqualification

**RECOMMENDED: Path A (install Bob IDE now)**

---

## 📊 FORGE COMPETITIVE POSITIONING (aligned with guide)

### Strong alignment points (use in video + writeup)
- ✅ **"Reads complete repository context"** (guide theme) → FORGE scans entire LLM codebase
- ✅ **"Automates complex transformations"** (guide theme) → FORGE auto-generates YAML policies
- ✅ **"Streamlines multi-step work"** (guide theme) → 4-stage pipeline SCAN→DETECT→FORGE→AUDIT
- ✅ **"Code understanding and onboarding accelerator"** (use case #1) → ARCHITECTURE.md generated by Bob
- ✅ **"Automated documentation and test companion"** (use case #2) → 90 tests + 60K docs generated by Bob

### Speakable judge soundbite
> "FORGE uses IBM Bob to turn any LLM codebase into compliance-grade governance artifacts in 27ms — automatically. Bob analyzes intent, OWASP maps the risk, FORGE generates the YAML policy, BobShell signs the audit trail. Five Bob sessions: from zero to 90 tests passing, 60KB of docs, and a tamper-evident chain — verified."

---

## 📝 LABLAB SUBMISSION FIELDS (consolidated)

Per guide and lablab UI we already saw:

**Step 1 Basic Information:**
- Title (5-50 chars): "FORGE — AI Security Policy Generator for LLMs"
- Short Description (50-255 chars): use IBM 2025 + Cisco + OWASP verified version
- Long Description (600-2000 chars): The Problem / The Solution / Built with IBM Bob / Verified
- Categories: Security · Developer Tools · Coding excellence
- Technologies: Ibm · watsonx.ai · IBM Granite · LangChain · Anthropic Claude · IBM watsonx Assistant

**Step 2 Media:**
- Cover Image: `branding/banner_cover.png` (1920×1080, with IBM 8-stripe + VERIFIED STANDARDS row)
- Video Presentation: ≤5 min, YouTube unlisted URL
- Slide Presentation: `branding/FORGE_pitch_deck.pdf` (8 slides, 1.27MB)

**Step 3 Final fields (TBD):**
- GitHub URL: https://github.com/SRKRZ23/ibm-bob-forge
- (likely) Additional links / team members confirmation

---

## ⚠️ ADDITIONAL CRITICAL GUIDE WARNINGS

### Credentials safety (page 18 + page 20)
> "Ensure that all credentials and API keys are removed in your code before exporting the task session reports and uploading them to your public code repository which will be shared as part of your submission. If any IBM Bob or Cloud service credentials are detected in your code repository, the IBM Security team will deactivate your account access."

**Our status:** ✅ SECURITY_NOTICE.md added, demo credentials redacted to `_FORGE_DEMO_PLACEHOLDER_` markers, bob_sessions JSONs post-processed (118 substitutions)

### IBM Cloud credentials exposure (page 20-21)
> "If any IBM Cloud credential associated with your hackathon account is detected in a public repository or publicly accessible platform: The credential will be deactivated immediately. Your hackathon cloud account access will be suspended"

**Our status:** ✅ We didn't use IBM Cloud (didn't request watsonx) — no risk

### Bobcoin limits (page 6)
> "Once your Bobcoin usage reaches 100% usage, no additional Bobcoins will be provided"

**Our status:** 20.64/40 used (52%) — 19+ Bobcoins remaining. Plenty for Path A remediation.

---

## ✅ POST-REMEDIATION CHECKLIST

After installing Bob IDE + replaying sessions:

- [ ] Bob IDE installed and logged into `ibm-coding-challenge-uat`
- [ ] 2-3 productive Bob IDE tasks completed on FORGE codebase
- [ ] Each task: screenshot of task session consumption summary captured
- [ ] Each task: markdown file exported via "Export task history" icon
- [ ] `bob_sessions/` folder updated with: screenshots + markdown files
- [ ] `bob_sessions/README.md` updated to explain both Bob Shell historical + Bob IDE official
- [ ] All credentials still redacted, no real secrets in any session report
- [ ] Commit + push to ibm-bob-forge
- [ ] Continue with video + lablab Step 2/3

---

## 📌 KEY URLS FROM GUIDE

- Hackathon page: lablab.ai/ai-hackathons/ibm-bob-hackathon
- Bob IDE install: bob.ibm.com/download (or via guide link "Bob IDE installation instructions")
- IBM Cloud signup: ibm.com/account/reg/us-en/signup?formid=urx-54370 (we don't need this)
- Bob best practices: linked in guide
- IBM Bob FAQ: linked in guide
- Bob admin portal: linked in guide

---

## 💡 KEY LEARNINGS TO ADD TO MEMORY

1. **Always read the official hackathon guide BEFORE starting**, not at the end. We assumed Bob Shell was equivalent to Bob IDE for judging — guide explicitly says otherwise.

2. **"Optional" vs "Required" tool distinction is critical** — when a hackathon mandates a specific UI/IDE for evidence purposes, the equivalent CLI is not a substitute.

3. **Export format matters as much as content** — markdown + screenshots (Bob IDE format) ≠ JSON (Bob Shell format), even if content is identical.

4. **Specific procedural steps in guide must be followed verbatim** — "select Views and More Actions → History → task → header → screenshot + Export" is judging instruction, not suggestion.
