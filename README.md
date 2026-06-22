# PageZero — Self-Healing Kubernetes Agent

> **Intercept at Minute Zero. Page nobody.**

PageZero is an autonomous SRE agent that auto-remediates Kubernetes failures at "Minute Zero" — before a single engineer gets paged. It monitors your cluster continuously, detects failures, reasons about root causes using **Gemma-4-31b-it** via the Google Gemini API, executes security-gated kubectl commands, verifies recovery, and learns from every incident.

Built for the **Worldline Tech Forum** to demonstrate agentic AI in production-grade payment infrastructure.

---

## Architecture

```
┌───────────┐    ┌───────────┐    ┌────────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐
│  OBSERVE  │──▶│  REASON   │──▶│ REMEDIATE  │──▶│  VERIFY   │──▶│   LEARN   │──▶│ ESCALATE  │
│ (kubectl) │    │(Gemma-4)  │    │ (kubectl)  │    │ (kubectl) │    │ (memory)  │    │  (Slack)  │
└───────────┘    └───────────┘    └────────────┘    └───────────┘    └───────────┘    └───────────┘
      ▲                                                                   │
      └───────────────── retry with updated context ──────────────────────┘
```

**6-node LangGraph state machine** with conditional routing:

| Node | Role |
|------|------|
| **Observe** | Collects pod status, deployment replica counts, node taints, and container logs |
| **Reason** | Sends all evidence + past memory to Gemma-4-31b-it; receives exact kubectl commands + diagnosis |
| **Remediate** | Executes AI-generated kubectl commands through a multi-layer security gate |
| **Verify** | Polls the cluster for recovery with a double stability confirmation check |
| **Learn** | Stores successful resolutions to persistent memory; logs failed attempts for retry context |
| **Escalate** | After 5 failed attempts, generates a detailed incident report and alerts via Slack |

Built with [LangGraph](https://github.com/langchain-ai/langgraph) for the state machine and [Google Gemini API](https://ai.google.dev/) for reasoning.

---

## Features

### AI-Driven Remediation
- **No hardcoded if/else** — Gemma-4-31b-it decides the exact kubectl commands based on live cluster state
- **Structured reasoning** — AI provides diagnosis, root cause, confidence level, and specific commands
- **Retry with escalation** — Failed fixes are logged; Gemma receives "what I already tried" context to avoid repeating actions
- **Degraded mode** — If the AI is unreachable, the agent falls back to heuristic-based remediation

### Self-Learning Memory (Two-Tier)
- **Permanent memory** (`incident_memory.json`) — Stores only successful resolutions (symptoms, commands, MTTR) across restarts
- **Temporary memory** (in-process) — Tracks all attempts during an active incident, cleared on resolution or escalation
- Past incidents are fed into Gemma's prompt so the agent learns from both successes and failures

### Security Hardening
- **Shell injection prevention** — LLM-generated commands are parsed with `shlex.split()` (never `shell=True`) and scanned for shell metacharacters (`;`, `|`, `&&`, `` ` ``, `$()`, etc.)
- **Command allowlist** — Only reversible commands are executed (`kubectl delete pod`, `kubectl scale`, `kubectl rollout undo/restart`, `kubectl set image/env`)
- **Irreversible command blocking** — Commands like `kubectl delete deployment`, `kubectl patch`, `kubectl apply`, `kubectl create` are blocked and logged for human review
- **Configurable SSL** — SSL verification enabled by default; configurable via `DISABLE_SSL_VERIFY` env var for corporate proxy environments
- **Subprocess timeouts** — All kubectl calls have a 30-second timeout to prevent indefinite hangs

### Human Escalation
- **Hard stop after 5 attempts** — Agent stops retrying and generates a detailed escalation report
- **Slack notifications** — Rich Block Kit alerts sent via webhook for both auto-resolved incidents and escalations
- **Escalation reports** — JSON files with root cause analysis, all attempted fixes, and suggested next steps (including blocked irreversible commands the engineer may need to run)

### Chaos Engineering Toolkit
- **6 built-in scenarios** in `chaos.py` covering real-world Kubernetes failures
- **2 irreversible scenarios** that test the agent's escalation path

---

## Prerequisites

- Python 3.11+
- [kubectl](https://kubernetes.io/docs/tasks/tools/) configured with cluster access
- A Kubernetes cluster with namespace `techforum-demo` and deployments:
  - `payment-gateway`
  - `fraud-detection`
  - `transaction-ledger`
- [Gemini API key](https://ai.google.dev/) (free tier works)

---

## Setup

```bash
# 1. Clone the repo
git clone <repo-url>
cd agentic-sre

# 2. Create virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install langgraph google-genai python-dotenv httpx

# 4. Configure environment variables
# Create a .env file:
cat > .env << EOF
GEMINI_API_KEY=your-api-key-here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
DISABLE_SSL_VERIFY=false
EOF

# 5. Set up the Kubernetes cluster (k3d example)
k3d cluster create sre-demo
kubectl create namespace techforum-demo
kubectl create deployment payment-gateway --image=nginx:alpine --replicas=2 -n techforum-demo
kubectl create deployment fraud-detection --image=nginx:alpine --replicas=1 -n techforum-demo
kubectl create deployment transaction-ledger --image=nginx:alpine --replicas=1 -n techforum-demo
```

---

## Usage

### Run the agent

```bash
python agent.py
```

The agent continuously monitors the cluster (every 12 seconds) and auto-heals any issues it detects. It will retry up to 5 times with escalating strategies before handing off to a human engineer via Slack.

### Inject chaos (separate terminal)

```bash
python chaos.py
```

Choose from 6 scenarios:

| # | Scenario | What it does | Agent behavior |
|---|----------|-------------|----------------|
| 1 | 💥 CrashLoopBackOff | Bad command → `exit 1` | AI diagnoses → delete pod → escalates to rollback |
| 2 | 💥 Scale-to-Zero | Replicas set to 0 | AI detects 0 replicas → scales back up |
| 3 | 💥 ImagePullBackOff | Non-existent image tag | AI detects bad image → rolls back deployment |
| 4 | 💥 OOMKilled | Memory limit 1Mi | AI detects OOM → scales up → escalates to rollback |
| 5 | 🔒 Node Taint | `NoSchedule` on all nodes | Pods stuck Pending → agent tries 5 times → **escalates to human** (fix requires `kubectl taint` which is blocked) |
| 6 | 🔒 Missing Secret | Deletes required `envFrom` secret | `CreateContainerConfigError` → agent tries 5 times → **escalates to human** (fix requires `kubectl create secret` which is blocked) |
| 7 | ✅ Restore | Full reset of all scenarios | Removes taints, secrets, recreates clean deployment |

> **Scenarios 5 & 6** are intentionally irreversible from the agent's perspective — they demonstrate the escalation and human handoff path.

---

## Environment Variables

Configure these in the `.env` file:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | ✅ Yes | — | Google Gemini API key for Gemma-4-31b-it |
| `SLACK_WEBHOOK_URL` | No | `""` | Slack incoming webhook URL for incident notifications |
| `DISABLE_SSL_VERIFY` | No | `false` | Set to `true` to bypass SSL verification (for corporate proxy environments) |

---

## Configuration

All timing and behavior constants are at the top of `agent.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `REMEDIATE_WAIT_S` | 8 | Seconds to wait after executing fix before verifying |
| `VERIFY_POLL_S` | 8 | Seconds between each verification poll |
| `VERIFY_STABILITY_S` | 8 | Seconds for the stability confirmation double-check |
| `VERIFY_MAX_ATTEMPTS` | 3 | Max verification polling rounds |
| `MAIN_LOOP_WAIT_S` | 12 | Seconds between full monitoring cycles |
| `MAX_REMEDIATION_ATTEMPTS` | 5 | Max fix attempts before escalating to human |
| `PERMANENT_MEMORY_MAX` | 50 | Max successful resolutions stored in memory |

---

## File Structure

```
agentic-sre/
├── agent.py              # Main agent — 6-node LangGraph state machine
│                         #   Observe → Reason → Remediate → Verify → Learn → Escalate
├── .py                   # Legacy agent (Ollama/Gemma3:1b, rule-based, no escalation)
├── chaos.py              # Chaos injection tool (6 scenarios + restore)
├── incident_memory.json  # Persistent self-learning memory (auto-created)
├── escalation_*.json     # Escalation reports (auto-created, gitignored)
├── .env                  # API keys and config (not committed)
├── .gitignore            # Excludes .env, venv, __pycache__, memory, escalation reports
└── README.md             # This file
```

---

## How the AI Reasoning Works

The agent sends Gemma-4-31b-it a structured prompt containing:

1. **Live pod status** — `kubectl get pods` output
2. **Deployment replica counts** — Desired vs ready replicas for all 3 services
3. **Node status** — Taint and condition info (when pods are Pending)
4. **Container logs** — Last 40 lines from the crashing container
5. **Attempt history** — What has already been tried this incident (to avoid repeating)
6. **Success memory** — Past successful resolutions with exact commands and MTTR

Gemma responds in a structured format:
```
THINKING: [diagnosis in 3-5 sentences]
ACTION: [human-readable summary]
COMMANDS:
kubectl <exact command 1>
kubectl <exact command 2>
ROOT_CAUSE: [one sentence]
CONFIDENCE: [HIGH / MEDIUM / LOW]
```

### Security Gate

Before execution, each command passes through:
1. **kubectl prefix check** — Must start with `kubectl`
2. **Shell metacharacter scan** — Rejects `;`, `|`, `&&`, `` ` ``, `$()`, `>`, `<`
3. **Allowlist match** — Must match a reversible command prefix
4. **Blocklist check** — Must not match any irreversible pattern

Blocked commands are logged in the escalation report for human review.

---

## Slack Integration

PageZero sends two types of Slack notifications (requires `SLACK_WEBHOOK_URL` in `.env`):

### ✅ Auto-Resolved
Sent when an incident is successfully fixed — includes service name, action taken, MTTR, commands executed, and memory count.

### 🚨 Escalation
Sent when all 5 automated attempts fail — includes severity, root cause, all attempted fixes, suggested next steps (including blocked irreversible commands), and customer impact assessment.

---

## License

MIT
