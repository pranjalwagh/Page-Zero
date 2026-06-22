import time, subprocess, json, os, shlex, re
from datetime import datetime
from langgraph.graph import StateGraph, END
from typing import TypedDict
from google import genai
from google.genai import types
import httpx
from dotenv import load_dotenv

load_dotenv()  # loads GEMINI_API_KEY from .env file

# ─────────────────────────────────────────────
#  TIMING
# ─────────────────────────────────────────────
REMEDIATE_WAIT_S    = 8
VERIFY_POLL_S       = 8
VERIFY_STABILITY_S  = 8
VERIFY_MAX_ATTEMPTS = 3
MAIN_LOOP_WAIT_S    = 12

NS             = "techforum-demo"
MEMORY_FILE    = "incident_memory.json"
DEPLOYMENTS    = ["payment-gateway", "fraud-detection", "transaction-ledger"]
AI_MODEL       = "gemma-4-31b-it"
AI_PROVIDER    = "Google Cloud (Gemma-4-31b)"

# ── Feature 1: Safe Remediation ───────────────
MAX_REMEDIATION_ATTEMPTS = 5          # hard stop before human escalation
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# ── Security: SSL verification ────────────────
# Set DISABLE_SSL_VERIFY=true in .env ONLY for corporate proxy environments.
# Default is False (verify SSL) for production safety.
DISABLE_SSL_VERIFY = os.environ.get("DISABLE_SSL_VERIFY", "false").lower() in ("true", "1", "yes")
if DISABLE_SSL_VERIFY:
    import warnings
    warnings.warn(
        "⚠️  SSL verification is DISABLED (DISABLE_SSL_VERIFY=true). "
        "This makes API calls vulnerable to man-in-the-middle attacks. "
        "Only use this in trusted corporate proxy environments.",
        stacklevel=1,
    )

# ── Security: Shell metacharacter blocklist ───
SHELL_METACHARACTERS = frozenset(';|&`$><!()')

def _is_safe_command(cmd: str) -> bool:
    """Validate a kubectl command is safe to execute.

    Returns True only if:
      1. The command starts with 'kubectl'
      2. It contains no shell metacharacters that could allow injection
      3. It matches at least one REVERSIBLE_COMMANDS prefix (allowlist)
      4. It does NOT match any IRREVERSIBLE_PATTERNS prefix (blocklist)
    """
    stripped = cmd.strip()
    # Must start with kubectl
    if not stripped.startswith("kubectl"):
        return False
    # Reject shell metacharacters (prevents ; && || | ` $() > < injection)
    if any(ch in stripped for ch in SHELL_METACHARACTERS):
        return False
    # Allowlist: must match at least one reversible command prefix
    if not any(stripped.startswith(prefix) for prefix in REVERSIBLE_COMMANDS):
        return False
    # Blocklist: must NOT match any irreversible pattern
    if any(stripped.startswith(pattern) for pattern in IRREVERSIBLE_PATTERNS):
        return False
    return True

# Commands the agent is ALLOWED to execute autonomously (fully reversible)
REVERSIBLE_COMMANDS = [
    "kubectl delete pod",
    "kubectl scale deployment",
    "kubectl rollout undo",
    "kubectl rollout restart",
    "kubectl set image",
    "kubectl set env",
    "kubectl annotate",
    "kubectl label",
]

# Command patterns that are BLOCKED — agent can only suggest these in the report
IRREVERSIBLE_PATTERNS = [
    "kubectl delete deployment",
    "kubectl delete namespace",
    "kubectl delete pvc",
    "kubectl delete secret",
    "kubectl delete configmap",
    "kubectl drain",
    "kubectl cordon",
    "kubectl taint",
    "kubectl replace",
    "kubectl patch",   # can silently change specs, security contexts, tolerations — human must approve
    "kubectl create",  # creates new resources — out of scope for autonomous agent
    "kubectl apply",   # declarative apply — can create/replace anything
]

# ── Feature 2: Two-tier memory ────────────────
PERMANENT_MEMORY_MAX = 50             # up from 20, only successes stored
# Temporary in-process log — per deployment, cleared after each incident resolves
# Key: deployment_name → list of {attempt, action, commands, outcome}
active_incident_log: dict[str, list] = {}

_api_key = os.environ.get("GEMINI_API_KEY")
if not _api_key:
    raise EnvironmentError("GEMINI_API_KEY environment variable is not set. "
                           "Add GEMINI_API_KEY=your-key to the .env file.")
gemma_client   = genai.Client(api_key=_api_key)
# Conditionally bypass SSL verification for corporate proxy environments.
# Controlled via DISABLE_SSL_VERIFY env var (default: False = verify SSL).
if DISABLE_SSL_VERIFY:
    gemma_client._api_client._httpx_client = httpx.Client(verify=False)
failure_memory: dict[str, int] = {}

# ─────────────────────────────────────────────
#  LLM HELPER — robust Gemma call
# ─────────────────────────────────────────────
# gemma-4-31b-it is a THINKING model: it consumes hidden "thinking tokens"
# before writing visible output.  With a small max_output_tokens budget the
# model can exhaust all tokens on internal reasoning and return resp.text=None.
# Fix: (1) cap thinking budget so real output always has room,
#      (2) keep total budget generous (8 192),
#      (3) fall back to walking candidates.parts when resp.text is still None.
def _call_gemma(prompt: str,
                max_tokens: int = 8192,
                temperature: float = 0.3,
                _retries: int = 4) -> str:
    """Call Gemma safely with automatic retry on transient errors.

    Retries up to _retries times with exponential backoff on:
      - 500 INTERNAL  (Google-side transient fault)
      - 503 UNAVAILABLE  (overload / maintenance)
      - 429 RESOURCE_EXHAUSTED  (quota/rate-limit — back off and retry)
    Raises immediately on 400 (bad request) and 401/403 (auth).

    gemma-4-31b-it uses hidden thinking tokens that count against
    max_output_tokens. Keep max_tokens large (default 8192) so visible
    output always has room after internal reasoning finishes.
    """
    RETRYABLE_CODES = {429, 500, 502, 503, 504}
    last_exc: Exception = RuntimeError("no attempt made")

    for attempt in range(1, _retries + 2):   # +2: first try + _retries retries
        try:
            resp = gemma_client.models.generate_content(
                model=AI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )

            # Path 1: normal — resp.text works
            if resp.text is not None and resp.text.strip():
                return resp.text.strip()

            # Path 2: thinking model — walk candidates.parts, skip thought=True
            for candidate in (resp.candidates or []):
                parts = getattr(getattr(candidate, "content", None), "parts", None) or []
                visible = "".join(
                    getattr(p, "text", "") or ""
                    for p in parts
                    if not getattr(p, "thought", False)
                ).strip()
                if visible:
                    return visible

            # Path 3: still nothing — diagnose and raise
            finish = "unknown"
            try:
                finish = str(resp.candidates[0].finish_reason) if resp.candidates else "no candidates"
            except Exception:
                pass
            raise ValueError(f"Empty response (finish_reason={finish})")

        except Exception as exc:
            last_exc = exc
            exc_str  = str(exc)

            # Check if this is a retryable HTTP error code
            is_retryable = any(f" {code} " in exc_str or f"_{code}" in exc_str
                               for code in RETRYABLE_CODES)
            # Also catch plain connection/timeout errors
            is_retryable = is_retryable or any(
                kw in exc_str.lower()
                for kw in ("timeout", "connection", "reset", "eof", "internal error")
            )

            if not is_retryable or attempt > _retries:
                raise  # non-retryable or exhausted — let caller handle

            wait = min(2 ** attempt, 30)   # 2s, 4s, 8s, 16s … capped at 30s
            print(f"    ⚠️  Gemini transient error (attempt {attempt}/{_retries + 1}): "
                  f"{exc_str[:80]}")
            print(f"    🔁  Retrying in {wait}s...")
            time.sleep(wait)

    raise last_exc  # should not reach here, but satisfies type checker

# ─────────────────────────────────────────────
#  PERMANENT MEMORY  (success-only, survives restarts)
# ─────────────────────────────────────────────
def load_memory() -> list[dict]:
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE) as f:
                return json.load(f).get("incidents", [])
        except Exception:
            pass
    return []

def save_to_memory(deployment: str, symptoms: str, root_cause: str,
                   action: str, mttr_s: float,
                   commands: list[str] | None = None) -> None:
    """Write ONLY successful resolutions to permanent memory."""
    incidents = load_memory()
    incidents.append({
        "timestamp":  datetime.now().isoformat(timespec="seconds"),
        "deployment": deployment,
        "symptoms":   symptoms[:200],
        "root_cause": root_cause,
        "action":     action,
        "commands":   commands or [],
        "mttr_s":     round(mttr_s, 1),
    })
    with open(MEMORY_FILE, "w") as f:
        json.dump({"incidents": incidents[-PERMANENT_MEMORY_MAX:]}, f, indent=2)
    print(f"    📚 Success stored to permanent memory ({len(incidents)} total)")

def get_success_memory(deployment: str) -> str:
    """Return past SUCCESSFUL resolutions for Gemma to learn from."""
    incidents = load_memory()
    if not incidents:
        return "No successful resolutions recorded yet."
    relevant  = [i for i in incidents if i["deployment"] == deployment]
    all_recent = incidents[-5:]
    pool = relevant[-3:] + [i for i in all_recent if i not in relevant[-3:]]
    if not pool:
        return "No successful resolutions recorded yet."
    lines = []
    for i in pool[-5:]:
        cmds = i.get("commands", [])
        cmd_str = f" | cmds: {'; '.join(cmds)}" if cmds else ""
        lines.append(
            f"  ✅ [{i['timestamp']}] {i['deployment']}: "
            f"symptoms='{i['symptoms'][:50]}' → {i['action']}{cmd_str} "
            f"(MTTR {i['mttr_s']}s)"
        )
    return "\n".join(lines)

# ─────────────────────────────────────────────
#  TEMPORARY MEMORY  (per-incident, in-process only)
# ─────────────────────────────────────────────
def log_attempt(deployment: str, attempt_num: int, action: str,
                commands: list[str], outcome: str) -> None:
    """Append one remediation attempt to the temporary per-incident log."""
    if deployment not in active_incident_log:
        active_incident_log[deployment] = []
    active_incident_log[deployment].append({
        "attempt": attempt_num,
        "action":  action,
        "commands": commands,
        "outcome": outcome,
    })

def get_attempt_context(deployment: str) -> str:
    """Return what the agent has already tried THIS incident — for Gemma prompt."""
    attempts = active_incident_log.get(deployment, [])
    if not attempts:
        return "No remediation attempts yet this incident."

    lines = []
    blocked_strategies: set[str] = set()

    for a in attempts:
        cmds = "; ".join(a["commands"]) if a["commands"] else "no commands"
        icon = "✅" if a["outcome"] == "success" else "❌"
        lines.append(f"  {icon} Attempt {a['attempt']}: {a['action']} | {cmds} → {a['outcome']}")

        # Classify the strategy type so Gemma can't reuse it with a new pod name
        for cmd in a.get("commands", []):
            cmd_l = cmd.lower()
            if "delete pod" in cmd_l:
                blocked_strategies.add("kubectl delete pod  ← tried, pod was replaced but issue persists")
            elif "rollout restart" in cmd_l:
                blocked_strategies.add("kubectl rollout restart  ← tried, did not resolve the issue")
            elif "scale" in cmd_l and "--replicas=0" in cmd_l:
                blocked_strategies.add("kubectl scale 0→1 bounce  ← tried, did not resolve the issue")
            elif "scale" in cmd_l:
                blocked_strategies.add("kubectl scale  ← tried, did not resolve the issue")
            elif "rollout undo" in cmd_l:
                blocked_strategies.add("kubectl rollout undo  ← tried, did not resolve the issue")
            elif "set image" in cmd_l:
                blocked_strategies.add("kubectl set image  ← tried, did not resolve the issue")
            elif "set env" in cmd_l:
                blocked_strategies.add("kubectl set env  ← tried, did not resolve the issue")

    result = "\n".join(lines)

    if blocked_strategies:
        result += (
            "\n\n  ⛔ EXHAUSTED STRATEGIES — DO NOT USE THESE AGAIN IN ANY FORM:\n"
            "  (Note: the pod name changes after every delete — that does NOT make\n"
            "   'kubectl delete pod' a new strategy. It has already been tried.)\n"
        )
        for s in sorted(blocked_strategies):
            result += f"  ⛔ {s}\n"

    return result

def clear_incident_log(deployment: str) -> None:
    """Wipe the temporary incident log once an incident is resolved or escalated."""
    active_incident_log.pop(deployment, None)

# ─────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────
class SREState(TypedDict):
    pod_name:             str
    deployment_name:      str
    namespace:            str
    raw_symptoms:         str    # raw kubectl output fed to Gemma
    pod_logs:             str
    issue_detected:       bool
    gemma_reasoning:      str    # Gemma's chain-of-thought
    remediation_action:   str    # human-readable action summary
    kubectl_commands:     list   # Gemma-generated reversible commands
    blocked_commands:     list   # irreversible commands Gemma suggested (not executed)
    remediation_done:     bool
    verified:             bool
    escalated:            bool   # True when MAX_REMEDIATION_ATTEMPTS reached
    incident_report:      str
    incident_attempt_log: list   # temp memory — all attempts this incident
    retry_count:          int
    incident_start:       float

# ─────────────────────────────────────────────
#  NODE 1: OBSERVE  — collect raw facts only
# ─────────────────────────────────────────────
def observe(state: SREState) -> SREState:
    print("\n" + "="*55)
    print("🔍  [OBSERVE] Scanning Worldline payment services...")
    print("="*55)

    r = subprocess.run(
        ["kubectl", "get", "pods", "-n", NS, "--no-headers"],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode != 0:
        print(f"⚠️   kubectl error: {r.stderr.strip()}")
        state["issue_detected"] = False
        return state

    pod_output = r.stdout.strip()

    # Collect raw deployment replica counts — two separate calls to avoid
    # Windows subprocess hang when readyReplicas is null (e.g. scale-to-zero)
    replica_info = []
    for dep in DEPLOYMENTS:
        spec_r = subprocess.run(
            ["kubectl", "get", "deployment", dep, "-n", NS,
             "-o", "jsonpath={.spec.replicas}"],
            capture_output=True, text=True, timeout=30
        )
        ready_r = subprocess.run(
            ["kubectl", "get", "deployment", dep, "-n", NS,
             "-o", "jsonpath={.status.readyReplicas}"],
            capture_output=True, text=True, timeout=30
        )
        spec  = spec_r.stdout.strip()  or "0"
        ready = ready_r.stdout.strip() or "0"
        note  = " ← SCALED TO ZERO — service completely down!" if spec == "0" else ""
        replica_info.append(f"{dep}: {spec}/{ready} replicas{note}")

    raw_symptoms = f"POD STATUS:\n{pod_output}\n\nDEPLOYMENT REPLICAS:\n" + "\n".join(replica_info)

    # If any pods are Pending, capture node taint/condition info for Gemma
    if "Pending" in pod_output:
        node_info = subprocess.run(
            ["kubectl", "get", "nodes", "-o",
             "custom-columns=NAME:.metadata.name,TAINTS:.spec.taints[*].effect,STATUS:.status.conditions[-1].type"],
            capture_output=True, text=True, timeout=30
        )
        raw_symptoms += f"\n\nNODE STATUS (pods are Pending — possible scheduling block):\n{node_info.stdout.strip()}"

    # Detect any obvious issue to decide if we need to act
    problem_pod    = None
    problem_deploy = None
    pod_logs       = ""

    for line in pod_output.split("\n"):
        if not line.strip():
            continue
        bad_states = ["CrashLoopBackOff", "OOMKilled", "Error",
                      "ImagePullBackOff", "ErrImagePull", "0/1", "Pending"]
        if any(s in line for s in bad_states):
            parts = line.split()
            # Filter out transitional states (but NOT Pending — that IS a problem)
            if len(parts) >= 3 and parts[2] in ("ContainerCreating", "Terminating"):
                continue
            # 0/1 Running with 0 restarts = just starting, not broken
            if "0/1" in line and "Running" in line:
                try:
                    restarts = int(parts[3].split("(")[0]) if len(parts) > 3 and parts[3][0].isdigit() else 0
                except (ValueError, IndexError):
                    restarts = 0
                if restarts == 0:
                    continue
            problem_pod    = parts[0]
            problem_deploy = "-".join(parts[0].split("-")[:-2])
            break

    # Check scale-to-zero
    if not problem_pod:
        for dep in DEPLOYMENTS:
            rc = subprocess.run(
                ["kubectl", "get", "deployment", dep, "-n", NS,
                 "-o", "jsonpath={.spec.replicas}"],
                capture_output=True, text=True, timeout=30
            )
            if rc.stdout.strip() == "0":
                problem_pod    = f"{dep} (0 replicas — fully down)"
                problem_deploy = dep
                break

    if problem_pod:
        is_reentry = bool(state.get("incident_start"))   # True when looping back from learn()

        # Only increment the outer failure counter on FIRST detection per main-loop cycle.
        # On re-entry from learn() the incident is already in progress — don't double-count.
        if not is_reentry:
            failure_memory[problem_deploy] = failure_memory.get(problem_deploy, 0) + 1

        # retry_count is authoritative in state (learn() increments it each attempt).
        # On first detection: seed it from failure_memory.
        # On re-entry: PRESERVE what learn() already set — do NOT overwrite with failure_memory.
        current_retry = state.get("retry_count") if is_reentry else failure_memory.get(problem_deploy, 1)

        print(f"⚠️   Issue detected → {problem_pod}")
        print(f"    Attempt #{current_retry} for [{problem_deploy}]")

        # Collect logs
        if "0 replicas" not in problem_pod:
            logs = subprocess.run(
                ["kubectl", "logs", problem_pod, "-n", NS, "--tail=40", "--previous"],
                capture_output=True, text=True, timeout=30
            )
            pod_logs = logs.stdout or logs.stderr
            if not pod_logs.strip():
                logs2 = subprocess.run(
                    ["kubectl", "logs", problem_pod, "-n", NS, "--tail=40"],
                    capture_output=True, text=True, timeout=30
                )
                pod_logs = logs2.stdout or logs2.stderr or "No logs available"

            # ── Deep diagnostics: container spec, exit codes, scheduling events ──
            # This is the PRIMARY source for root-cause: shows injected commands,
            # OOM limits, image errors, and why the pod is failing.
            desc_r = subprocess.run(
                ["kubectl", "describe", "pod", problem_pod, "-n", NS],
                capture_output=True, text=True, timeout=30
            )
            if desc_r.stdout.strip():
                raw_symptoms += (
                    f"\n\nPOD DESCRIBE (container command, exit code, events — READ THIS CAREFULLY):\n"
                    f"{desc_r.stdout[:3000]}"
                )
        else:
            pod_logs = f"No pods running — deployment {problem_deploy} has 0 replicas"

        state.update({
            "pod_name":        problem_pod,
            "deployment_name": problem_deploy,
            "raw_symptoms":    raw_symptoms,
            "pod_logs":        pod_logs,
            "issue_detected":  True,
            "retry_count":     current_retry,
            "incident_start":  state.get("incident_start") or time.time(),
        })
    else:
        print("✅  All payment services healthy. Watching...")
        failure_memory.clear()
        state["issue_detected"] = False

    return state

# ─────────────────────────────────────────────
#  NODE 2: REASON  — Gemma is the brain
# ─────────────────────────────────────────────
def reason(state: SREState) -> SREState:
    print(f"\n🧠  [REASON] {AI_MODEL} analyzing → {state['pod_name']}")
    print(f"    Querying {AI_PROVIDER}...\n")

    deployment     = state["deployment_name"]
    retry          = state["retry_count"]
    attempt_ctx    = get_attempt_context(deployment)
    success_memory = get_success_memory(deployment)

    escalation_warning = ""
    if retry >= MAX_REMEDIATION_ATTEMPTS:
        escalation_warning = (
            f"\n🚨 FINAL ATTEMPT: This is attempt {retry} of {MAX_REMEDIATION_ATTEMPTS}. "
            f"If this fails the agent will stop and escalate to a human engineer. "
            f"Choose the STRONGEST reversible fix possible."
        )

    prompt = f"""You are an autonomous SRE AI agent at Worldline, a global payment processing company.
You monitor Kubernetes infrastructure and AUTONOMOUSLY fix issues — no human intervention.

═══════════════════════════════════════════════
LIVE INFRASTRUCTURE STATE
═══════════════════════════════════════════════
{state['raw_symptoms']}

CONTAINER LOGS (last 40 lines):
{state['pod_logs'][:1500]}

═══════════════════════════════════════════════
WHAT I HAVE ALREADY TRIED THIS INCIDENT (DO NOT REPEAT THESE):
═══════════════════════════════════════════════
{attempt_ctx}
{escalation_warning}

═══════════════════════════════════════════════
SUCCESSFUL FIXES FROM PAST INCIDENTS (these have worked before):
═══════════════════════════════════════════════
{success_memory}

═══════════════════════════════════════════════
YOUR TASK
═══════════════════════════════════════════════
Analyze the infrastructure state above. Diagnose the root cause.
Then provide the EXACT kubectl commands to fix the issue.

ENVIRONMENT FACTS (do NOT contradict these):
- OS: Windows with PowerShell (single quotes around JSON DO NOT WORK — use double quotes with escaped inner quotes)
- Namespace: {NS}
- Each deployment has EXACTLY 1 container (same name as deployment). There are NO sidecars.
- These are simple nginx:alpine containers with no custom apps.

DIAGNOSIS GUIDE — use the POD DESCRIBE data above to decide:
- CrashLoopBackOff + "Command:" shows "exit 1" or a non-nginx command → the deployment spec is BROKEN.
  The correct fix is "kubectl rollout undo deployment/<name> -n {NS}" to revert to the last working version.
  Do NOT just delete the pod — the new pod will crash for the exact same reason.
- CrashLoopBackOff + normal spec (no injected command, image=nginx:alpine) → transient crash.
  Deleting the pod resets the backoff timer and may work.
- ImagePullBackOff → wrong image tag. Check the image in the describe output and fix with "kubectl set image".
- OOMKilled → memory limit too low. Use "kubectl rollout undo" to revert to previous resource limits.

ALLOWED COMMANDS (reversible — you may use these):
  kubectl delete pod, kubectl scale deployment, kubectl rollout undo,
  kubectl rollout restart, kubectl set image, kubectl set env

RESPOND IN THIS EXACT FORMAT (nothing else):
THINKING: [your diagnosis in 3-5 sentences — what's wrong, why, what's the best fix]
ACTION: [short human-readable summary]
COMMANDS:
kubectl <your first command>
kubectl <your second command if needed>
ROOT_CAUSE: [one sentence]
CONFIDENCE: [HIGH / MEDIUM / LOW]

RULES:
- Every command MUST start with "kubectl"
- Always include -n {NS} for namespace
- 1 to 3 commands maximum
- No explanations inside the COMMANDS block — raw kubectl commands only
- Do NOT repeat anything listed in "WHAT I HAVE ALREADY TRIED" above"""

    try:
        print(f"    ┌─ {AI_MODEL} analyzing... ────────────────────────────┐")
        raw = _call_gemma(prompt, max_tokens=8192, temperature=0.3)

    except Exception as primary_err:
        print(f"    ⚠️  Primary call failed: {primary_err}")
        print(f"    🔄  Retrying with focused diagnostic prompt...")

        # Lean retry prompt — plain ASCII, minimal length, same structured question
        retry_prompt = (
            f"You are an SRE. A Kubernetes pod is broken and needs a fix.\n\n"
            f"DEPLOYMENT: {deployment}\n"
            f"NAMESPACE: {NS}\n"
            f"ATTEMPT NUMBER: {retry + 1} of {MAX_REMEDIATION_ATTEMPTS}\n\n"
            f"CURRENT POD STATUS:\n{state.get('raw_symptoms', '')[:800]}\n\n"
            f"RECENT CONTAINER LOGS:\n{state.get('pod_logs', '')[:600]}\n\n"
            f"ALREADY TRIED THIS INCIDENT (DO NOT REPEAT):\n"
            f"{attempt_ctx if attempt_ctx.strip() else 'Nothing yet.'}\n\n"
            f"PAST SUCCESSFUL FIXES FOR THIS SERVICE:\n"
            f"{success_memory if success_memory.strip() else 'None on record.'}\n\n"
            f"Choose a DIFFERENT fix that has NOT been tried yet.\n"
            f"Use only: kubectl delete pod, kubectl scale, kubectl rollout restart, "
            f"kubectl rollout undo, kubectl set image, kubectl set env.\n\n"
            f"Reply in EXACTLY this format:\n"
            f"THINKING: <your diagnosis in plain sentences>\n"
            f"ACTION: <what you will do>\n"
            f"COMMANDS:\n"
            f"kubectl <command 1>\n"
            f"ROOT_CAUSE: <one sentence>\n"
            f"CONFIDENCE: HIGH or MEDIUM or LOW"
        )

        try:
            raw = _call_gemma(retry_prompt, max_tokens=4096, temperature=0.4)
            print(f"    ✅  Focused retry succeeded — {AI_MODEL} is reasoning")

        except Exception as retry_err:
            # Both LLM calls failed — agent is running BLIND. Log loudly.
            print(f"    ❌  Focused retry also failed: {retry_err}")
            print(f"    ⚠️  AI OFFLINE — agent running in degraded mode (no LLM reasoning)")
            pod_safe = state.get("pod_name", "").split()[0]
            tried_cmds_str = " ".join(
                " ".join(a.get("commands", [])) for a in active_incident_log.get(deployment, [])
            )
            if "rollout restart" not in tried_cmds_str:
                last_cmd = f"kubectl rollout restart deployment/{deployment} -n {NS}"
                last_act = "rollout restart (AI offline — degraded fallback)"
            elif "rollout undo" not in tried_cmds_str:
                last_cmd = f"kubectl rollout undo deployment/{deployment} -n {NS}"
                last_act = "rollout undo (AI offline — degraded fallback)"
            else:
                last_cmd = f"kubectl delete pod {pod_safe} -n {NS} --grace-period=0 --force"
                last_act = "delete pod (AI offline — degraded fallback)"
            raw = (
                f"THINKING: Both LLM calls failed. Degraded fallback — not AI-driven.\n"
                f"ACTION: {last_act}\n"
                f"COMMANDS:\n{last_cmd}\n"
                f"ROOT_CAUSE: LLM unavailable — heuristic only\n"
                f"CONFIDENCE: LOW"
            )

    # Parse Gemma's structured response
    thinking    = ""
    action      = "unknown"
    commands    = []
    root_cause  = "Unknown"
    confidence  = "LOW"
    in_commands = False

    for line in raw.split("\n"):
        l = line.strip()
        if l.startswith("THINKING:"):
            thinking    = l[len("THINKING:"):].strip()
            in_commands = False
        elif l.startswith("ACTION:"):
            action      = l[len("ACTION:"):].strip()
            in_commands = False
        elif l.startswith("COMMANDS:"):
            in_commands = True
        elif l.startswith("ROOT_CAUSE:"):
            root_cause  = l[len("ROOT_CAUSE:"):].strip()
            in_commands = False
        elif l.startswith("CONFIDENCE:"):
            confidence  = l[len("CONFIDENCE:"):].strip().upper()
            in_commands = False
        elif in_commands and l.startswith("kubectl"):
            commands.append(l)

    if not commands:
        pod_safe = state["pod_name"].split()[0]
        commands = [f"kubectl delete pod {pod_safe} -n {NS} --grace-period=0 --force"]
        action   = "delete pod (Gemma response unparseable)"

    print(f"    │ 💭 {thinking[:100]}")
    print(f"    │ 🎯 Action     : {action}")
    print(f"    │ 🔍 Root cause : {root_cause[:60]}")
    print(f"    │ 📊 Confidence : {confidence}")
    print(f"    │ 🛠️  Commands   : {len(commands)} kubectl command(s)")
    for cmd in commands:
        print(f"    │    → {cmd}")
    print(f"    └──────────────────────────────────────────────────┘")

    total_success = len(load_memory())
    if total_success > 0:
        print(f"    📚 Referencing {total_success} successful past resolutions from memory")

    state.update({
        "gemma_reasoning":    raw,
        "remediation_action": action,
        "kubectl_commands":   commands,
        "blocked_commands":   [],
        "incident_report":    root_cause,
    })
    return state

#  NODE 3: REMEDIATE — execute Gemma's kubectl commands
# ─────────────────────────────────────────────
def remediate(state: SREState) -> SREState:
    commands   = state.get("kubectl_commands", [])
    action     = state["remediation_action"]
    deployment = state["deployment_name"]

    print(f"\n🔧  [REMEDIATE] Executing Gemma's plan: '{action}' on [{deployment}]")

    if not commands:
        print("    ⚠️  No commands to execute")
        state["remediation_done"] = False
        return state

    executed_cmds = []

    for i, cmd in enumerate(commands, 1):
        # ── Security: comprehensive command validation ──
        if not _is_safe_command(cmd):
            stripped = cmd.strip()
            if not stripped.startswith("kubectl"):
                print(f"    ⛔ Blocked non-kubectl command: {stripped[:50]}")
            elif any(ch in stripped for ch in SHELL_METACHARACTERS):
                print(f"    ⛔ Blocked command with shell metacharacters: {stripped[:80]}")
            elif any(stripped.startswith(p) for p in IRREVERSIBLE_PATTERNS):
                print(f"    🔒 BLOCKED irreversible command — logged but NOT executed: {stripped[:80]}")
                state["blocked_commands"].append(cmd)
            else:
                print(f"    ⛔ Command not in reversible allowlist: {stripped[:80]}")
            continue

        print(f"    [{i}/{len(commands)}] $ {cmd[:120]}")
        # Security: use shlex.split() + shell=False to prevent shell injection.
        # Never use shell=True with LLM-generated commands.
        try:
            cmd_args = shlex.split(cmd.strip())
        except ValueError as e:
            print(f"         ⛔ Could not parse command (possible injection): {e}")
            executed_cmds.append(f"FAILED: {cmd}")
            continue

        try:
            result = subprocess.run(cmd_args, capture_output=True, text=True, shell=False, timeout=60)
        except FileNotFoundError:
            print(f"         ❌ kubectl not found in PATH")
            executed_cmds.append(f"FAILED: {cmd}")
            continue

        if result.returncode == 0:
            output = result.stdout.strip()
            if output:
                print(f"         ✅ {output[:80]}")
            else:
                print(f"         ✅ Done")
            executed_cmds.append(cmd)
        else:
            err = result.stderr.strip()
            print(f"         ❌ {err[:80]}")
            executed_cmds.append(f"FAILED: {cmd}")

    if state["blocked_commands"]:
        print(f"    ⚠️  {len(state['blocked_commands'])} irreversible command(s) withheld — human escalation may be required")

    # If EVERY command failed (all start with "FAILED:"), the fix did nothing
    all_failed = bool(executed_cmds) and all(c.startswith("FAILED:") for c in executed_cmds)
    if all_failed:
        print(f"    ❌ All {len(executed_cmds)} command(s) failed — this remediation had no effect")
        state["remediation_done"] = False
    else:
        state["remediation_done"] = True

    # Record this attempt in per-incident memory (outcome updated in learn())
    log_attempt(deployment, state["retry_count"], action,
                [c for c in executed_cmds if not c.startswith("FAILED:")], "pending")

    # NOTE: Do NOT overwrite remediation_done here — the all_failed check above
    # already set it correctly. Overwriting would hide the failure signal from verify().
    print(f"    ⏳ Waiting {REMEDIATE_WAIT_S}s for convergence...")
    time.sleep(REMEDIATE_WAIT_S)
    return state

# ─────────────────────────────────────────────
#  NODE 4: VERIFY
# ─────────────────────────────────────────────
def all_healthy_check() -> bool:
    r = subprocess.run(
        ["kubectl", "get", "pods", "-n", NS, "--no-headers"],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode != 0 or not r.stdout.strip():
        return False
    for dep in DEPLOYMENTS:
        rc = subprocess.run(
            ["kubectl", "get", "deployment", dep, "-n", NS,
             "-o", "jsonpath={.spec.replicas}"],
            capture_output=True, text=True, timeout=30
        )
        if rc.stdout.strip() == "0":
            return False
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        # Pending = pod cannot be scheduled (e.g. node taint, no resources)
        if "Pending" in line:
            return False
        if any(s in line for s in ["CrashLoopBackOff", "OOMKilled", "Error",
                                    "ImagePullBackOff", "ErrImagePull"]):
            return False
        parts = line.split()
        if len(parts) >= 4 and parts[3][0].isdigit():
            try:
                restarts = int(parts[3].split("(")[0])
            except (ValueError, IndexError):
                restarts = 0
            if "0/1" in line and "Running" in line and restarts > 0:
                return False
    return True

def verify(state: SREState) -> SREState:
    print(f"\n✔️   [VERIFY] Confirming recovery...")

    # If all commands failed during remediation, don't waste time polling —
    # we know the cluster state is unchanged
    if not state.get("remediation_done"):
        print(f"    ⏩ Skipping poll — remediation commands all failed, cluster unchanged")
        state["verified"] = False
        return state

    resolved = False

    for attempt in range(1, VERIFY_MAX_ATTEMPTS + 1):
        time.sleep(VERIFY_POLL_S)
        if all_healthy_check():
            print(f"    ✅ Healthy — stability check in {VERIFY_STABILITY_S}s...")
            time.sleep(VERIFY_STABILITY_S)
            if all_healthy_check():
                resolved = True
                break
            else:
                print(f"    ⚠️  Stability check failed — pod crashed again (attempt {attempt})")
        else:
            print(f"    ⏳ Still recovering... (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")

    state["verified"] = resolved
    return state

# ─────────────────────────────────────────────
#  NODE 5: LEARN  ← THE SELF-LEARNING NODE
# ─────────────────────────────────────────────
def learn(state: SREState) -> SREState:
    if not state.get("issue_detected"):
        return state

    mttr       = round(time.time() - state.get("incident_start", time.time()), 1)
    verified   = state.get("verified", False)
    deployment = state.get("deployment_name", "unknown")
    symptoms   = state.get("raw_symptoms", "")[:200]
    root_cause = state.get("incident_report", "unknown")
    action     = state.get("remediation_action", "unknown")
    commands   = state.get("kubectl_commands", [])

    print(f"\n📚  [LEARN] Outcome: {'✅ SUCCESS' if verified else '❌ FAILED'} | MTTR: {mttr}s")
    print(f"    Action  : {action}")

    # Update the outcome of the last logged attempt
    if deployment in active_incident_log and active_incident_log[deployment]:
        active_incident_log[deployment][-1]["outcome"] = "success" if verified else "failed"

    if verified:
        # SUCCESS — write to permanent success-only memory
        save_to_memory(deployment, symptoms, root_cause, action, mttr, commands)
        clear_incident_log(deployment)
        total = len(load_memory())
        print(f"    📝 Saved to permanent memory ({total} total successes) 🧠")

        report = f"""
╔══════════════════════════════════════════════════════╗
║   ✅  PageZero — INCIDENT AUTO-RESOLVED               ║
║      Intercepted at Minute Zero. Zero engineers paged║
╠══════════════════════════════════════════════════════╣
║  Service      : {state['pod_name'][:36]:<36} ║
║  AI Model     : {AI_MODEL + " (Google Cloud)":<36} ║
║  Action taken : {action:<36} ║
║  MTTR         : {str(mttr)+'s':<36} ║
║  Engineers    : 0 paged  🎉                          ║
║  Memory       : {str(total)+' successes in permanent memory':<36} ║
║  Status       : All payment services OPERATIONAL     ║
╚══════════════════════════════════════════════════════╝"""
        print(report)
        state["incident_report"] = report
        failure_memory[deployment] = 0
        send_slack_success(state)
    else:
        # FAILURE — increment retry counter (routing will decide: retry or escalate)
        new_retry = state["retry_count"] + 1
        state["retry_count"] = new_retry
        remaining = MAX_REMEDIATION_ATTEMPTS - new_retry
        if remaining > 0:
            print(f"    🔄 Attempt {new_retry}/{MAX_REMEDIATION_ATTEMPTS} failed — retrying with updated context...")
            print(f"    📋 {len(active_incident_log.get(deployment, []))} attempt(s) logged for next reason() call")
        else:
            print(f"    🚨 Attempt {new_retry}/{MAX_REMEDIATION_ATTEMPTS} failed — MAX reached, escalating to human...")

    return state

# ─────────────────────────────────────────────
#  SLACK — SUCCESS notification
# ─────────────────────────────────────────────
def send_slack_success(state: SREState) -> None:
    if not SLACK_WEBHOOK_URL:
        print("    ℹ️  SLACK_WEBHOOK_URL not set — skipping Slack notification")
        return
    try:
        deployment = state.get("deployment_name", "unknown")
        action     = state.get("remediation_action", "unknown")
        root_cause = state.get("incident_report", "unknown")[:120]
        commands   = state.get("kubectl_commands", [])
        mttr       = round(time.time() - state.get("incident_start", time.time()), 1)
        ts         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_mem  = len(load_memory())

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "✅ PageZero — Incident Auto-Resolved"}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Service:*\n`{deployment}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n:white_check_mark: OPERATIONAL"},
                    {"type": "mrkdwn", "text": f"*MTTR:*\n{mttr}s"},
                    {"type": "mrkdwn", "text": f"*Engineers paged:*\n0 :tada:"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*🤖 AI Action Taken:*\n{action}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*🔍 Root Cause:*\n{root_cause}"}
            },
        ]

        if commands:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*🛠️ Commands Executed:*\n```{'  '.join(commands)}```"}
            })

        blocks += [
            {"type": "divider"},
            {
                "type": "context",
                "elements": [{"type": "mrkdwn",
                               "text": (f"PageZero AI Agent | {AI_MODEL} | "
                                        f"Memory: {total_mem} successful resolutions | {ts}")}]
            }
        ]

        with httpx.Client(verify=not DISABLE_SSL_VERIFY) as hc:
            r = hc.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=10)
            r.raise_for_status()
        print("    📣 Slack success notification sent")
    except Exception as e:
        print(f"    ⚠️  Slack success notification failed: {e}")

# ─────────────────────────────────────────────
#  SLACK ALERT  (optional — needs SLACK_WEBHOOK_URL in .env)
# ─────────────────────────────────────────────
def send_slack_alert(report: dict) -> None:
    if not SLACK_WEBHOOK_URL:
        print("    ℹ️  SLACK_WEBHOOK_URL not set — skipping Slack notification")
        return
    try:
        sev      = report.get("severity", "P2")
        sev_icon = ":rotating_light:" if sev == "P1" else ":warning:" if sev == "P2" else ":information_source:"
        deploy   = report["deployment"]
        ts       = report.get("timestamp", "")[:19].replace("T", " ")
        attempts = f"{report.get('attempts_made', 0)}/{MAX_REMEDIATION_ATTEMPTS}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 PageZero Escalation — {sev} Incident"}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Service:*\n`{deploy}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{sev_icon} {sev}"},
                    {"type": "mrkdwn", "text": f"*Auto-fix attempts:*\n{attempts} (all failed)"},
                    {"type": "mrkdwn", "text": f"*Detected at:*\n{ts}"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔍 Root Cause:*\n{report.get('root_cause', 'Unknown')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔁 What Was Tried (all reversible, all failed):*\n{report.get('what_was_tried', 'See agent logs')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*⚡ Suggested Next Steps (some may be irreversible — engineer approval required):*\n{report.get('suggested_next_steps', 'Manual investigation required')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*💳 Customer Impact:*\n{report.get('customer_impact', 'Potential payment processing impact')}"
                }
            },
        ]

        # Add blocked commands section if any
        if report.get("blocked_commands"):
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🚫 Commands Blocked by Agent (irreversible — not auto-executed):*\n```{chr(10).join(report['blocked_commands'])}```"
                }
            })

        blocks.append({"type": "divider"})
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"PageZero AI Agent | {AI_MODEL} | Escalation generated at {ts}"}]
        })

        with httpx.Client(verify=not DISABLE_SSL_VERIFY) as hc:
            r = hc.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=10)
            r.raise_for_status()
        print("    📣 Slack alert sent (Block Kit)")
    except Exception as e:
        print(f"    ⚠️  Slack alert failed: {e}")

# ─────────────────────────────────────────────
#  NODE 6: ESCALATE  — human handoff
# ─────────────────────────────────────────────
def escalate(state: SREState) -> SREState:
    deployment  = state.get("deployment_name", "unknown")
    attempts    = state.get("retry_count", MAX_REMEDIATION_ATTEMPTS)
    blocked     = state.get("blocked_commands", [])
    symptoms    = state.get("raw_symptoms", "")[:1200]
    attempt_ctx = get_attempt_context(deployment)

    print(f"\n🚨  [ESCALATE] {attempts} attempts exhausted — generating escalation report...")

    blocked_str = "\n".join(blocked) if blocked else "None identified"
    escalation_prompt = f"""You are PageZero, an autonomous SRE AI agent at Worldline.
All {attempts} automated remediation attempts for Kubernetes deployment '{deployment}' have FAILED.
Only REVERSIBLE commands were attempted. Now a HUMAN engineer must take over.

CURRENT CLUSTER STATE:
{symptoms}

ALL ATTEMPTS THIS INCIDENT (in order):
{attempt_ctx}

IRREVERSIBLE COMMANDS THAT WERE BLOCKED (agent could not run these automatically):
{blocked_str}

Write a DETAILED, ACTIONABLE escalation report for the on-call engineer.
Be specific — include exact kubectl commands they should run.

RESPOND IN THIS EXACT FORMAT (each section can span multiple lines):
SEVERITY: P1
ROOT_CAUSE:
<one or two sentences explaining the exact technical root cause>
WHAT_WAS_TRIED:
• Attempt 1: <what was tried and what happened>
• Attempt 2: <what was tried and what happened>
• Attempt 3: <what was tried and what happened>
SUGGESTED_NEXT_STEPS:
• Step 1: <exact kubectl command or action — be specific>
• Step 2: <exact kubectl command or action>
• Step 3: <exact kubectl command or action>
• If all else fails: <describe nuclear option with exact command>
CUSTOMER_IMPACT:
<one sentence — describe the payment processing impact to Worldline customers>"""

    try:
        raw = _call_gemma(escalation_prompt, max_tokens=4096, temperature=0.2)
        print(f"    ✅ Gemma escalation report generated ({len(raw)} chars)")
    except Exception as e:
        print(f"    ⚠️  Gemma API error during escalation: {e}")
        raw = (
            f"SEVERITY: P2\n"
            f"ROOT_CAUSE:\nAll {attempts} automated remediation attempts for {deployment} failed. "
            f"Manual investigation required.\n"
            f"WHAT_WAS_TRIED:\n{attempt_ctx}\n"
            f"SUGGESTED_NEXT_STEPS:\n"
            f"• kubectl describe pod -n {NS} -l app={deployment}\n"
            f"• kubectl get events -n {NS} --sort-by=.lastTimestamp\n"
            f"• kubectl logs deployment/{deployment} -n {NS} --tail=100\n"
            f"• kubectl delete deployment {deployment} -n {NS} && kubectl apply (irreversible — human only)\n"
            f"CUSTOMER_IMPACT:\nPotential degraded payment processing for {deployment} service."
        )

    # State-machine parser — accumulates multi-line sections correctly
    report = {
        "deployment":           deployment,
        "attempts_made":        attempts,
        "timestamp":            datetime.now().isoformat(),
        "severity":             "P2",
        "root_cause":           "",
        "what_was_tried":       "",
        "suggested_next_steps": "",
        "customer_impact":      "",
        "blocked_commands":     blocked,
        "raw_gemma_output":     raw,
    }
    current_key = None
    key_map = {
        "SEVERITY:":             "severity",
        "ROOT_CAUSE:":           "root_cause",
        "WHAT_WAS_TRIED:":       "what_was_tried",
        "SUGGESTED_NEXT_STEPS:": "suggested_next_steps",
        "CUSTOMER_IMPACT:":      "customer_impact",
    }
    for line in raw.split("\n"):
        stripped = line.strip()
        matched = False
        for prefix, key in key_map.items():
            if stripped.upper().startswith(prefix):
                current_key = key
                inline = stripped[len(prefix):].strip()
                if key == "severity":
                    # Severity is always single-line — strip bracket hints like "[P1 / P2 / P3]"
                    for p in ["P1", "P2", "P3"]:
                        if p in inline:
                            inline = p
                            break
                    report[key] = inline or report[key]
                else:
                    report[key] = inline  # may be empty if Gemma put content on next line
                matched = True
                break
        if not matched and current_key and current_key != "severity" and stripped:
            sep = "\n" if report[current_key] else ""
            report[current_key] = report[current_key] + sep + stripped

    # Save escalation report to disk
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"escalation_{deployment}_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"    📄 Escalation report saved: {fname}")

    # Print full terminal summary
    print(f"""
╔══════════════════════════════════════════════════════╗
║   🚨  PageZero — ESCALATING TO HUMAN ENGINEER        ║
╠══════════════════════════════════════════════════════╣
║  Service   : {deployment:<40} ║
║  Severity  : {report['severity']:<40} ║
║  Attempts  : {str(attempts)+'/'+str(MAX_REMEDIATION_ATTEMPTS)+' exhausted':<40} ║
╚══════════════════════════════════════════════════════╝
🔍 Root Cause:
   {report['root_cause']}

🔁 What Was Tried:
{report['what_was_tried']}

⚡ Suggested Next Steps:
{report['suggested_next_steps']}

💳 Customer Impact:
   {report['customer_impact']}""")

    # Send Slack alert
    send_slack_alert(report)

    # Clear per-incident memory now that we've escalated
    clear_incident_log(deployment)

    state["escalated"]       = True
    state["incident_report"] = json.dumps(report, indent=2)
    return state

# ─────────────────────────────────────────────
#  ROUTING
# ─────────────────────────────────────────────
def route_after_observe(state: SREState) -> str:
    return "reason" if state["issue_detected"] else END

def route_after_learn(state: SREState) -> str:
    if not state.get("issue_detected"):
        return END
    if state.get("verified"):
        return END
    if state.get("retry_count", 0) >= MAX_REMEDIATION_ATTEMPTS:
        return "escalate"
    return "observe"   # re-observe: get FRESH pod state before next fix attempt

# ─────────────────────────────────────────────
#  BUILD LANGGRAPH  (6-node graph with escalation)
# ─────────────────────────────────────────────
workflow = StateGraph(SREState)
workflow.add_node("observe",   observe)
workflow.add_node("reason",    reason)
workflow.add_node("remediate", remediate)
workflow.add_node("verify",    verify)
workflow.add_node("learn",     learn)
workflow.add_node("escalate",  escalate)

workflow.set_entry_point("observe")
workflow.add_conditional_edges("observe", route_after_observe)
workflow.add_edge("reason",    "remediate")
workflow.add_edge("remediate", "verify")
workflow.add_edge("verify",    "learn")
workflow.add_conditional_edges("learn", route_after_learn)
workflow.add_edge("escalate",  END)

agent = workflow.compile()

# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────
if __name__ == "__main__":
    total_memory = len(load_memory())
    print(f"""
╔══════════════════════════════════════════════════════╗
║   🚀 PageZero — Self-Healing Kubernetes Agent        ║
║      Intercept at Minute Zero. Page nobody.          ║
║      LangGraph + {AI_MODEL + " (Google Cloud)":<36} ║
║      Observe → Reason → Remediate → Verify → Learn   ║
║      Self-learning: {str(total_memory)+' past incidents in memory':<34} ║
╚══════════════════════════════════════════════════════╝
Monitoring: {' | '.join(DEPLOYMENTS)}
""")

    cycle = 0
    while True:
        cycle += 1
        print(f"\n[Cycle {cycle}] {time.strftime('%H:%M:%S')} — Running health check...")
        try:
            initial: SREState = {
                "pod_name":           "",
                "deployment_name":    "",
                "namespace":          NS,
                "raw_symptoms":       "",
                "pod_logs":           "",
                "issue_detected":     False,
                "gemma_reasoning":    "",
                "remediation_action": "",
                "kubectl_commands":   [],
                "blocked_commands":   [],
                "remediation_done":   False,
                "verified":           False,
                "escalated":          False,
                "incident_report":    "",
                "incident_attempt_log": [],
                "retry_count":        0,
                "incident_start":     0.0,
            }
            result = agent.invoke(initial)
            if result["issue_detected"] and result.get("verified"):
                print(f"\n✅  System stable. Monitoring resumed (cycle {cycle})...")
            elif result["issue_detected"] and result.get("escalated"):
                print(f"""
╔══════════════════════════════════════════════════════╗
║   �  PageZero — MONITORING PAUSED                   ║
║      Human engineer has been alerted via Slack.      ║
║      Agent is standing down — do not auto-retry      ║
║      after a human escalation.                       ║
╚══════════════════════════════════════════════════════╝
Restart the agent once the incident is manually resolved.
""")
                break
            elif result["issue_detected"]:
                print(f"\n🔄  Attempt failed — re-observing for next try...")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"\n⚠️  Cycle error: {e} — continuing...")
        time.sleep(MAIN_LOOP_WAIT_S)
