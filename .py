import time
import subprocess
import json
from langgraph.graph import StateGraph, END
from typing import TypedDict
from ollama import Client

# ─────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────
class SREState(TypedDict):
    pod_name: str
    namespace: str
    pod_logs: str
    issue_detected: bool
    scenario_type: str        # 'crashloop' | 'scaled_down' | 'imagepull' | 'oomkilled'
    deployment_name: str      # always the real k8s deployment name, derived once in observe()
    ai_analysis: str
    remediation_action: str
    remediation_done: bool
    verified: bool
    incident_report: str
    retry_count: int

ollama_client = Client()
NS = "techforum-demo"

# ─────────────────────────────────────────────
#  TIMING CONSTANTS  (tune here for demo speed)
# ─────────────────────────────────────────────
REMEDIATE_WAIT_S   = 8   # seconds to wait after kubectl action before verifying
VERIFY_POLL_S      = 8   # seconds between each verify poll
VERIFY_STABILITY_S = 8   # seconds for the double-check stability confirmation
VERIFY_MAX_ATTEMPTS = 4  # max polling rounds (4 × 8s = 32s max verify window)
MAIN_LOOP_WAIT_S   = 12  # seconds between full agent cycles

# Track consecutive failures per deployment
failure_memory = {}

# Deployments we monitor for scale-to-zero
KNOWN_DEPLOYMENTS = ['fraud-detection', 'payment-gateway', 'transaction-ledger']


def get_scenario_from_line(line: str) -> str:
    """Return the scenario type from a single crashing kubectl pod line.
    NOTE: OOMKilled may not appear in STATUS after first restart cycle —
    caller should refine this with get_pod_termination_reason() for accuracy.
    """
    if 'ImagePullBackOff' in line or 'ErrImagePull' in line:
        return 'imagepull'
    if 'OOMKilled' in line:
        return 'oomkilled'
    return 'crashloop'  # covers CrashLoopBackOff and any other crash state


def get_pod_termination_reason(pod_name: str) -> str:
    """Query the pod's last container termination reason from Kubernetes.
    This is accurate even when STATUS has moved to CrashLoopBackOff.
    Returns: 'OOMKilled', 'Error', 'Completed', or '' if unavailable.
    """
    result = subprocess.run(
        ["kubectl", "get", "pod", pod_name, "-n", NS,
         "-o", "jsonpath={.status.containerStatuses[0].lastState.terminated.reason}"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return ''

# ─────────────────────────────────────────────
#  SHARED: pod health classifier
#  Returns (is_crashing, is_transitional) for one kubectl --no-headers line.
#  kubectl columns: NAME  READY  STATUS  RESTARTS  AGE
# ─────────────────────────────────────────────
def classify_pod(line: str):
    """
    Returns:
        'crashing'     – pod is definitively broken (CrashLoopBackOff / Error / OOMKilled)
        'transitional' – pod is starting up / terminating; ignore it
        'healthy'      – pod is fully ready
    """
    if not line.strip():
        return 'transitional'

    # Explicit crash statuses (appear as substring anywhere in the line)
    if any(bad in line for bad in ('CrashLoopBackOff', 'OOMKilled', 'CreateContainerError',
                                   'ImagePullBackOff', 'ErrImagePull')):
        return 'crashing'

    parts = line.split()
    if len(parts) < 4:
        return 'transitional'

    status   = parts[2]
    try:
        restarts = int(parts[3].split('(')[0].strip())   # handles "5 (3m ago)" → 5
    except (ValueError, IndexError):
        restarts = 0

    # States that mean "give it time"
    if status in ('Terminating', 'ContainerCreating', 'PodInitializing',
                  'Init:0/1', 'Init:1/2', 'Pending'):
        return 'transitional'

    # Error states that are not caught by substring check above
    if status in ('Error', 'OOMKilled'):
        return 'crashing'

    # Running/Completed — check readiness
    if '/' in parts[1]:
        ready, total = parts[1].split('/')
        if ready == total:
            return 'healthy'
        # Not yet ready — distinguish "starting" from "crash"
        # If restarts == 0 and status == Running → pod is just starting up
        if status == 'Running' and restarts == 0:
            return 'transitional'
        # Restarts > 0 and not ready → something is wrong
        return 'crashing'

    return 'transitional'

# ─────────────────────────────────────────────
#  NODE 1: OBSERVE
# ─────────────────────────────────────────────
def observe(state: SREState) -> SREState:
    print("\n" + "="*55)
    print("🔍  [OBSERVE] Scanning Worldline payment services...")
    print("="*55)

    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", NS, "--no-headers"],
        capture_output=True, text=True, timeout=30
    )

    if result.returncode != 0:
        print(f"⚠️   kubectl error — is the cluster running? ({result.stderr.strip()})")
        state['issue_detected'] = False
        return state

    crashing_pod  = None
    scenario_type = 'crashloop'

    for line in result.stdout.strip().split('\n'):
        classification = classify_pod(line)
        if classification == 'crashing':
            crashing_pod  = line.split()[0]
            scenario_type = get_scenario_from_line(line)
            break
        # 'transitional' and 'healthy' → keep scanning

    # ── Refine scenario using pod termination reason ─────────────
    # CrashLoopBackOff can mask an OOMKill — check the actual reason
    # stored in the pod's lastState, which persists across restarts.
    if crashing_pod and scenario_type == 'crashloop':
        reason = get_pod_termination_reason(crashing_pod)
        if reason == 'OOMKilled':
            scenario_type = 'oomkilled'

    # ── Scale-to-Zero detection ──────────────────────────────────
    # If no crashing pod was found, check whether any known deployment
    # has been deliberately scaled to 0 replicas (no pods appear at all).
    if not crashing_pod:
        for dep in KNOWN_DEPLOYMENTS:
            scale_check = subprocess.run(
                ["kubectl", "get", "deployment", dep, "-n", NS,
                 "-o", "jsonpath={.spec.replicas}"],
                capture_output=True, text=True, timeout=30
            )
            if scale_check.returncode == 0 and scale_check.stdout.strip() == '0':
                crashing_pod  = f"{dep}-scaled-to-zero"   # synthetic — deployment name derivable
                scenario_type = 'scaled_down'
                break

    if crashing_pod:
        # For real pods: derive from pod name (strip last 2 hash segments)
        # For scaled-to-zero: dep is already known from the loop above
        if scenario_type == 'scaled_down':
            deployment = crashing_pod.replace('-scaled-to-zero', '')
        else:
            deployment = '-'.join(crashing_pod.split('-')[:-2])

        failure_memory[deployment] = failure_memory.get(deployment, 0) + 1
        retries = failure_memory[deployment]

        scenario_label = {
            'crashloop':   'CrashLoopBackOff',
            'scaled_down': 'SCALED_DOWN',
            'imagepull':   'ImagePullBackOff',
            'oomkilled':   'OOMKilled',
        }.get(scenario_type, scenario_type.upper())

        print(f"⚠️   ANOMALY DETECTED → {crashing_pod}")
        print(f"    [{deployment}] has failed {retries} time(s) — scenario: {scenario_label}")

        if scenario_type == 'scaled_down':
            pod_logs = f"Deployment {deployment} has 0 desired replicas — service completely down"
        else:
            logs = subprocess.run(
                ["kubectl", "logs", crashing_pod, "-n", NS, "--tail=30", "--previous"],
                capture_output=True, text=True, timeout=30
            )
            pod_logs = logs.stdout or logs.stderr
            if not pod_logs.strip():
                logs2 = subprocess.run(
                    ["kubectl", "logs", crashing_pod, "-n", NS, "--tail=30"],
                    capture_output=True, text=True, timeout=30
                )
                pod_logs = logs2.stdout or logs2.stderr or "No logs — pod in early crash loop"

        state['pod_name']        = crashing_pod
        state['deployment_name'] = deployment
        state['pod_logs']        = pod_logs
        state['scenario_type']   = scenario_type
        state['issue_detected']  = True
        state['retry_count']     = retries
    else:
        print("✅  All payment services healthy. Watching...")
        state['issue_detected'] = False
        # Reset memory for recovered services
        failure_memory.clear()

    return state

# ─────────────────────────────────────────────
#  NODE 2: REASON  (Gemma3 on-prem)
# ─────────────────────────────────────────────
def reason(state: SREState) -> SREState:
    scenario = state.get('scenario_type', 'crashloop')
    print(f"\n🧠  [REASON] Analysing → {state['pod_name']}  [{scenario.upper()}]")

    # ── Rule 1: Hard escalation after 2+ failures ─────────────────
    if state['retry_count'] >= 2:
        print(f"    ⬆️  Escalating strategy — {state['retry_count']} failed attempts")
        analysis = {
            "root_cause":   "Persistent failure — previous fix insufficient, root cause in deployment spec",
            "severity":     "CRITICAL",
            "remediation":  "rollback",
            "explanation":  "Hard-escalating to rollback to restore last healthy deployment spec",
        }
        state['ai_analysis']        = json.dumps(analysis, indent=2)
        state['remediation_action'] = "rollback"

    # ── Rule 2: Known scenarios — instant rule-based fix, no Gemma3 ──
    elif scenario in ('scaled_down', 'imagepull', 'oomkilled'):
        INSTANT_FIX = {
            'scaled_down': {
                'root_cause':  'Deployment scaled to 0 replicas — no pods running',
                'severity':    'CRITICAL',
                'remediation': 'scale_up',
                'explanation': 'Scale back to healthy replica count immediately',
            },
            'imagepull': {
                'root_cause':  'ImagePullBackOff — bad or non-existent image tag in deployment spec',
                'severity':    'CRITICAL',
                'remediation': 'rollback',
                'explanation': 'Roll back to last known-good image immediately',
            },
            'oomkilled': {
                'root_cause':  'OOMKilled — container exceeds its memory limit',
                'severity':    'HIGH',
                'remediation': 'scale_up',
                'explanation': 'Scale up to distribute memory load; escalate to rollback if it persists',
            },
        }
        print(f"    ⚡ Rule-based diagnosis — skipping Gemma3 (scenario known)")
        analysis = INSTANT_FIX[scenario]
        state['ai_analysis']        = json.dumps(analysis, indent=2)
        state['remediation_action'] = analysis['remediation']

    # ── Rule 3: Unknown crash (crashloop) — ask Gemma3 ────────────
    else:
        print("    (On-prem AI — zero data leaving Worldline infrastructure)")
        prompt = f"""You are a Senior SRE at Worldline, a global payment processing company.
A Kubernetes pod '{state['pod_name']}' is in CrashLoopBackOff.

Analyse ONLY the logs below to determine the root cause and the correct fix.

Pod logs:
{state['pod_logs'][:1500]}

DECISION RULES — apply in order:
1. If logs show a BAD CONFIGURATION (missing file, bad env var, bad mount, bad command, config parse error)
   → use "rollback"  (the spec itself is broken, restarting won't help)
2. If logs show a RESOURCE ISSUE (disk full, quota exceeded, permission denied on data dir)
   → use "delete_pod"  (transient, a fresh pod may get a different node/disk)
3. If logs show a DEPENDENCY ISSUE (connection refused, upstream timeout, DB unreachable)
   → use "scale_up"  (distribute load, pod itself is healthy)
4. If logs are empty or unclear
   → use "delete_pod"  (safe default)

YOUR RESPONSE MUST BE ONLY THIS JSON OBJECT — NO OTHER TEXT, NO MARKDOWN:
{{
  "root_cause": "one short sentence from the logs",
  "severity": "HIGH",
  "remediation": "delete_pod",
  "explanation": "one sentence linking the log evidence to the fix"
}}

The "remediation" field MUST be EXACTLY one of: delete_pod, scale_up, rollback"""

        try:
            response = ollama_client.generate(model='gemma3:1b', prompt=prompt)
            text = response['response'].strip()
        except Exception as e:
            print(f"    ⚠️  Ollama unreachable ({e}) — using safe default action")
            text = ""

        try:
            start = text.find('{')
            end   = text.rfind('}') + 1
            analysis = json.loads(text[start:end]) if start >= 0 and end > start else {}
        except Exception:
            analysis = {}

        analysis.setdefault('root_cause',  'Unexpected pod failure')
        analysis.setdefault('severity',    'HIGH')
        analysis.setdefault('remediation', 'delete_pod')
        analysis.setdefault('explanation', 'Restarting pod to restore payment service')

        # Normalize — Gemma3 sometimes returns a full sentence instead of the token
        VALID_ACTIONS = {'delete_pod', 'scale_up', 'rollback'}
        raw_action = str(analysis['remediation']).lower()
        if raw_action not in VALID_ACTIONS:
            normalized = 'delete_pod'
            for valid in VALID_ACTIONS:
                if valid in raw_action:
                    normalized = valid
                    break
            print(f"    ⚠️  LLM returned '{analysis['remediation'][:40]}' → normalized to '{normalized}'")
            analysis['remediation'] = normalized

        state['ai_analysis']        = json.dumps(analysis, indent=2)
        state['remediation_action'] = analysis['remediation']

    action = json.loads(state['ai_analysis'])
    source = "⚡ RULE-BASED" if scenario in ('scaled_down', 'imagepull', 'oomkilled') and state['retry_count'] < 2 else "🧠 Gemma3:1b" if scenario == 'crashloop' and state['retry_count'] < 2 else "⬆️  ESCALATION"
    print(f"\n┌─ DIAGNOSIS [{source}] {'─' * 30}┐")
    print(f"│ Scenario   : {scenario.upper():<50} │")
    print(f"│ Root cause : {action['root_cause'][:50]:<50} │")
    print(f"│ Severity   : {action['severity']:<50} │")
    print(f"│ Action     : {action['remediation']:<50} │")
    print(f"│ Reasoning  : {action['explanation'][:50]:<50} │")
    print(f"└{'─' * 65}┘")

    return state

# ─────────────────────────────────────────────
#  NODE 3: REMEDIATE
# ─────────────────────────────────────────────
def remediate(state: SREState) -> SREState:
    action     = state['remediation_action']
    pod        = state['pod_name']
    scenario   = state.get('scenario_type', 'crashloop')
    deployment = state['deployment_name']   # always the real k8s deployment name

    print(f"\n🔧  [REMEDIATE] Executing '{action}' on {deployment}  [scenario: {scenario.upper()}]...")

    if action == 'delete_pod':
        # Only valid for real pods, not the synthetic scaled-to-zero marker
        if scenario != 'scaled_down':
            subprocess.run(
                ["kubectl", "delete", "pod", pod, "-n", NS,
                 "--grace-period=0", "--force"],
                capture_output=True, text=True, timeout=30
            )
            print("    → Pod deleted. Kubernetes is self-healing...")

    elif action == 'scale_up':
        # scale_to_zero → restore to 2 replicas (makes the scale-up visually clear)
        # oomkilled     → scale to 2 (distributes load; escalates to rollback if OOM persists)
        target_replicas = 2
        result = subprocess.run(
            ["kubectl", "scale", "deployment", deployment,
             f"--replicas={target_replicas}", "-n", NS],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"    → Scaled {deployment} to {target_replicas} replicas")
        else:
            print(f"    ❌ Scale failed: {result.stderr.strip()}")

    elif action == 'rollback':
        result = subprocess.run(
            ["kubectl", "rollout", "undo", f"deployment/{deployment}", "-n", NS],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"    → Rolled back {deployment} to last healthy spec")
            print(f"    → {result.stdout.strip()}")
            # Clear failure memory after successful rollback
            failure_memory[deployment] = 0
        else:
            print(f"    ❌ Rollback failed: {result.stderr.strip()}")
            print(f"    → Falling back to pod delete...")
            subprocess.run(
                ["kubectl", "delete", "pod", pod, "-n", NS,
                 "--grace-period=0", "--force"],
                capture_output=True, text=True, timeout=30
            )

    else:
        # LLM returned an unrecognised action — safe fallback
        print(f"    ⚠️  Unknown action '{action}' from LLM — defaulting to delete_pod")
        subprocess.run(
            ["kubectl", "delete", "pod", pod, "-n", NS,
             "--grace-period=0", "--force"],
            capture_output=True, text=True, timeout=30
        )
        print("    → Pod deleted. Kubernetes is self-healing...")

    state['remediation_done'] = True
    print("    ⏳ Waiting for Kubernetes to converge...")
    time.sleep(REMEDIATE_WAIT_S)
    return state

# ─────────────────────────────────────────────
#  NODE 4: VERIFY
# ─────────────────────────────────────────────
def verify(state: SREState) -> SREState:
    print(f"\n✔️   [VERIFY] Confirming payment service recovery...")

    # Poll up to VERIFY_MAX_ATTEMPTS × VERIFY_POLL_S seconds
    all_healthy = False

    for attempt in range(1, VERIFY_MAX_ATTEMPTS + 1):
        time.sleep(VERIFY_POLL_S)

        # ── Scale-to-zero: verify by checking .spec.replicas, not pod list ──
        if state.get('scenario_type') == 'scaled_down':
            dep = state['deployment_name']
            check = subprocess.run(
                ["kubectl", "get", "deployment", dep, "-n", NS,
                 "-o", "jsonpath={.spec.replicas}"],
                capture_output=True, text=True, timeout=30
            )
            replicas = check.stdout.strip()
            ready_check = subprocess.run(
                ["kubectl", "get", "deployment", dep, "-n", NS,
                 "-o", "jsonpath={.status.readyReplicas}"],
                capture_output=True, text=True, timeout=30
            )
            ready = ready_check.stdout.strip() or '0'
            if replicas != '0' and ready != '0':
                print(f"    ✅ {dep} is back up — {ready}/{replicas} replicas ready")
                all_healthy = True
                break
            else:
                print(f"    [!] {dep}: {ready}/{replicas} ready (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")
            continue

        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", NS, "--no-headers"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0 or not result.stdout.strip():
            print(f"    [!] kubectl error during verify (attempt {attempt}) — retrying...")
            continue

        lines = [l for l in result.stdout.strip().split('\n') if l]
        classifications = [classify_pod(l) for l in lines]

        if any(c == 'crashing' for c in classifications):
            print(f"    [!] Unhealthy pods still detected (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")
            continue

        if any(c == 'transitional' for c in classifications):
            print(f"    ... Pods still converging... (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")
            continue

        # All pods look healthy — confirm stability before declaring success
        print(f"    ✅ Pods look healthy — stability check in {VERIFY_STABILITY_S}s...")
        time.sleep(VERIFY_STABILITY_S)
        result2 = subprocess.run(
            ["kubectl", "get", "pods", "-n", NS, "--no-headers"],
            capture_output=True, text=True, timeout=30
        )
        if result2.returncode != 0 or not result2.stdout.strip():
            print(f"    [!] Stability check: kubectl error — not marking as resolved")
            continue

        lines2 = [l for l in result2.stdout.strip().split('\n') if l]
        classifications2 = [classify_pod(l) for l in lines2]

        if any(c == 'crashing' for c in classifications2):
            print(f"    [!] Stability check FAILED — pod crashed again (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")
            continue
        if any(c == 'transitional' for c in classifications2):
            print(f"    ... Stability check: still converging (attempt {attempt}/{VERIFY_MAX_ATTEMPTS})")
            continue

        # Passed both checks — genuinely stable
        all_healthy = True
        break

    state['verified'] = all_healthy

    if all_healthy:
        deployment = state['deployment_name']
        failure_memory[deployment] = 0
        report = f"""
╔══════════════════════════════════════════════════════╗
║          INCIDENT AUTO-RESOLVED  ✅                   ║
╠══════════════════════════════════════════════════════╣
║  Service   : {state['pod_name']:<36} ║
║  AI Model  : Gemma3:1b (On-Prem, Zero Data Risk)     ║
║  Action    : {state['remediation_action']:<36} ║
║  MTTR      : < 90 seconds                            ║
║  Engineers : 0 paged  🎉                             ║
║  Status    : All payment services OPERATIONAL        ║
╚══════════════════════════════════════════════════════╝"""
        print(report)
        state['incident_report'] = report
    else:
        print("⚠️   Recovery incomplete — agent will retry with escalated strategy next cycle...")
        state['incident_report'] = "RETRYING"

    return state

# ─────────────────────────────────────────────
#  ROUTING
# ─────────────────────────────────────────────
def route_after_observe(state: SREState) -> str:
    return "reason" if state['issue_detected'] else END

# ─────────────────────────────────────────────
#  BUILD LANGGRAPH
# ─────────────────────────────────────────────
workflow = StateGraph(SREState)
workflow.add_node("observe",   observe)
workflow.add_node("reason",    reason)
workflow.add_node("remediate", remediate)
workflow.add_node("verify",    verify)

workflow.set_entry_point("observe")
workflow.add_conditional_edges("observe", route_after_observe)
workflow.add_edge("reason",    "remediate")
workflow.add_edge("remediate", "verify")
workflow.add_edge("verify",    END)

agent = workflow.compile()

# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   🚀 AGENTIC SRE — WORLDLINE PAYMENT GUARDIAN        ║
║      LangGraph + Gemma3:1b  (100% On-Prem)           ║
║      Observe → Reason → Remediate → Verify           ║
║      Rule-based fast path + Gemma3 log analysis      ║
╚══════════════════════════════════════════════════════╝
""")

    cycle = 0
    while True:
        cycle += 1
        print(f"\n[Cycle {cycle}] {time.strftime('%H:%M:%S')} — Running health check...")

        initial: SREState = {
            "pod_name":           "",
            "namespace":          NS,
            "pod_logs":           "",
            "issue_detected":     False,
            "scenario_type":      "",
            "deployment_name":    "",
            "ai_analysis":        "",
            "remediation_action": "",
            "remediation_done":   False,
            "verified":           False,
            "incident_report":    "",
            "retry_count":        0
        }

        try:
            result = agent.invoke(initial)
        except Exception as e:
            print(f"\n❌  [ERROR] Agent cycle failed: {e}")
            print("    Continuing to next cycle...")
            time.sleep(MAIN_LOOP_WAIT_S)
            continue

        if result['issue_detected'] and result.get('verified'):
            print(f"\n✅  System stable. Resuming monitoring (cycle {cycle})...")
        elif result['issue_detected'] and not result.get('verified'):
            print(f"\n🔄  Escalating strategy on next cycle...")

        time.sleep(MAIN_LOOP_WAIT_S)
