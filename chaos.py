"""
chaos.py — Inject 6 different faults into the payment cluster.
Run in a SEPARATE terminal while agent.py is running.
Usage: python chaos.py
"""
import subprocess

NS         = "techforum-demo"
DEPLOYMENT = "fraud-detection"


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _kubectl_patch(patch: str) -> bool:
    """Apply a strategic merge patch to the fraud-detection deployment."""
    result = subprocess.run(
        ["kubectl", "patch", "deployment", DEPLOYMENT, "-n", NS, "--patch", patch],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"❌  Patch failed: {result.stderr.strip()}")
        return False
    return True


def _wait_for_rollout(timeout: str = "90s") -> None:
    subprocess.run(
        ["kubectl", "rollout", "status", f"deployment/{DEPLOYMENT}",
         "-n", NS, f"--timeout={timeout}"],
        text=True
    )


# ─────────────────────────────────────────────
#  SCENARIO 1 — CrashLoopBackOff
#  How: bad command → exit 1
#  Agent detects: CrashLoopBackOff status
#  Fix: delete_pod → fails → escalate to rollback
# ─────────────────────────────────────────────

def inject_crashloop() -> None:
    """Inject a CrashLoopBackOff by patching the container command to exit 1."""
    print("""
╔══════════════════════════════════════════════════╗
║  💥  SCENARIO 1 — CrashLoopBackOff              ║
╠══════════════════════════════════════════════════╣
║  Method : Container command → exit 1             ║
║  Signal : CrashLoopBackOff                       ║
║  Fix    : delete_pod → escalate to rollback      ║
╚══════════════════════════════════════════════════╝
""")
    patch = (
        '{"spec":{"template":{"spec":{"containers":[{'
        '"name":"fraud-detection",'
        '"image":"nginx:alpine",'
        '"command":["sh","-c",'
        '"echo FRAUD-DETECTION CRITICAL FAILURE: disk quota exceeded && exit 1"'
        ']}]}}}}'
    )
    if _kubectl_patch(patch):
        print("💥  fraud-detection → CrashLoopBackOff")
        print("    Watch the agent detect and fix this...\n")


# ─────────────────────────────────────────────
#  SCENARIO 2 — Scale-to-Zero
#  How: replicas=0
#  Agent detects: 0 desired replicas (no pods at all)
#  Fix: scale_up (immediate rule-based, no Gemma3)
# ─────────────────────────────────────────────

def inject_scale_zero() -> None:
    """Scale the deployment to 0 replicas — payment service completely down."""
    print("""
╔══════════════════════════════════════════════════╗
║  💥  SCENARIO 2 — Scale-to-Zero                 ║
╠══════════════════════════════════════════════════╣
║  Method : kubectl scale --replicas=0             ║
║  Signal : SCALED_DOWN (no pods running)          ║
║  Fix    : scale_up (rule-based, instant)         ║
╚══════════════════════════════════════════════════╝
""")
    result = subprocess.run(
        ["kubectl", "scale", "deployment", DEPLOYMENT, "--replicas=0", "-n", NS],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("💥  fraud-detection → 0 replicas (completely down)")
        print("    Watch the agent detect and fix this...\n")
    else:
        print(f"❌  {result.stderr.strip()}")


# ─────────────────────────────────────────────
#  SCENARIO 3 — ImagePullBackOff
#  How: patch with non-existent image tag
#  Agent detects: ImagePullBackOff / ErrImagePull status
#  Fix: rollback (immediate rule-based, no Gemma3)
# ─────────────────────────────────────────────

def inject_imagepull() -> None:
    """Patch to a non-existent image tag — causes ImagePullBackOff."""
    print("""
╔══════════════════════════════════════════════════╗
║  �  SCENARIO 3 — ImagePullBackOff              ║
╠══════════════════════════════════════════════════╣
║  Method : Bad image tag → nginx:broken-tag-9999  ║
║  Signal : ImagePullBackOff / ErrImagePull        ║
║  Fix    : rollback (rule-based, instant)         ║
╚══════════════════════════════════════════════════╝
""")
    patch = (
        '{"spec":{"template":{"spec":{"containers":[{'
        '"name":"fraud-detection",'
        '"image":"nginx:broken-tag-9999",'
        '"command":null'
        '}]}}}}'
    )
    if _kubectl_patch(patch):
        print("💥  fraud-detection → ImagePullBackOff (bad image tag)")
        print("    Watch the agent detect and fix this...\n")


# ─────────────────────────────────────────────
#  SCENARIO 4 — OOMKilled
#  How: memory limit = 1Mi (too small for nginx)
#  Agent detects: OOMKilled status
#  Fix: scale_up (rule-based) → OOMKills again → escalate to rollback
# ─────────────────────────────────────────────

def inject_oom() -> None:
    """Set a 1Mi memory limit — nginx will be OOMKilled immediately."""
    print("""
╔══════════════════════════════════════════════════╗
║  💥  SCENARIO 4 — OOMKilled                     ║
╠══════════════════════════════════════════════════╣
║  Method : Memory limit → 1Mi (way too low)       ║
║  Signal : OOMKilled                              ║
║  Fix    : scale_up → OOMKills again → rollback   ║
╚══════════════════════════════════════════════════╝
""")
    patch = (
        '{"spec":{"template":{"spec":{"containers":[{'
        '"name":"fraud-detection",'
        '"image":"nginx:alpine",'
        '"command":null,'
        '"resources":{"limits":{"memory":"1Mi"}}'
        '}]}}}}'
    )
    if _kubectl_patch(patch):
        print("💥  fraud-detection → 1Mi memory limit (will OOMKill)")
        print("    Watch the agent detect and fix this...\n")


# ─────────────────────────────────────────────
#  SCENARIO 5 — Node Taint (IRREVERSIBLE from agent POV)
#  How: taint all nodes with NoSchedule
#  Agent detects: pods stuck in Pending (can't be scheduled)
#  Why irreversible: fix requires "kubectl taint" which is in IRREVERSIBLE_PATTERNS
#  Agent tries all reversible commands — all fail (pod keeps going Pending)
#  Then escalates with the taint-removal command in "Suggested Next Steps"
#  Manual fix: kubectl taint nodes --all sre-chaos=unschedulable:NoSchedule-
# ─────────────────────────────────────────────

def inject_node_taint() -> None:
    """Taint all cluster nodes with NoSchedule — pods can't be scheduled, stuck in Pending."""
    print("""
╔══════════════════════════════════════════════════╗
║  💥  SCENARIO 5 — Node Taint (IRREVERSIBLE)     ║
╠══════════════════════════════════════════════════╣
║  Method : kubectl taint nodes --all NoSchedule   ║
║  Signal : Pods stuck in Pending state            ║
║  Why irreversible: fix = kubectl taint (blocked) ║
║  Expected: agent tries 5 times, all fail,        ║
║            escalates with taint-removal command  ║
╚══════════════════════════════════════════════════╝
""")
    # Step 0: Strip any existing tolerations from the deployment so the pod
    # cannot bypass the taint (agent may have patched tolerations previously)
    print("    🧹 Removing any existing tolerations from deployment spec...")
    subprocess.run(
        ["kubectl", "patch", "deployment", DEPLOYMENT, "-n", NS,
         "--type=json",
         "-p", '[{"op":"remove","path":"/spec/template/spec/tolerations"}]'],
        capture_output=True, text=True   # ignore error if no tolerations exist
    )

    # Step 1: Apply taint to ALL nodes FIRST
    nodes_r = subprocess.run(
        ["kubectl", "get", "nodes", "--no-headers",
         "-o", "custom-columns=NAME:.metadata.name"],
        capture_output=True, text=True
    )
    nodes = [n.strip() for n in nodes_r.stdout.strip().splitlines() if n.strip()]
    if not nodes:
        print("❌  No nodes found")
        return

    tainted = 0
    for node in nodes:
        r = subprocess.run(
            ["kubectl", "taint", "node", node,
             "sre-chaos=unschedulable:NoSchedule", "--overwrite"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            tainted += 1
            print(f"    🔒 Node tainted: {node}")
        else:
            print(f"    ⚠️  Could not taint {node}: {r.stderr.strip()}")

    if tainted == 0:
        print("❌  No nodes could be tainted — aborting")
        return

    # Step 2: Scale bounce (0→1) to force a fresh pod that CANNOT schedule
    print(f"\n    Bouncing deployment replicas (0 → 1) to force a Pending pod...")
    subprocess.run(
        ["kubectl", "scale", "deployment", DEPLOYMENT, "--replicas=0", "-n", NS],
        capture_output=True, text=True
    )
    subprocess.run(
        ["kubectl", "wait", "--for=delete", "pod",
         "-l", f"app={DEPLOYMENT}", "-n", NS, "--timeout=30s"],
        capture_output=True, text=True
    )
    subprocess.run(
        ["kubectl", "scale", "deployment", DEPLOYMENT, "--replicas=1", "-n", NS],
        capture_output=True, text=True
    )

    # Step 3: Verify the pod is Pending
    import time as _time
    _time.sleep(4)
    check = subprocess.run(
        ["kubectl", "get", "pods", "-n", NS, "-l", f"app={DEPLOYMENT}", "--no-headers"],
        capture_output=True, text=True
    )
    print(f"\n    Current pod status:\n    {check.stdout.strip()}")

    if "Pending" in check.stdout:
        print(f"\n💥  {tainted} node(s) tainted — fraud-detection pod is Pending (unschedulable)")
        print("    The agent CANNOT fix this with reversible commands")
        print("    Watch it try 5 times then escalate to human...\n")
        print("    ⚠️  To manually restore: run option 7 in this menu\n")
    else:
        print("\n⚠️  Pod is not Pending — check if deployment still has tolerations:")
        print("    kubectl get deployment fraud-detection -n techforum-demo -o jsonpath='{.spec.template.spec.tolerations}'")


# ─────────────────────────────────────────────
#  SCENARIO 6 — Missing Required Secret (TRULY IRREVERSIBLE)
#
#  How it works:
#    1. Create a secret "fraud-db-credentials" with DB credentials
#    2. Patch deployment to load it via envFrom (pod works fine)
#    3. DELETE the secret — pod goes CreateContainerConfigError
#
#  Why the agent CANNOT fix it:
#    - kubectl delete pod  → new pod also fails (secret still missing)
#    - kubectl rollout restart → same
#    - kubectl scale 0→1  → same
#    - kubectl rollout undo → "no rollout history" (fresh deploy from restore)
#    - kubectl set image  → doesn't recreate a missing secret
#    - kubectl set env    → can add env vars but NOT remove envFrom reference
#    - kubectl patch      → BLOCKED (in IRREVERSIBLE_PATTERNS)
#    - kubectl create     → BLOCKED
#
#  Fix requires: kubectl create secret generic fraud-db-credentials ...
#  Manual restore: run option 7 in this menu
# ─────────────────────────────────────────────

SECRET_NAME = "fraud-db-credentials"

def inject_missing_secret() -> None:
    """Delete a secret that the deployment requires — causes CreateContainerConfigError."""
    import time as _time

    print("""
╔══════════════════════════════════════════════════╗
║  💥  SCENARIO 6 — Missing Required Secret       ║
╠══════════════════════════════════════════════════╣
║  Method : Delete envFrom secret after binding    ║
║  Signal : CreateContainerConfigError             ║
║  Why unfixable: fix = kubectl create secret      ║
║                 kubectl patch = BLOCKED          ║
║  Expected: agent tries 5 times → all fail →     ║
║            escalates with exact fix command      ║
╚══════════════════════════════════════════════════╝
""")
    # Step 1 — create the secret the deployment will depend on
    r = subprocess.run(
        ["kubectl", "create", "secret", "generic", SECRET_NAME,
         "--from-literal=DB_HOST=postgres.worldline.internal",
         "--from-literal=DB_PASSWORD=s3cr3t-payment-key-2026",
         "-n", NS],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        if "already exists" in r.stderr:
            print(f"    ℹ️  Secret '{SECRET_NAME}' already exists — reusing")
        else:
            print(f"❌  Could not create secret: {r.stderr.strip()}")
            return
    else:
        print(f"    🔑 Secret '{SECRET_NAME}' created")

    # Step 2 — patch deployment to load secret as environment variables
    # Must include "image" field — Kubernetes strategic merge patch requires it
    # when updating the containers list, even if we're not changing the image.
    patch = (
        '{"spec":{"template":{"spec":{"containers":[{'
        '"name":"fraud-detection",'
        '"image":"nginx:alpine",'
        f'"envFrom":[{{"secretRef":{{"name":"{SECRET_NAME}"}}}}]'
        '}]}}}}'
    )
    if not _kubectl_patch(patch):
        print("❌  Could not patch deployment — aborting")
        return
    print(f"    🔗 Deployment patched: envFrom → '{SECRET_NAME}'")

    # Step 3 — wait until pod is Running and healthy with the secret
    print("    ⏳ Waiting for deployment to use the secret...")
    _wait_for_rollout("90s")

    # Step 4 — delete the secret (THIS is the chaos injection)
    r = subprocess.run(
        ["kubectl", "delete", "secret", SECRET_NAME, "-n", NS],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        print(f"    💣 Secret '{SECRET_NAME}' DELETED!")
    else:
        print(f"    ⚠️  Delete failed: {r.stderr.strip()}")

    # Step 5 — force a pod restart so it immediately hits the error
    subprocess.run(
        ["kubectl", "rollout", "restart", f"deployment/{DEPLOYMENT}", "-n", NS],
        capture_output=True, text=True
    )
    _time.sleep(6)

    # Show current state
    check = subprocess.run(
        ["kubectl", "get", "pods", "-n", NS, "-l", f"app={DEPLOYMENT}", "--no-headers"],
        capture_output=True, text=True
    )
    print(f"\n    Current pod status:\n    {check.stdout.strip()}")

    if any(s in check.stdout for s in ["Error", "Pending", "0/1"]):
        print(f"""
💥  fraud-detection is failing — secret '{SECRET_NAME}' is missing

    The agent CANNOT fix this with any reversible command.
    Watch it try 5 times, diagnose correctly, then escalate.

    ⚡ Manual fix (what the escalation report will suggest):
       kubectl create secret generic {SECRET_NAME} \\
         --from-literal=DB_HOST=postgres.worldline.internal \\
         --from-literal=DB_PASSWORD=s3cr3t-payment-key-2026 \\
         -n {NS}

    ⚠️  To fully restore: run option 7 in this menu
""")
    else:
        print("\n⏳  Pod may need a few more seconds to enter error state")


# ─────────────────────────────────────────────
#  OPTION 7 — Restore ALL to healthy
#  Covers all 6 scenarios in one shot
# ─────────────────────────────────────────────

def restore() -> None:
    """Restore fraud-detection and cluster to a fully clean healthy state."""
    print("\n🔁  Restoring fraud-detection to fully healthy state...")

    # Step 1: Remove node taints (scenario 5)
    nodes_r = subprocess.run(
        ["kubectl", "get", "nodes", "--no-headers",
         "-o", "custom-columns=NAME:.metadata.name"],
        capture_output=True, text=True
    )
    nodes = [n.strip() for n in nodes_r.stdout.strip().splitlines() if n.strip()]
    untainted = 0
    for node in nodes:
        r = subprocess.run(
            ["kubectl", "taint", "node", node,
             "sre-chaos=unschedulable:NoSchedule-"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            untainted += 1
            print(f"    🔓 Node taint removed: {node}")
    if untainted > 0:
        print(f"    ✅ Removed taint from {untainted} node(s)")
    else:
        print("    ℹ️  No sre-chaos taint found on nodes (already clean)")

    # Step 2: Delete the scenario-6 secret if it exists (scenario 6)
    r = subprocess.run(
        ["kubectl", "delete", "secret", SECRET_NAME, "-n", NS, "--ignore-not-found"],
        capture_output=True, text=True
    )
    if "deleted" in r.stdout:
        print(f"    🗑️  Secret '{SECRET_NAME}' cleaned up")

    # Step 3: Delete deployment entirely — removes ALL spec mutations (all scenarios)
    subprocess.run(
        ["kubectl", "delete", "deployment", DEPLOYMENT, "-n", NS, "--ignore-not-found"],
        capture_output=True, text=True
    )

    # Wait for all old pods to fully terminate
    subprocess.run(
        ["kubectl", "wait", "--for=delete", "pod",
         "-l", f"app={DEPLOYMENT}", "-n", NS, "--timeout=60s"],
        capture_output=True, text=True
    )

    # Step 4: Recreate from scratch — clean: 1 container, no limits, no command, no envFrom
    result = subprocess.run(
        ["kubectl", "create", "deployment", DEPLOYMENT,
         "--image=nginx:alpine", "--replicas=1", "-n", NS],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"❌  Recreate failed: {result.stderr.strip()}")
        return

    print("    Waiting for rollout...")
    _wait_for_rollout()
    print("✅  fraud-detection is fully restored and healthy\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

SCENARIOS = {
    "1": ("CrashLoopBackOff  — bad command → exit 1",                   inject_crashloop),
    "2": ("Scale-to-Zero     — replicas=0",                             inject_scale_zero),
    "3": ("ImagePullBackOff  — bad image tag",                          inject_imagepull),
    "4": ("OOMKilled         — memory limit: 1Mi",                      inject_oom),
    "5": ("Node Taint        — NoSchedule on all nodes [IRREVERSIBLE]",  inject_node_taint),
    "6": ("Missing Secret    — deleted envFrom secret   [IRREVERSIBLE]", inject_missing_secret),
    "7": ("Restore to healthy — resets ALL scenarios",                   restore),
}

if __name__ == "__main__":
    print("🎯  PageZero — Chaos Injector")
    print("    Simulating real Worldline P1 payment outages\n")
    print("Choose chaos scenario:")
    for key, (label, _) in SCENARIOS.items():
        if key == "7":
            prefix = "✅"
        elif key in ("5", "6"):
            prefix = "🔒"
        else:
            prefix = "💥"
        print(f"  {key}. {prefix}  {label}")

    choice = input("\nEnter choice (1-7): ").strip()

    if choice in SCENARIOS:
        SCENARIOS[choice][1]()
    else:
        print("Invalid choice — enter 1 to 7")
