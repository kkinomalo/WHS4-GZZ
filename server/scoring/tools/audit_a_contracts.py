"""Read-only A-side event audit; never contacts a server or opens the game.

Run on Windows from any directory with Python 3.10+:
  python -B server/scoring/tools/audit_a_contracts.py
  python -B server/scoring/tools/audit_a_contracts.py --examples

Replay examples are observations from older captures, not proof of delivery.
Synthetic probes exercise the current adapters with supplied values/mocks.
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
import io
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from shared.errors import ValidationError
from shared.schema import decode_event, encode_event, validate_event_id

MODULES = (
    "external_access", "module_integrity", "localguard_yara", "localguard_executable_hash",
    "filesystem", "injection", "value_tamper", "overlay_hook",
    "godmode_runtime", "noclip_runtime", "aimbot_runtime",
    "whistle", "whistle_rpc", "hide_anywhere",
)
EXTENDED_MODULES = set(MODULES) - {
    "external_access", "module_integrity", "localguard_yara", "localguard_executable_hash", "hide_anywhere",
}


def load(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def scan_replays(result_adapter):
    counts = {module: Counter() for module in MODULES}
    examples = {}
    for path in sorted((ROOT / "ReplayAnalyzer/replay-data").rglob("events.jsonl")):
        if "raw" in path.relative_to(ROOT).parts:
            continue
        for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            module = event.get("module")
            if module not in counts:
                continue
            counter = counts[module]
            counter["rows"] += 1
            # Adapt only the emitter that actually uses to_shared_event().
            adapted = result_adapter.to_shared_event(event) if module in EXTENDED_MODULES else event
            status = adapted.get("evidence", {}).get("status")
            kind = "positive" if event["raw_score"] > 0 else (
                "unavailable" if status in ("ERROR", "OFFLINE") else "zero")
            counter[kind] += 1
            try:
                decode_event(line.encode("utf-8"))
                counter["original_valid"] += 1
            except ValidationError:
                counter["original_invalid"] += 1
            try:
                encode_event(adapted)
                counter["adapted_valid"] += 1
            except ValidationError:
                counter["adapted_invalid"] += 1
            examples.setdefault((module, kind), {
                "source": path.relative_to(ROOT).as_posix(), "line": line_no,
                "origin": "replay_capture", "central_adapter_applied": module in EXTENDED_MODULES,
                "event": adapted,
            })
    return counts, examples


def probe_external_access():
    from client.LocalGuard.external_access.common.models import ArtifactInfo
    from client.LocalGuard.external_access.process_access.detector import ProcessAccessDetector
    from client.LocalGuard.external_access.process_access.models import ExternalHandleObservation, ScanContext

    detector = ProcessAccessDetector(environment={"USERPROFILE": r"C:\Users\audit"})
    ctx = ScanContext("audit_synthetic", "audit_player", 1000)
    read_only = ExternalHandleObservation(1234, "example.exe", None, 0x10)
    assert detector.evaluate(read_only, ctx) is None
    path = Path(r"C:\Users\audit\Desktop\example.exe")
    artifact = ArtifactInfo(path, "a" * 64, "invalid", None)
    risky = ExternalHandleObservation(1234, "example.exe", path, 0x2A, artifact)
    event = detector.evaluate(risky, ctx)
    assert event["module"] == "external_access" and event["raw_score"] == 10
    encode_event(event)
    return {"vm_read_only_event": None, "maximum_score_event": event}


def probe_hide():
    detector = load("audit_hide_detector", "client/detectors/Hide_anywhere_detector/mecha_detector_v9.py")
    bridge_mod = load("audit_hide_bridge", "client/detectors/Hide_anywhere_detector/server_bridge.py")
    events = [detector.make_common_event("audit_synthetic", "audit_player", "hide_anywhere", 1000, values)
              for values in ({}, detector.EXPECTED)]
    for event in events:
        encode_event(event)
    assert [event["raw_score"] for event in events] == [0, 3]
    bridge = bridge_mod.ServerBridge.__new__(bridge_mod.ServerBridge)
    bridge.run_id, bridge.sequence = "a" * 32, 0
    records = []
    def check_send(event, *, event_id):
        encode_event(event)
        validate_event_id(event_id)
    bridge.api = SimpleNamespace(send_detection=check_send)
    bridge.emit = lambda kind, **data: records.append({"kind": kind, **data})
    bridge.send(events[1])
    assert records[0]["kind"] == "server_enqueue_error"
    assert records[0]["error_type"] == "ValidationError"
    return {"events": events, "actual_bridge_result": records[0]}


def probe_runtime_scores(result_adapter):
    sys.path.insert(0, str(ROOT / "client/LocalGuard/memory_integrity"))
    class Memory:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read_pointer(self, _address): return 0x2000
        def read_uint8(self, _address): return 0x23
        def read_double(self, _address): return 0.0
    locator = SimpleNamespace(locate=lambda: 0x1000, get_controller=lambda: 0x3000)
    evidence = SimpleNamespace(target="ControlRotation", observed="supplied", expected="supplied",
                               event_type="VALUE_PATTERN", reason="synthetic rule hit", details={})
    results = {}
    for name in ("noclip_runtime", "godmode_runtime", "aimbot_runtime"):
        module = load("audit_" + name, "client/LocalGuard/memory_integrity/detectors/" + name + ".py")
        with patch.object(module, "ProcessMemory", return_value=Memory()), \
             patch.object(module, "PawnLocator", return_value=locator):
            if name == "godmode_runtime":
                with patch.object(module, "_read_values", return_value={
                    "is_hunter": False, "invincible": True, "dead": False,
                    "health": 100, "max_health": 100, "change_before_health": 100,
                }):
                    result = module.scan()
            elif name == "aimbot_runtime":
                times = iter((0, .1, .1, .2, .3, 4))
                with patch.object(module, "time", SimpleNamespace(perf_counter=lambda: next(times), sleep=lambda _s: None)), \
                     patch.object(module, "AimbotMemoryRules", return_value=SimpleNamespace(
                         MIN_WINDOW_SAMPLES=1, evaluate=lambda *_args: [evidence])):
                    result = module.scan()
            else:
                result = module.scan()
        assert result.reasons and result.evidence and not result.error
        event = result_adapter.to_shared_event(result_adapter.to_team_event(
            result, "audit_synthetic", timestamp_ms=1000, player_id="audit_player"))
        encode_event(event)
        assert event["raw_score"] == 0
        results[name] = {"raw_score": event["raw_score"], "status": event["evidence"]["status"],
                         "reasons": event["reasons"], "evidence_count": len(result.evidence),
                         "passes_positive_send_gate": event["raw_score"] > 0}
    return results


def probe_input_signature_gate():
    replay = load("audit_input_replay", "client/LocalGuard/input_signature/replay_events.py")
    session = replay.ReplaySession.__new__(replay.ReplaySession)
    session.lock, session.closed = threading.RLock(), False
    session.elapsed = lambda: 1000
    session.manifest = {"session_id": "audit_synthetic", "player_id": "audit_player"}
    session.file, session.counts, session.labelled_player_events = io.StringIO(), Counter(), 0
    forwarded = []
    session.event_sink = forwarded.append
    for score in (0, 3):
        event = session.emit("localguard_yara", "audit_player", {}, [], score)
        encode_event(event)
    assert len(session.file.getvalue().splitlines()) == 2 and len(forwarded) == 1
    return {"local_events": 2, "central_events": 1, "central_score": forwarded[0]["raw_score"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--examples", action="store_true", help="Print first replay example per module/kind")
    args = parser.parse_args()
    result_adapter = load("audit_result_adapter", "client/LocalGuard/memory_integrity/core/result.py")
    counts, examples = scan_replays(result_adapter)
    probes = {
        "external_access_synthetic": probe_external_access(),
        "hide_synthetic": probe_hide(),
        "runtime_synthetic": probe_runtime_scores(result_adapter),
        "input_signature_send_gate": probe_input_signature_gate(),
    }
    for name, counter in counts.items():
        print(json.dumps({"module": name, "counts": dict(counter), "examples": {
            kind: {key: value for key, value in examples[(name, kind)].items() if key != "event"}
            for kind in ("zero", "positive", "unavailable") if (name, kind) in examples
        }}, ensure_ascii=True))
    print(json.dumps({"probes": probes}, ensure_ascii=True))
    if args.examples:
        for example in examples.values():
            print(json.dumps(example, ensure_ascii=True))


if __name__ == "__main__":
    main()
