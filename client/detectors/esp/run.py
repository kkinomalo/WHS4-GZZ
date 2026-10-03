from __future__ import annotations

import argparse
from dataclasses import replace
import json
import signal
import sys
import time
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from anti_esp.config import load_settings
from anti_esp.controller import AntiEspController
from anti_esp.shared_transport import SharedEventSink
from shared.errors import SharedError


PROJECT_ROOT = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Real-time, evidence-based Anti-ESP review monitor"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "config.json",
        help="configuration JSON (defaults to config.json, then config.example.json)",
    )
    parser.add_argument(
        "--session-id",
        default=None,
        help="team test name, for example normal_001 or esp_001",
    )
    parser.add_argument(
        "--player-id",
        default=None,
        help="team player identifier written to common detection events",
    )
    parser.add_argument(
        "--t0",
        type=float,
        default=None,
        help="launcher session start as Unix epoch seconds",
    )
    parser.add_argument(
        "--central-telemetry",
        choices=("managed", "off"),
        default="managed",
        help="queue common events through shared 0.2.0 or keep local logs only",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="test label such as normal or esp",
    )
    parser.add_argument(
        "--cheat-on-ms",
        type=int,
        default=None,
        help="optional test annotation: cheat activation time in session ms",
    )
    parser.add_argument(
        "--cheat-off-ms",
        type=int,
        default=None,
        help="optional test annotation: cheat deactivation time in session ms",
    )
    parser.add_argument("--headless", action="store_true", help="run without the Qt UI")
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        help="optional headless run duration in seconds",
    )
    parser.add_argument(
        "--export-on-exit",
        type=Path,
        default=None,
        help="export this run's evidence as JSONL before exit",
    )
    return parser


def resolve_config(requested: Path) -> Path:
    requested = requested.expanduser()
    if requested.exists():
        return requested.resolve()
    if requested.name == "config.json":
        example = requested.with_name("config.example.json")
        if example.exists():
            return example.resolve()
    raise FileNotFoundError(f"configuration file not found: {requested}")


def run_headless(controller: AntiEspController, duration: float | None) -> int:
    if duration is not None and duration < 0:
        raise ValueError("--duration must be non-negative")
    controller.start()
    started = time.monotonic()
    previous: tuple[object, ...] | None = None
    try:
        while duration is None or time.monotonic() - started < duration:
            failure = controller.fatal_error
            if failure is not None:
                raise RuntimeError(f"ESP collector stopped after fatal error: {failure}")
            snapshot = controller.snapshot()
            current = (
                snapshot["suspicion_score"],
                snapshot["observation_confidence"],
                snapshot["status"],
                snapshot["active_event_count"],
            )
            if current != previous:
                print(json.dumps(snapshot, ensure_ascii=False, sort_keys=True))
                previous = current
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
    failure = controller.fatal_error
    if failure is not None:
        raise RuntimeError(f"ESP collector stopped after fatal error: {failure}")
    return 0


def run_gui(controller: AntiEspController) -> int:
    from PyQt5.QtWidgets import QApplication

    from anti_esp.dashboard import DashboardWindow

    app = QApplication.instance() or QApplication(sys.argv)
    window = DashboardWindow(controller)
    window.show()
    return int(app.exec_())


def main(argv: list[str] | None = None) -> int:
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    args = build_parser().parse_args(argv)
    config_path = resolve_config(args.config)
    settings = load_settings(config_path)
    if any(
        value is not None
        for value in (
            args.session_id,
            args.player_id,
            args.scenario,
            args.cheat_on_ms,
            args.cheat_off_ms,
        )
    ):
        if args.cheat_on_ms is not None and args.cheat_on_ms < 0:
            raise ValueError("--cheat-on-ms must be non-negative")
        if args.cheat_off_ms is not None and args.cheat_off_ms < 0:
            raise ValueError("--cheat-off-ms must be non-negative")
        cheat_on_ms = (
            args.cheat_on_ms
            if args.cheat_on_ms is not None
            else settings.telemetry.cheat_on_ms
        )
        cheat_off_ms = (
            args.cheat_off_ms
            if args.cheat_off_ms is not None
            else settings.telemetry.cheat_off_ms
        )
        if (
            cheat_on_ms is not None
            and cheat_off_ms is not None
            and cheat_off_ms < cheat_on_ms
        ):
            raise ValueError("--cheat-off-ms must be >= --cheat-on-ms")
        settings = replace(
            settings,
            telemetry=replace(
                settings.telemetry,
                session_id=args.session_id or settings.telemetry.session_id,
                player_id=args.player_id or settings.telemetry.player_id,
                scenario=args.scenario or settings.telemetry.scenario,
                cheat_on_ms=cheat_on_ms,
                cheat_off_ms=cheat_off_ms,
            ),
        )
    shared_sink: SharedEventSink | None = None
    if args.central_telemetry == "managed":
        try:
            shared_sink = SharedEventSink.from_environment()
            print("[shared] ESP telemetry client configured")
        except SharedError as error:
            print(
                f"[shared] ESP telemetry unavailable: {type(error).__name__}",
                file=sys.stderr,
            )

    try:
        controller = AntiEspController(
            settings,
            session_started_at=args.t0,
            team_event_sink=shared_sink.queue if shared_sink is not None else None,
        )
    except Exception:
        if shared_sink is not None:
            shared_sink.close()
        raise
    if controller.telemetry_session_dir is not None:
        print(f"team telemetry: {controller.telemetry_session_dir}")
    try:
        result = (
            run_headless(controller, args.duration)
            if args.headless
            else run_gui(controller)
        )
        if args.export_on_exit is not None:
            count = controller.export_jsonl(args.export_on_exit)
            print(f"exported {count} evidence event(s) to {args.export_on_exit}")
        return result
    except Exception as exc:
        controller.mark_failed(exc)
        raise
    finally:
        controller.close()
        if shared_sink is not None:
            shared_sink.close()


if __name__ == "__main__":
    raise SystemExit(main())
