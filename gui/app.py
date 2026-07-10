"""
TOP RECON — application entry.

Boots Qt, runs the mandatory Authorization Gate, then drives the async pivot
engine inside the Qt event loop via qasync so the GUI never blocks. Falls back
to a dedicated-thread asyncio loop if qasync is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("toprecon")


def _install_crash_guard() -> None:
    """Keep a stray exception in a Qt slot/paint from silently aborting the app.

    PyQt6 calls ``qFatal`` for any exception escaping a virtual (e.g. paintEvent)
    or slot, which terminates the process with no visible error. We log the
    traceback and let the app keep running instead.
    """
    import traceback
    from pathlib import Path

    log_path = Path(__file__).resolve().parent.parent / "data" / "crash.log"

    def _hook(exctype, value, tb) -> None:
        if issubclass(exctype, KeyboardInterrupt):
            return  # benign — user interrupt / shutdown race, not an error
        text = "".join(traceback.format_exception(exctype, value, tb))
        logger.error("Unhandled exception (app kept alive):\n%s", text)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except Exception:  # noqa: BLE001
            pass

    sys.excepthook = _hook


def main() -> int:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QFont

    from gui import theme
    from gui.authorization_gate import AuthorizationGate
    from gui.main_window import MainWindow
    from config.settings import Settings
    from transforms import build_registry

    _install_crash_guard()
    app = QApplication(sys.argv)
    app.setApplicationName("TOP RECON")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(theme.stylesheet())

    settings = Settings()

    # --- Authorization Gate (blocking, before anything scans) ---
    gate = AuthorizationGate(settings)
    if gate.exec() != AuthorizationGate.DialogCode.Accepted:
        logger.info("Authorization declined — exiting.")
        return 0
    result = gate.result()
    if result is None:
        return 0

    registry = build_registry()
    logger.info("Registry: %d transforms loaded", len(registry))

    window = MainWindow(settings, registry, result)
    window.show()

    # --- async loop via qasync (preferred) ---
    try:
        import qasync
    except Exception:  # noqa: BLE001
        qasync = None

    if qasync is not None:
        loop = qasync.QEventLoop(app)
        asyncio.set_event_loop(loop)

        def _on_quit():
            # Stop the engine so no new blocking transforms are dispatched to the
            # thread-pool, then best-effort close the shared HTTP client.
            try:
                window._engine.stop()
            except Exception:  # noqa: BLE001
                pass
            try:
                from transforms.common import close_http
                loop.create_task(close_http())
            except Exception:  # noqa: BLE001
                pass
        app.aboutToQuit.connect(_on_quit)

        loop.call_soon(window.start_scan)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        # The window has closed and the app is quitting. Guarantee a prompt,
        # non-hanging exit even if a background transform thread is still
        # finishing (the executor join would otherwise block on shutdown).
        os._exit(0)

    # --- fallback: run the engine loop in a background thread ---
    logger.warning("qasync unavailable — using background-thread engine loop.")
    import threading
    bg_loop = asyncio.new_event_loop()

    def _run_loop():
        asyncio.set_event_loop(bg_loop)
        bg_loop.run_forever()
    threading.Thread(target=_run_loop, daemon=True).start()

    def _start():
        # Schedule the engine coroutine on the background loop.
        seed = result.target
        from core.entities import EntityType
        asyncio.run_coroutine_threadsafe(
            window._engine.run(seed, EntityType.DOMAIN,
                               active_enabled=result.active_scan,
                               max_depth=settings.max_depth), bg_loop)
    from PyQt6.QtCore import QTimer
    QTimer.singleShot(200, _start)
    rc = app.exec()
    bg_loop.call_soon_threadsafe(bg_loop.stop)
    return rc


if __name__ == "__main__":
    sys.exit(main())
