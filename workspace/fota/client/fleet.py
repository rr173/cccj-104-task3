"""CLI fleet simulator used by scripts/demo.sh.

Creates N registered terminals in a hardware batch, then each time it is
invoked every terminal advances one step (check-in / resume download / install),
which is exactly what real intermittently-connected devices do on wakeup.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client import SimDevice  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=os.environ.get("FOTA_URL", "http://localhost:8080"))
    ap.add_argument("--model", default="term-x1")
    ap.add_argument("--hardware-batch", default="HW2026Q3")
    ap.add_argument("--bootloader", default="1.2.0")
    ap.add_argument("--version", default="1.9.0")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--fail-ids", default="", help="comma-separated device indexes that fail install, e.g. 3,4")
    ap.add_argument("--drop-chunks", type=int, default=None)
    ap.add_argument("--workdir", default="")
    ap.add_argument("--steps", type=int, default=1)
    args = ap.parse_args()

    workdir = Path(args.workdir or tempfile.mkdtemp(prefix="fota-fleet-"))
    fail_ids = {int(x) for x in args.fail_ids.split(",") if x}
    report = []

    for i in range(args.count):
        dev_id = f"term-{i:03d}"
        d = SimDevice(
            args.base_url,
            device_id=dev_id,
            model=args.model,
            hardware_batch=args.hardware_batch,
            bootloader=args.bootloader,
            current_version=args.version,
            workdir=workdir / dev_id,
            fail_install=i in fail_ids,
        )
        d.register()
        entry = {"device": dev_id}
        for _step in range(args.steps):
            ci = d.check_in()
            if not ci.get("offered"):
                entry.update(offered=False, reason=ci.get("reason"))
                break
            entry["offered"] = True
            entry["state"] = d._offer["install_state"]
            state = d._offer["install_state"]
            if state in ("assigned", "downloading"):
                try:
                    entry["download"] = d.download(fail_after_chunks=args.drop_chunks)
                except ConnectionError as e:
                    entry["download"] = {"interrupted": str(e)}
                    break
            elif state == "downloaded":
                entry["install"] = d.install()
                break
            elif state == "installing":
                entry["install"] = d.install()
                break
        report.append(entry)
        d.close()

    print(json.dumps({"workdir": str(workdir), "report": report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
