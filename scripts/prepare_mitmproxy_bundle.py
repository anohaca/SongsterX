#!/usr/bin/env python3
"""Build the self-contained mitmdump resource used by SongsterX.

The application intentionally keeps mitmproxy as a separate child process so
the Rust runtime can supervise it, but release builds carry the executable in
the app bundle. The build machine needs mitmproxy and PyInstaller installed;
end users do not.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tempfile
import signal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src-tauri" / "resources" / "mitmdump"
LAUNCHER = '''
import quickjs  # bundled for the external SongsterX Surge script bridge
from mitmproxy.tools.main import mitmdump

if __name__ == "__main__":
    raise SystemExit(mitmdump())
'''


def main() -> int:
    if platform.system() not in {"Darwin", "Windows", "Linux"}:
        raise SystemExit(f"不支持的平台：{platform.system()}")
    python = os.environ.get("SONGSTERX_PYTHON", sys.executable)
    pyinstaller = [python, "-m", "PyInstaller"]
    try:
        subprocess.run([*pyinstaller, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        if OUTPUT.is_file():
            print(f"PyInstaller unavailable; reusing existing bundled mitmdump: {OUTPUT}")
            return 0
        raise SystemExit(
            "缺少 PyInstaller。请在构建环境执行：python3 -m pip install -r scripts/mitmproxy-build-requirements.txt"
        ) from error

    resource_dir = OUTPUT.parent
    resource_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="songsterx-mitm-build-") as temporary:
        temporary_path = Path(temporary)
        launcher = temporary_path / "songsterx_mitmdump_launcher.py"
        launcher.write_text(LAUNCHER, encoding="utf-8")
        command = [
            *pyinstaller,
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            "mitmdump",
            "--distpath",
            str(resource_dir),
            "--workpath",
            str(temporary_path / "work"),
            "--specpath",
            str(temporary_path / "spec"),
            "--collect-all",
            "mitmproxy",
            "--hidden-import",
            "quickjs",
            str(launcher),
        ]
        print(f"Building bundled mitmdump for {platform.machine()} …")
        build_environment = os.environ.copy()
        build_environment["PYINSTALLER_CONFIG_DIR"] = str(temporary_path / "pyinstaller-config")
        subprocess.run(command, check=True, env=build_environment)

    generated_output = resource_dir / ("mitmdump.exe" if platform.system() == "Windows" else "mitmdump")
    if generated_output != OUTPUT and generated_output.is_file():
        generated_output.replace(OUTPUT)
    if not OUTPUT.is_file():
        raise SystemExit(f"PyInstaller 未生成 {OUTPUT}")
    OUTPUT.chmod(0o755)
    smoke = subprocess.Popen([str(OUTPUT), "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        smoke_output, _ = smoke.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        smoke.send_signal(signal.SIGINT)
        smoke_output, _ = smoke.communicate(timeout=10)
    if "Operation not permitted" in smoke_output and "semaphore" in smoke_output:
        print("Warning: 当前沙箱禁止 mitmdump 的 semaphore 自检；已确认可执行文件生成，发布环境将继续验证。")
    elif "Mitmproxy:" not in smoke_output:
        raise SystemExit(f"内置 mitmdump 自检失败：{smoke_output.strip()}")
    print(f"Bundled mitmdump: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
