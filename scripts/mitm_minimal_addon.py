"""SongsterX Module Engine adapter for mitmproxy.

The Rust side verifies module and asset hashes and writes a runtime plan. This
addon consumes only that local plan, executes matched HTTP scripts in the
embedded QuickJS runtime, and never downloads executable code at request time.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http

try:
    from surge_js_runtime import (
        SurgeScriptRuntime,
        apply_body_rewrite,
        apply_result,
        flow_request_dict,
        flow_response_dict,
        parse_module_files,
    )
except ModuleNotFoundError:  # Allows repository-side replay tests.
    from scripts.surge_js_runtime import (
        SurgeScriptRuntime,
        apply_body_rewrite,
        apply_result,
        flow_request_dict,
        flow_response_dict,
        parse_module_files,
    )


PLAN_PATH = os.environ.get("SONGSTERX_MODULE_PLAN", "")
MAX_MAP_BYTES = 4 * 1024 * 1024
MAX_REGEX_LENGTH = 4096
MITM_HOSTS = frozenset({"api.day.app"})
PLAN: dict[str, Any] = {}
COMPILED: dict[str, list[tuple[dict[str, Any], re.Pattern[str]]]] = {}
SCRIPT_ENTRIES: list[dict[str, Any]] = []
BODY_REWRITE_ENTRIES: list[dict[str, Any]] = []
SCRIPT_RUNTIME: SurgeScriptRuntime | None = None


def _log(message: str, *args: Any) -> None:
    rendered = f"SongsterX: {message % args if args else message}"
    logger = getattr(ctx, "log", None)
    if logger is not None:
        logger.info(rendered)
    else:
        print(rendered)


def _compile_safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError("正则表达式超过 4096 字符限制")
    # Python's backtracking engine has no per-match timeout. Reject the common
    # nested-quantifier forms that can turn a URL match into catastrophic work.
    if re.search(r"\([^()\n]{0,256}[+*][^()\n]{0,256}\)[+*]", pattern):
        raise ValueError("拒绝包含嵌套量词的高风险正则表达式")
    return re.compile(pattern)


def _compile_rules(key: str) -> list[tuple[dict[str, Any], re.Pattern[str]]]:
    compiled: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    for rule in PLAN.get(key, []):
        pattern = rule.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            compiled.append((rule, _compile_safe_regex(pattern)))
        except (re.error, ValueError) as error:
            _log("跳过无效模块正则 %r: %s", pattern, error)
    return compiled


def _load_plan() -> None:
    global PLAN, COMPILED, SCRIPT_ENTRIES, BODY_REWRITE_ENTRIES, SCRIPT_RUNTIME
    if not PLAN_PATH:
        PLAN = {}
        COMPILED = {}
        SCRIPT_ENTRIES = []
        BODY_REWRITE_ENTRIES = []
        return
    try:
        PLAN = json.loads(Path(PLAN_PATH).read_text(encoding="utf-8"))
        COMPILED = {
            "url_rewrites": _compile_rules("urlRewrites"),
            "map_locals": _compile_rules("mapLocals"),
            "header_rewrites": _compile_rules("headerRewrites"),
            "static_url_rules": [],
        }
        for rule in PLAN.get("staticRules", []):
            if rule.get("kind") != "url_regex":
                continue
            pattern = rule.get("value")
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                COMPILED["static_url_rules"].append((rule, _compile_safe_regex(pattern)))
            except (re.error, ValueError) as error:
                _log("跳过无效 URL-REGEX %r: %s", pattern, error)
        SCRIPT_ENTRIES, BODY_REWRITE_ENTRIES = parse_module_files(PLAN.get("moduleFiles", []))
        storage = Path(PLAN_PATH).parent / "module-persistent-store.json"
        SCRIPT_RUNTIME = SurgeScriptRuntime(storage, _log)
        _log(
            "Module Engine loaded: modules=%s, MITM hosts=%s, URL rewrites=%s, map locals=%s, "
            "header rewrites=%s, body rewrites=%s, scripts=%s",
            len(PLAN.get("enabledModules", [])),
            len(PLAN.get("mitmHostnames", [])),
            len(PLAN.get("urlRewrites", [])),
            len(PLAN.get("mapLocals", [])),
            len(PLAN.get("headerRewrites", [])),
            len(BODY_REWRITE_ENTRIES),
            len(SCRIPT_ENTRIES),
        )
    except (OSError, json.JSONDecodeError) as error:
        PLAN = {}
        COMPILED = {}
        SCRIPT_ENTRIES = []
        BODY_REWRITE_ENTRIES = []
        SCRIPT_RUNTIME = None
        _log("模块运行计划不可用：%s", error)


def load(loader) -> None:
    _load_plan()


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().strip().rstrip(".")
    if pattern.startswith("*"):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


def _is_module_host(host: str) -> bool:
    return any(_host_matches(host, pattern) for pattern in PLAN.get("mitmHostnames", []))


def _reject(flow: http.HTTPFlow, reason: str) -> None:
    flow.response = http.Response.make(
        403,
        f"blocked by SongsterX module: {reason}".encode("utf-8"),
        {"content-type": "text/plain; charset=utf-8", "x-songsterx-module": "reject"},
    )


def _replacement_for_python(value: str) -> str:
    return re.sub(r"\$(\d+)", r"\\g<\1>", value)


def _apply_url_rewrites(flow: http.HTTPFlow) -> bool:
    url = flow.request.pretty_url
    for rule, pattern in COMPILED.get("static_url_rules", []):
        if rule.get("action") == "reject" and pattern.search(url):
            _reject(flow, str(rule.get("module", "URL-REGEX")))
            return True
    for rule, pattern in COMPILED.get("url_rewrites", []):
        match = pattern.search(url)
        if not match:
            continue
        action = rule.get("action")
        if action == "reject":
            _reject(flow, str(rule.get("module", "URL Rewrite")))
            return True
        if action == "redirect":
            status = int(rule.get("status", 302))
            location = pattern.sub(_replacement_for_python(str(rule.get("replacement", ""))), url, count=1)
            flow.response = http.Response.make(status, b"", {"location": location})
            return True
        if action == "replace":
            replacement = _replacement_for_python(str(rule.get("replacement", "")))
            flow.request.url = pattern.sub(replacement, url, count=1)
            url = flow.request.pretty_url
    return False


def _apply_header_rewrites(flow: http.HTTPFlow, phase: str) -> None:
    url = flow.request.pretty_url
    for rule, pattern in COMPILED.get("header_rewrites", []):
        if rule.get("phase") != phase or not pattern.search(url):
            continue
        headers = flow.request.headers if phase == "http-request" else flow.response.headers
        name = str(rule.get("name", "")).strip()
        if not name:
            continue
        operation = rule.get("operation")
        if operation == "header-del":
            headers.pop(name, None)
        elif operation in {"header-add", "header-replace"}:
            headers[name] = str(rule.get("value", ""))


def _map_local(flow: http.HTTPFlow) -> bool:
    url = flow.request.pretty_url
    for rule, pattern in COMPILED.get("map_locals", []):
        if not pattern.search(url):
            continue
        local_path = rule.get("localPath")
        inline_data = rule.get("inlineData")
        try:
            if isinstance(local_path, str) and local_path:
                path = Path(local_path)
                if not path.is_file() or path.stat().st_size > MAX_MAP_BYTES:
                    _log("跳过 Map Local 资源：%s", local_path)
                    continue
                body = path.read_bytes()
            elif isinstance(inline_data, str):
                body = inline_data.encode("utf-8")
            else:
                continue
        except OSError as error:
            _log("Map Local 读取失败：%s", error)
            continue
        headers = {"x-songsterx-module": str(rule.get("module", "Map Local"))}
        header = rule.get("header")
        if isinstance(header, str) and header:
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()
            else:
                headers["content-type"] = header
        elif rule.get("dataType") == "text":
            headers["content-type"] = "text/plain; charset=utf-8"
        flow.response = http.Response.make(200, body, headers)
        return True
    return False


def _script_matches(script: dict[str, Any], flow: http.HTTPFlow, phase: str) -> bool:
    if script.get("disabledReason") or script.get("type") != f"http-{phase}":
        return False
    pattern = script.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        return False
    try:
        return re.search(pattern, flow.request.pretty_url) is not None
    except re.error as error:
        _log("跳过脚本无效正则 %s：%s", script.get("name"), error)
        return False


def _script_body_allowed(script: dict[str, Any], body: bytes) -> bool:
    if not script.get("requiresBody"):
        return True
    max_size = int(script.get("maxSize", 0) or 0)
    if max_size > 0 and len(body) > max_size:
        _log("脚本 body 超限，透传：%s", script.get("name"))
        return False
    return True


def _run_scripts(flow: http.HTTPFlow, phase: str) -> None:
    if SCRIPT_RUNTIME is None:
        return
    if phase == "request":
        body = bytes(flow.request.raw_content or b"")
        request = flow_request_dict(flow)
        response = None
    else:
        body = bytes(flow.response.raw_content or b"")
        request = flow_request_dict(flow)
        response = flow_response_dict(flow)
    for script in SCRIPT_ENTRIES:
        if not _script_matches(script, flow, phase) or not _script_body_allowed(script, body):
            continue
        request_data = request.copy()
        response_data = response.copy() if response else None
        try:
            result = SCRIPT_RUNTIME.run(script, request_data, response_data)
            apply_result(flow, result, phase)
            if phase == "request":
                request = flow_request_dict(flow)
            else:
                response = flow_response_dict(flow)
            body = bytes(flow.request.raw_content or b"") if phase == "request" else bytes(flow.response.raw_content or b"")
        except Exception as error:
            _log("脚本执行异常 %s：%s", script.get("name"), error)


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if host in MITM_HOSTS:
        flow.request.headers["X-SongsterX-M0"] = "1"
    if not _is_module_host(host):
        if host in MITM_HOSTS:
            _log("HTTP request hook: %s", flow.request.pretty_url)
        return
    if _apply_url_rewrites(flow):
        return
    if _map_local(flow):
        return
    _apply_header_rewrites(flow, "http-request")
    _run_scripts(flow, "request")


def response(flow: http.HTTPFlow) -> None:
    if not flow.response:
        return
    if flow.request.pretty_host in MITM_HOSTS:
        flow.response.headers["X-SongsterX-M0-Intercepted"] = "1"
    if not _is_module_host(flow.request.pretty_host):
        return
    _apply_header_rewrites(flow, "http-response")
    body = bytes(flow.response.raw_content or b"")
    body = apply_body_rewrite(
        body,
        flow.response.headers.get("content-type", ""),
        BODY_REWRITE_ENTRIES,
        flow.request.pretty_url,
        _log,
    )
    flow.response.content = body
    _run_scripts(flow, "response")
