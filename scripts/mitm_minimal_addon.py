"""SongsterX Module Engine adapter for mitmproxy.

The Rust side verifies module and asset hashes and writes a runtime plan. This
addon consumes only that local plan, executes matched HTTP scripts in the
embedded QuickJS runtime, and never downloads executable code at request time.
"""

from __future__ import annotations

import json
import os
import re
import base64
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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


def _flow_url_candidates(flow: http.HTTPFlow) -> list[str]:
    """Return the URL as seen on the wire plus its original TLS/HTTP host.

    Gateway interception happens after sing-box has resolved a destination, so
    some transparent flows arrive at mitmproxy with an IP URL. Surge modules
    match the original hostname, which is still available from TLS SNI or the
    HTTP Host header. Keep both forms: the wire URL for transport and the
    hostname URL for module matching/JavaScript.
    """
    actual = flow.request.pretty_url
    candidates = [actual]
    parsed = urlsplit(actual)
    authorities: list[str] = []
    # The original hostname is on the client-side TLS connection.  The
    # server-side SNI belongs to mitmproxy's own upstream hop and may already
    # be the FakeIP/CDN address.
    for connection in (
        getattr(flow, "client_conn", None),
        getattr(flow, "server_conn", None),
    ):
        sni = getattr(connection, "sni", None)
        if isinstance(sni, str) and sni.strip():
            authorities.append(sni.strip())
    host_header = flow.request.headers.get("host")
    if isinstance(host_header, str) and host_header.strip():
        authorities.append(host_header.strip())
    for authority in authorities:
        authority = authority.strip()
        if authority.startswith("["):
            authority = authority[1:].split("]", 1)[0]
        elif authority.count(":") == 1:
            authority = authority.split(":", 1)[0]
        if not authority or ":" in authority or not parsed.scheme:
            continue
        netloc = authority
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and port not in {80, 443}:
            netloc = f"{netloc}:{port}"
        alias = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
        if alias not in candidates:
            candidates.append(alias)
    return candidates


def _module_url(flow: http.HTTPFlow) -> str:
    candidates = _flow_url_candidates(flow)
    for candidate in candidates:
        if _is_module_host(urlsplit(candidate).hostname or ""):
            return candidate
    return candidates[0]


def _flow_is_module_host(flow: http.HTTPFlow) -> bool:
    return any(_is_module_host(urlsplit(candidate).hostname or "") for candidate in _flow_url_candidates(flow))


def _restore_module_hostname(flow: http.HTTPFlow) -> None:
    """Restore the original hostname before the upstream sing-box hop.

    In Gateway + FakeIP mode the client connects to a synthetic address.  The
    TLS SNI or HTTP Host header still carries the real module hostname, but
    mitmproxy's upstream mode otherwise forwards the synthetic/CDN IP to the
    loopback sing-box inbound.  Some CDNs answer that IP with redirects or
    reject it altogether.  Rewrite only the MITM-side upstream target; the
    client-facing FakeIP and sing-box's FakeIP DNS mapping remain unchanged.
    """
    actual = urlsplit(flow.request.pretty_url)
    actual_host = actual.hostname
    if not actual_host:
        return
    # A normal hostname such as grpc.biliapi.net may carry app.bilibili.com
    # in the client-side SNI/Host candidates, but it is already a valid
    # upstream target and must not be rewritten.  This repair is only for a
    # FakeIP or literal CDN address that reached upstream mode without its
    # original module hostname.
    try:
        ipaddress.ip_address(actual_host)
    except ValueError:
        return
    module_url = next(
        (
            candidate
            for candidate in _flow_url_candidates(flow)
            if _is_module_host(urlsplit(candidate).hostname or "")
        ),
        None,
    )
    if not module_url:
        return
    original = urlsplit(module_url)
    original_host = original.hostname
    if not original_host or original_host.lower() == actual_host.lower():
        return

    port = actual.port
    if port and port not in {80, 443}:
        netloc = f"{original_host}:{port}"
        host_header = netloc
    else:
        netloc = original_host
        host_header = original_host
    flow.request.url = urlunsplit(
        (
            actual.scheme or original.scheme,
            netloc,
            actual.path,
            actual.query,
            actual.fragment,
        )
    )
    flow.request.headers["host"] = host_header
    _log("恢复 MITM 上游主机名：%s -> %s", actual_host, original_host)


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
    candidates = _flow_url_candidates(flow)
    for rule, pattern in COMPILED.get("static_url_rules", []):
        if rule.get("action") == "reject":
            for candidate in candidates:
                if pattern.search(candidate):
                    _reject(flow, str(rule.get("module", "URL-REGEX")))
                    return True
    for rule, pattern in COMPILED.get("url_rewrites", []):
        matched_url = next((candidate for candidate in candidates if pattern.search(candidate)), None)
        if matched_url is None:
            continue
        action = rule.get("action")
        if action == "reject":
            _reject(flow, str(rule.get("module", "URL Rewrite")))
            return True
        if action == "redirect":
            status = int(rule.get("status", 302))
            location = pattern.sub(_replacement_for_python(str(rule.get("replacement", ""))), matched_url, count=1)
            flow.response = http.Response.make(status, b"", {"location": location})
            return True
        if action == "replace":
            replacement = _replacement_for_python(str(rule.get("replacement", "")))
            flow.request.url = pattern.sub(replacement, matched_url, count=1)
            url = flow.request.pretty_url
            candidates = _flow_url_candidates(flow)
    return False


def _apply_header_rewrites(flow: http.HTTPFlow, phase: str) -> None:
    urls = _flow_url_candidates(flow)
    for rule, pattern in COMPILED.get("header_rewrites", []):
        if rule.get("phase") != phase or not any(pattern.search(url) for url in urls):
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
    urls = _flow_url_candidates(flow)
    for rule, pattern in COMPILED.get("map_locals", []):
        if not any(pattern.search(url) for url in urls):
            continue
        local_path = rule.get("localPath")
        inline_data = rule.get("inlineData")
        inline_data_base64 = rule.get("inlineDataBase64")
        try:
            if isinstance(inline_data_base64, str):
                body = base64.b64decode(inline_data_base64, validate=True)
                if len(body) > MAX_MAP_BYTES:
                    _log("跳过过大的内嵌 Map Local 资源")
                    continue
            elif isinstance(local_path, str) and local_path:
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
        return any(re.search(pattern, url) is not None for url in _flow_url_candidates(flow))
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


def _buffered_body(message: Any) -> bytes | None:
    """Return a complete message body, or None for a streaming response.

    mitmproxy exposes ``raw_content`` as None while a response is streamed.
    Treating that state as ``b""`` and assigning it back to ``content`` silently
    truncates the response.  Module body/script rules need a complete body, so
    callers must leave an unbuffered message untouched.
    """
    raw_content = getattr(message, "raw_content", None)
    if raw_content is None:
        return None
    return bytes(raw_content)


def _run_scripts(flow: http.HTTPFlow, phase: str) -> None:
    if SCRIPT_RUNTIME is None:
        return
    response_body: bytes | None = None
    if phase == "request":
        body = _buffered_body(flow.request) or b""
        request = flow_request_dict(flow, _module_url(flow))
        response = None
    else:
        response_body = _buffered_body(flow.response)
        body = response_body or b""
        request = flow_request_dict(flow, _module_url(flow))
        response = flow_response_dict(flow)
    for script in SCRIPT_ENTRIES:
        if phase == "response" and response_body is None and script.get("requiresBody"):
            _log("跳过流式响应 body 脚本，透传：%s", script.get("name"))
            continue
        if not _script_matches(script, flow, phase) or not _script_body_allowed(script, body):
            continue
        request_data = request.copy()
        response_data = response.copy() if response else None
        try:
            result = SCRIPT_RUNTIME.run(script, request_data, response_data)
            # A response script may still change status/headers on a streamed
            # response, but it must never synthesize a new body from the empty
            # placeholder used for an unavailable stream.
            apply_result(flow, result, phase, allow_body=response_body is not None)
            if phase == "request":
                request = flow_request_dict(flow, _module_url(flow))
            else:
                response = flow_response_dict(flow)
            body = (
                _buffered_body(flow.request) or b""
                if phase == "request"
                else _buffered_body(flow.response) or b""
            )
        except Exception as error:
            _log("脚本执行异常 %s：%s", script.get("name"), error)


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if host in MITM_HOSTS:
        flow.request.headers["X-SongsterX-M0"] = "1"
    if not _flow_is_module_host(flow):
        if host in MITM_HOSTS:
            _log("HTTP request hook: %s", flow.request.pretty_url)
        return
    _restore_module_hostname(flow)
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
    if not _flow_is_module_host(flow):
        return
    _apply_header_rewrites(flow, "http-response")
    body = _buffered_body(flow.response)
    if body is None:
        _log("流式响应原样透传：%s", _module_url(flow))
        _run_scripts(flow, "response")
        return
    original_body = body
    body = apply_body_rewrite(
        body,
        flow.response.headers.get("content-type", ""),
        BODY_REWRITE_ENTRIES,
        _module_url(flow),
        _log,
    )
    if body != original_body:
        flow.response.content = body
    _run_scripts(flow, "response")
