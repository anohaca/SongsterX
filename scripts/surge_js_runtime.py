"""Small, sandboxed Surge-compatible JavaScript runtime for Module Engine.

The runtime deliberately exposes only the request/response scripting surface and
the storage/notification bridges used by HTTP modules.  It does not expose the
filesystem, subprocesses, Python objects, or a general network API to JS.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import quickjs


_PLACEHOLDER = re.compile(r"\{\{\{([^{}]+)\}\}\}")
_OPTION_KEYS = {
    "type",
    "pattern",
    "requires-body",
    "binary-body-mode",
    "max-size",
    "timeout",
    "script-path",
    "argument",
    "engine",
    "script-update-interval",
    "debug",
}
_MAX_HTTP_BODY = 4 * 1024 * 1024
_MAX_REGEX_LENGTH = 4096


def _safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > _MAX_REGEX_LENGTH:
        raise ValueError("正则表达式超过 4096 字符限制")
    if re.search(r"\([^()\n]{0,256}[+*][^()\n]{0,256}\)[+*]", pattern):
        raise ValueError("拒绝包含嵌套量词的高风险正则表达式")
    return re.compile(pattern)


def _validate_http_url(raw_url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Module Engine 只允许访问 http/https URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError(f"无法解析 HTTP 目标：{error}") from error
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Module Engine 不允许访问本机或私有网络地址")
    return parsed


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def split_options(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char in "{[":
            depth += 1
        elif char in "}]":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return [part for part in result if part]


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _argument_defaults(line: str) -> dict[str, str]:
    marker = line.split("=", 1)
    if len(marker) != 2:
        return {}
    defaults: dict[str, str] = {}
    for part in split_options(marker[1]):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        defaults[key.strip()] = _unquote(value)
    return defaults


def _substitute(value: str, defaults: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda match: defaults.get(match.group(1).strip(), ""), value)


def _asset_map(module_path: Path) -> dict[str, Path]:
    candidates = [
        module_path.parent.parent / "module-assets.manifest.json",
        module_path.parent.parent / "config" / "module-assets.manifest.json",
        module_path.parent.parent.parent / "imported-module-assets.json",
        Path.cwd() / "config" / "module-assets.manifest.json",
    ]
    for manifest_path in candidates:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if manifest_path.name == "imported-module-assets.json":
            root = manifest_path.parent
        else:
            root = manifest_path.parent.parent if manifest_path.parent.name == "config" else manifest_path.parent
        result: dict[str, Path] = {}
        for asset in manifest.get("assets", []):
            source = asset.get("source")
            local_file = asset.get("local_file")
            if isinstance(source, str) and isinstance(local_file, str):
                result[source] = root / local_file
        return result
    return {}


def _parse_script_line(line: str, defaults: dict[str, str], assets: dict[str, Path], module_id: str) -> dict[str, Any] | None:
    match = re.match(r"^(.*?)\s*=\s*(?=type=)", line)
    if not match:
        return None
    name = match.group(1).strip()
    options: dict[str, str] = {}
    for part in split_options(line[match.end():]):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip().lower()
        if key in _OPTION_KEYS:
            options[key] = _unquote(value)
    source = options.get("script-path", "")
    local_path = assets.get(source)
    if not local_path or not local_path.is_file():
        return {
            "module": module_id,
            "name": name,
            "type": options.get("type", ""),
            "pattern": _substitute(options.get("pattern", ""), defaults).strip('"'),
            "disabledReason": "脚本未找到已校验的本地资源",
        }
    return {
        "module": module_id,
        "name": name,
        "type": options.get("type", ""),
        "pattern": _substitute(options.get("pattern", ""), defaults).strip('"'),
        "requiresBody": options.get("requires-body", "0").lower() in {"1", "true", "yes"},
        "binaryBodyMode": options.get("binary-body-mode", "0").lower() in {"1", "true", "yes"},
        "maxSize": int(options.get("max-size", "0") or 0),
        "timeout": int(options.get("timeout", "30") or 30),
        "engine": options.get("engine", "jsc"),
        "argument": _substitute(options.get("argument", ""), defaults),
        "source": source,
        "localPath": str(local_path),
    }


def parse_module_files(module_files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scripts: list[dict[str, Any]] = []
    body_rewrites: list[dict[str, Any]] = []
    for item in module_files:
        module_id = str(item.get("id", ""))
        path_value = item.get("path")
        if not module_id or not isinstance(path_value, str):
            continue
        path = Path(path_value)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        defaults: dict[str, str] = {}
        overrides = item.get("arguments", {})
        if isinstance(overrides, dict):
            defaults.update({str(key): str(value) for key, value in overrides.items()})
        section = ""
        assets = _asset_map(path)
        for raw in lines:
            line = raw.strip()
            if re.match(r"#!arguments(?:\s|=)", line, re.IGNORECASE):
                for key, value in _argument_defaults(line).items():
                    defaults.setdefault(key, value)
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip()
                continue
            if not line or line.startswith("#"):
                continue
            if section == "Script":
                parsed = _parse_script_line(line, defaults, assets, module_id)
                if parsed:
                    scripts.append(parsed)
            elif section == "Body Rewrite":
                match = re.match(r"^(\S+)\s+(\S+)\s+(.+)$", line)
                if match:
                    body_rewrites.append({
                        "module": module_id,
                        "type": match.group(1),
                        "phase": "http-response" if match.group(1).startswith("http-response") else "http-request",
                        "pattern": match.group(2).strip('"'),
                        "expression": _unquote(match.group(3)),
                    })
    return scripts, body_rewrites


def _body_bytes(body: str | bytes | None) -> bytes:
    if body is None:
        return b""
    return body if isinstance(body, bytes) else body.encode("utf-8")


def _path_get(value: Any, path: str) -> Any:
    current = value
    for part in path.strip().lstrip(".").split("."):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _path_delete(value: Any, path: str) -> bool:
    parts = [part for part in path.strip().lstrip(".").split(".") if part]
    if not parts:
        return False
    current = value
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return isinstance(current, dict) and current.pop(parts[-1], None) is not None


def apply_body_rewrite(body: bytes, content_type: str, rules: list[dict[str, Any]], url: str, logger: Callable[[str], None]) -> bytes:
    text = body.decode("utf-8", errors="replace")
    for rule in rules:
        if rule.get("phase") != "http-response":
            continue
        try:
            if not _safe_regex(str(rule.get("pattern", ".*"))).search(url):
                continue
        except (re.error, ValueError) as error:
            logger(f"跳过高风险 Body Rewrite 正则：{error}")
            continue
        if rule.get("type") != "http-response-jq":
            logger(f"跳过不支持的 Body Rewrite：{rule.get('type')}")
            continue
        try:
            data = json.loads(text)
            expression = str(rule.get("expression", ""))
            delete_match = re.fullmatch(r"del\((\.[A-Za-z0-9_.-]+)\)", expression)
            if delete_match:
                _path_delete(data, delete_match.group(1))
                text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                body = text.encode("utf-8")
        except (ValueError, TypeError, re.error) as error:
            logger(f"Body Rewrite 失败：{error}")
    return body


class SurgeScriptRuntime:
    def __init__(self, storage_path: Path, logger: Callable[[str], None]) -> None:
        self.storage_path = storage_path
        self.logger = logger
        self._lock = threading.Lock()

    def _read_store(self) -> dict[str, Any]:
        try:
            value = json.loads(self.storage_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_store(self, data: dict[str, Any]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def _http_request(self, method: str, raw_options: str) -> str:
        try:
            options = json.loads(raw_options) if raw_options else {}
            if isinstance(options, str):
                options = {"url": options}
            url = str(options.get("url", ""))
            _validate_http_url(url)
            headers = {str(k): str(v) for k, v in (options.get("headers") or {}).items()}
            body = options.get("body", "")
            payload = body.encode("utf-8") if isinstance(body, str) else None
            request = urllib.request.Request(url, data=payload, headers=headers, method=method)
            timeout = max(1.0, min(float(options.get("timeout", 15)), 30.0))
            opener = urllib.request.build_opener(_SafeRedirectHandler)
            with opener.open(request, timeout=timeout) as response:
                content = response.read(_MAX_HTTP_BODY + 1)
                if len(content) > _MAX_HTTP_BODY:
                    raise ValueError("Module Engine HTTP 响应超过 4 MiB 限制")
                result = {
                    "status": response.status,
                    "statusCode": response.status,
                    "headers": dict(response.headers.items()),
                    "body": content.decode("utf-8", errors="replace"),
                    "bodyBytes": base64.b64encode(content).decode("ascii"),
                }
                return json.dumps(result, ensure_ascii=False)
        except (OSError, ValueError, urllib.error.URLError) as error:
            return json.dumps({"error": str(error)}, ensure_ascii=False)

    def run(
        self,
        script: dict[str, Any],
        request: dict[str, Any],
        response: dict[str, Any] | None,
    ) -> dict[str, Any]:
        source_path = Path(str(script.get("localPath", "")))
        try:
            source = source_path.read_text(encoding="utf-8")
        except OSError as error:
            self.logger(f"脚本读取失败 {source_path}: {error}")
            return {}
        result: dict[str, Any] = {}
        context = quickjs.Context()
        timeout = max(1, min(int(script.get("timeout", 30) or 30), 120))
        # QuickJS interrupts runaway JavaScript. The limit covers both source
        # evaluation and pending jobs; the host bridge still applies its own
        # bounded HTTP timeout and response-size limit.
        context.set_memory_limit(64 * 1024 * 1024)

        def log(level: str, message: str) -> None:
            self.logger(f"[{level}] {message}")

        def done(raw: str) -> None:
            nonlocal result
            try:
                value = json.loads(raw) if raw else {}
                if isinstance(value, dict):
                    result = value
            except json.JSONDecodeError as error:
                self.logger(f"脚本返回值不是 JSON：{error}")

        def store_read(key: str) -> str:
            with self._lock:
                value = self._read_store().get(key)
            if value is None:
                return ""
            return str(value) if not isinstance(value, (dict, list)) else json.dumps(value, ensure_ascii=False)

        def store_write(key: str, value: str) -> bool:
            with self._lock:
                data = self._read_store()
                data[key] = value
                self._write_store(data)
            return True

        def store_remove(key: str) -> bool:
            with self._lock:
                data = self._read_store()
                data.pop(key, None)
                self._write_store(data)
            return True

        context.add_callable("__sx_log", log)
        context.add_callable("__sx_done", done)
        context.add_callable("__sx_store_read", store_read)
        context.add_callable("__sx_store_write", store_write)
        context.add_callable("__sx_store_remove", store_remove)
        context.add_callable("__sx_http", self._http_request)

        body_b64 = request.pop("__bodyBytesB64", None)
        response_b64 = response.pop("__bodyBytesB64", None) if response is not None else None
        request_json = json.dumps(request, ensure_ascii=False)
        response_json = json.dumps(response, ensure_ascii=False) if response is not None else "null"
        argument = json.dumps(str(script.get("argument", "")), ensure_ascii=False)
        prelude = fr"""
            var $request = JSON.parse({json.dumps(request_json)});
            var $response = JSON.parse({json.dumps(response_json)});
            var $argument = {argument};
            var $environment = {{"system":"{Path().anchor or ''}","language":"zh-CN","surge-version":"SongsterX"}};
            var $script = {{"name":{json.dumps(script.get('name',''))},"startTime":Date.now()/1000}};
            function __sx_log_args(level, args) {{ __sx_log(level, Array.prototype.map.call(args, function(v) {{ try {{ return typeof v === 'string' ? v : JSON.stringify(v); }} catch (_) {{ return String(v); }} }}).join(' ')); }}
            var console = {{ log:function(){{__sx_log_args('INFO', arguments)}}, info:function(){{__sx_log_args('INFO', arguments)}}, warn:function(){{__sx_log_args('WARN', arguments)}}, error:function(){{__sx_log_args('ERROR', arguments)}}, debug:function(){{__sx_log_args('DEBUG', arguments)}} }};
            function btoa(input) {{ var chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', output='', i=0; input=String(input); while(i<input.length){{var c1=input.charCodeAt(i++),c2=input.charCodeAt(i++),c3=input.charCodeAt(i++),e1=c1>>2,e2=((c1&3)<<4)|(c2>>4),e3=((c2&15)<<2)|(c3>>6),e4=c3&63;if(isNaN(c2))e3=e4=64;else if(isNaN(c3))e4=64;output+=chars.charAt(e1)+chars.charAt(e2)+chars.charAt(e3)+chars.charAt(e4);}} return output; }}
            function atob(input) {{ var chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', output='', i=0; input=String(input).replace(/[^A-Za-z0-9+/=]/g,''); while(i<input.length){{var e1=chars.indexOf(input.charAt(i++)),e2=chars.indexOf(input.charAt(i++)),e3=chars.indexOf(input.charAt(i++)),e4=chars.indexOf(input.charAt(i++)),c1=(e1<<2)|(e2>>4),c2=((e2&15)<<4)|(e3>>2),c3=((e3&3)<<6)|e4;output+=String.fromCharCode(c1);if(e3!==64)output+=String.fromCharCode(c2);if(e4!==64)output+=String.fromCharCode(c3);}} return output; }}
            function URLSearchParams(value) {{ this._pairs=[]; var input=String(value||'').replace(/^\?/,''); if(input) input.split('&').forEach(function(part){{var p=part.split('=');this._pairs.push([decodeURIComponent(p.shift()||''),decodeURIComponent(p.join('=')||'')]);}},this); }}
            URLSearchParams.prototype.get=function(key){{for(var i=0;i<this._pairs.length;i++)if(this._pairs[i][0]===String(key))return this._pairs[i][1];return null;}};
            URLSearchParams.prototype.has=function(key){{return this.get(key)!==null;}};
            URLSearchParams.prototype.set=function(key,value){{for(var i=0;i<this._pairs.length;i++)if(this._pairs[i][0]===String(key)){{this._pairs[i][1]=String(value);return;}}this._pairs.push([String(key),String(value)]);}};
            URLSearchParams.prototype.toString=function(){{return this._pairs.map(function(pair){{return encodeURIComponent(pair[0])+'='+encodeURIComponent(pair[1]);}}).join('&');}};
            function URL(input, base) {{ var raw=String(input); if(!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(raw)&&base) raw=String(base).replace(/\/$/,'')+'/'+raw.replace(/^\//,''); var m=raw.match(/^([A-Za-z][A-Za-z0-9+.-]*:)?\/\/([^\/?#]*)([^?#]*)?(\?[^#]*)?(#.*)?$/); if(!m) throw new TypeError('Invalid URL'); this.protocol=(m[1]||'').toLowerCase(); this.host=m[2]||''; var authority=this.host.split('@').pop(); var portMatch=authority.match(/:(\d+)$/); this.port=portMatch?portMatch[1]:''; this.hostname=(portMatch?authority.slice(0,-portMatch[0].length):authority).replace(/^\[|\]$/g,''); this.pathname=m[3]||'/'; this.search=m[4]||''; this.hash=m[5]||''; this.origin=this.protocol+'//'+this.host; this.searchParams=new URLSearchParams(this.search); this.href=this.origin+this.pathname+this.search+this.hash; }}
            URL.prototype.toString=function(){{return this.href;}}; URL.prototype.toJSON=function(){{return this.href;}};
            function TextEncoder(){{}} TextEncoder.prototype.encode=function(value){{var raw=unescape(encodeURIComponent(String(value)));var out=new Uint8Array(raw.length);for(var i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);return out;}};
            function TextDecoder(){{}} TextDecoder.prototype.decode=function(value){{var bytes=__sx_bytes(value)||new Uint8Array(0),raw='';for(var i=0;i<bytes.length;i++)raw+=String.fromCharCode(bytes[i]);try{{return decodeURIComponent(escape(raw));}}catch(_){{return raw;}}}};
            function __sx_bytes(value) {{ if (value == null) return null; if (value instanceof ArrayBuffer) return new Uint8Array(value); if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength); return null; }}
            function __sx_binary(value) {{ var bytes=__sx_bytes(value); if(!bytes) return value; var raw=''; for(var i=0;i<bytes.length;i++) raw+=String.fromCharCode(bytes[i]); return {{"__songsterx_binary_b64":btoa(raw)}}; }}
            function __sx_prepare(value) {{ if(!value || typeof value!=='object') return value; var out={{}}; Object.keys(value).forEach(function(k){{out[k]=k==='bodyBytes'?__sx_binary(value[k]):value[k];}}); return out; }}
            function $done(value) {{ __sx_done(JSON.stringify(__sx_prepare(value || {{}}))); }}
            var $persistentStore = {{ read:function(key){{return __sx_store_read(String(key));}}, write:function(value,key){{return __sx_store_write(String(key), String(value));}}, remove:function(key){{return __sx_store_remove(String(key));}} }};
            var $notification = {{ post:function(title,subtitle,body){{__sx_log('NOTIFY', [title,subtitle,body].filter(Boolean).join(' '));}} }};
            var $notify = function(title,subtitle,body){{__sx_log('NOTIFY', [title,subtitle,body].filter(Boolean).join(' '));}};
            var $httpClient = {{ get:function(options,cb){{var raw=__sx_http('GET',JSON.stringify(options));var data=JSON.parse(raw);if(cb)cb(data.error?data:null,data,data.body);return Promise.resolve(data);}}, post:function(options,cb){{var raw=__sx_http('POST',JSON.stringify(options));var data=JSON.parse(raw);if(cb)cb(data.error?data:null,data,data.body);return Promise.resolve(data);}} }};
            var setTimeout = function(fn){{fn();return 0;}};
        """
        if body_b64:
            prelude += f"$request.bodyBytes = new Uint8Array(Array.prototype.map.call(atob({json.dumps(body_b64)}), function(c){{return c.charCodeAt(0);}})).buffer;"
        if response is not None:
            if response_b64:
                prelude += f"$response.bodyBytes = new Uint8Array(Array.prototype.map.call(atob({json.dumps(response_b64)}), function(c){{return c.charCodeAt(0);}})).buffer;"
        try:
            context.set_time_limit(timeout)
            context.eval(prelude)
            context.eval(source)
            for _ in range(1000):
                if not context.execute_pending_job():
                    break
        except Exception as error:  # quickjs raises JSException and timeout errors
            self.logger(f"脚本执行失败 {script.get('name', '')}: {error}")
        finally:
            context.set_time_limit(0)
        return result


def flow_request_dict(flow: Any) -> dict[str, Any]:
    body = bytes(flow.request.raw_content or b"")
    return {
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "headers": dict(flow.request.headers.items(multi=True)),
        "body": body.decode("utf-8", errors="replace"),
        "__bodyBytesB64": base64.b64encode(body).decode("ascii"),
    }


def flow_response_dict(flow: Any) -> dict[str, Any]:
    body = bytes(flow.response.raw_content or b"")
    return {
        "status": flow.response.status_code,
        "statusCode": flow.response.status_code,
        "headers": dict(flow.response.headers.items(multi=True)),
        "body": body.decode("utf-8", errors="replace"),
        "__bodyBytesB64": base64.b64encode(body).decode("ascii"),
    }


def apply_result(flow: Any, result: dict[str, Any], phase: str) -> None:
    target = flow.request if phase == "request" else flow.response
    if not result:
        return
    if phase == "request":
        if isinstance(result.get("url"), str):
            flow.request.url = result["url"]
        if isinstance(result.get("method"), str):
            flow.request.method = result["method"]
    if isinstance(result.get("statusCode", result.get("status")), (int, float)) and phase == "response":
        target.status_code = int(result.get("statusCode", result.get("status")))
    if isinstance(result.get("headers"), dict):
        for key, value in result["headers"].items():
            if isinstance(value, list):
                target.headers.set_all(str(key), [str(v) for v in value])
            elif value is None:
                target.headers.pop(str(key), None)
            else:
                target.headers[str(key)] = str(value)
    if "bodyBytes" in result and isinstance(result["bodyBytes"], dict):
        marker = result["bodyBytes"].get("__songsterx_binary_b64")
        if isinstance(marker, str):
            target.content = base64.b64decode(marker)
    elif isinstance(result.get("body"), str):
        target.text = result["body"]
