"""Minimal MitmproxyBackend HTTP hook.

This file deliberately implements HTTP hooks only. It is not a Surge
JavaScript runtime and it must not choose a replacement outbound policy.
The future ContextRelay/backend adapter must attach the original FlowContext
to flow.metadata["songsterx"] before HTTP processing. Stock mitmproxy does
not provide that transport or query the Controller FlowRegistry by itself.
"""

from mitmproxy import ctx, http


MITM_HOSTS = frozenset(
    {
        "api.example.com",
    }
)
BLOCKED_HOSTS = frozenset({"blocked.example.com"})
MAX_BODY_REWRITE_BYTES = 1_048_576
REQUIRED_CONTEXT_FIELDS = (
    "flow_id",
    "backend_ingress_id",
    "selected_policy_ref",
    "resolved_policy",
    "policy_resolution_generation",
    "config_generation_id",
)


def _songsterx_context(flow: http.HTTPFlow) -> dict:
    metadata = getattr(flow, "metadata", {})
    context = metadata.get("songsterx", {})
    return context if isinstance(context, dict) else {}


def _require_context(flow: http.HTTPFlow) -> bool:
    context = _songsterx_context(flow)
    missing = [field for field in REQUIRED_CONTEXT_FIELDS if field not in context]
    identity_fields = (
        "source_process",
        "source_pid",
        "source_ip",
        "source_mac",
        "device_id",
        "device_name",
    )
    missing_identity = [field for field in identity_fields if field not in context]
    if missing or missing_identity:
        ctx.log.warn(
            "Flow %s rejected: incomplete SongsterX context (required=%s, "
            "identity=%s); the backend must not reconstruct it from "
            "destination or time",
            flow.id,
            ",".join(missing),
            ",".join(missing_identity),
        )
        flow.response = http.Response.make(
            502,
            b"SongsterX context unavailable",
            {"content-type": "text/plain; charset=utf-8"},
        )
        return False
    return True


def request(flow: http.HTTPFlow) -> None:
    if not _require_context(flow):
        return
    host = flow.request.pretty_host

    if host in BLOCKED_HOSTS:
        flow.response = http.Response.make(
            403,
            b"blocked by SongsterX",
            {"content-type": "text/plain; charset=utf-8"},
        )
        return

    if host in MITM_HOSTS:
        flow.request.headers["X-SongsterX"] = "mitmproxy-http-hook"


def response(flow: http.HTTPFlow) -> None:
    if not flow.response:
        return

    if flow.request.pretty_host not in MITM_HOSTS:
        return

    flow.response.headers["X-SongsterX-Intercepted"] = "1"

    # Body rewriting is intentionally bounded. Compression decoding,
    # binary-body-mode, streaming and JQ semantics belong to the
    # HTTPProcessingRuntime and are not silently implemented here.
    content_length = flow.response.headers.get("content-length")
    if content_length and content_length.isdigit():
        if int(content_length) > MAX_BODY_REWRITE_BYTES:
            ctx.log.info(
                "Skipping body rewrite for flow %s: body_too_large",
                flow.id,
            )
