"""MCP server - registers tools, resources and prompts.

Targets MCP spec 2025-11-25 (Streamable HTTP). Uses the official `mcp` Python SDK.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server import Server
from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
    ToolAnnotations,
)

from . import __version__
from .client_pool import ClientPool
from .composite_tools import (
    ALL_KINDS,
    device_full_profile,
    eset_search,
    incident_full_context,
    latest_detections,
)
from .config import Settings
from .credentials import CredentialResolverError
from .errors import EsetApiError, ModeForbiddenError
from .http_client import EsetHttpClient
from .modes import check_mode_allows
from .observability import (
    inc_capped,
    inc_tool_call,
    log_event,
    observe_response_bytes,
    observe_tool_duration,
)
from .response_shaping import apply_fields_projection, cap_response_size
from .tools_loader import ToolDef, load_all_tools

# Resolver protocol - anything with a no-arg `resolve()` returning Credentials.
# We don't import the protocol class to keep server.py decoupled; duck typing
# is enough and avoids a circular import.

_LOG = logging.getLogger("eset_mcp.server")

# All composite tools are read-only (they only fan out GET requests).
_COMPOSITE_TOOLS: list[Tool] = [
    Tool(
        name="eset_search",
        description=(
            "Case-insensitive substring search across devices, users, policies and groups. "
            "Returns matching items with their UUIDs and which field matched. Use this instead "
            "of list_* + manual filtering when you have a name fragment (e.g. 'jeff', 'laptop-23', "
            "'finance')."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Substring to look for (case-insensitive). Plain text, not regex.",
                },
                "kinds": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(ALL_KINDS)},
                    "description": (
                        "Resource kinds to search. Defaults to all four. Pick a subset to "
                        "narrow scope and save quota: e.g. ['user'] when looking for a person, "
                        "['device'] for hostnames/IPs."
                    ),
                },
                "limit_per_kind": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 20,
                    "description": "Max matches returned per kind (default 20).",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(
            title="ESET cross-resource substring search",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    ),
    Tool(
        name="device_full_profile",
        description=(
            "One call → device record + recent detections + vulnerabilities + recent scans. "
            "Use when answering 'what do you know about this machine'. Each sub-section "
            "degrades gracefully if the tenant lacks a module."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "deviceUuid": {"type": "string", "description": "UUID of the device."},
            },
            "required": ["deviceUuid"],
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(
            title="ESET device full profile (composite)",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    ),
    Tool(
        name="incident_full_context",
        description=(
            "One call → incident + comments + related detections + affected devices. "
            "Detections and devices are capped at 10 each to stay within rate limits; "
            "the response carries a 'truncated' flag if more exist."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "incidentUuid": {"type": "string", "description": "UUID of the incident."},
            },
            "required": ["incidentUuid"],
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(
            title="ESET incident full context (composite)",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    ),
    Tool(
        name="latest_detections",
        description=(
            "Newest detections in a time window, sorted by occurTime descending. "
            "Use this - NOT raw incident_detections__list_detections_* - when answering "
            "'what's the latest detection / what happened recently'. The raw list endpoints "
            "do NOT sort by date, so a first-page sort silently returns stale rows. "
            "This composite does v2→v1 fallback, paginates the time window, and sorts locally."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 24 * 365,
                    "default": 24,
                    "description": "Time window in hours back from now (default 24).",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 10,
                    "description": "Number of newest detections to return (default 10).",
                },
                "severity_min": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH"],
                    "description": "Optional: filter to severity at or above this level.",
                },
            },
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(
            title="ESET latest detections (composite)",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    ),
]


def build_server(settings: Settings, pool: ClientPool, resolver: Any) -> Server:
    """Build an mcp.server.Server instance with every capability wired up.

    `resolver` is anything with a no-arg ``resolve() -> Credentials`` method
    (EnvCredentialResolver in single-tenant mode, BasicAuthCredentialResolver
    in multi-tenant mode - see eset_mcp.credentials).
    `pool` is the shared ClientPool keyed by (user, region).
    """
    server = Server(name="eset-mcp", version=__version__)
    tools = load_all_tools()
    tools_by_name = {t.name: t for t in tools}

    async def _http() -> EsetHttpClient:
        """Resolve current request's credentials → fetch a pooled client."""
        creds = resolver.resolve()
        return await pool.get(creds)

    # --- TOOLS ---
    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        # In RO mode we hide RW tools entirely - the agent never sees them in
        # the catalog. Earlier design kept them visible-but-blocked, but that
        # wasted the agent's context and tempted it to call something that
        # could never succeed. Composite tools are all RO and always shown.
        if settings.mode == "RO":
            return [
                *_COMPOSITE_TOOLS,
                *(_tool_to_mcp(t) for t in tools if t.read_only),
            ]
        return [*_COMPOSITE_TOOLS, *(_tool_to_mcp(t) for t in tools)]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        import time as _time

        # All mutable telemetry state lives in this dict so the finally
        # block can read it without resorting to `locals().get(...)`.
        tel: dict[str, Any] = {
            "t0": _time.monotonic(),
            "deployment": "unknown",
            "user": "",
            "status": "error",
            "bytes_out": 0,
        }
        try:
            return await _dispatch(name, arguments, tel)
        finally:
            # Telemetry must NEVER kill a tool call. Wrap defensively so
            # that a misbehaving metrics registry or formatter cannot
            # turn a successful tool call into a 500 to the agent.
            try:
                _emit_tool_call_telemetry(name, settings.mode, tel)
            except Exception:  # observability MUST be best-effort
                _LOG.exception("telemetry emission failed for tool=%s", name)

    async def _dispatch(name: str, arguments: dict[str, Any], tel: dict[str, Any]) -> list[TextContent]:
        try:
            http = await _http()
        except CredentialResolverError as e:
            tel["status"] = "auth_error"
            return [TextContent(type="text", text=f"Auth error: {e}")]
        tel["deployment"] = http.credentials.deployment
        tel["user"] = getattr(http.credentials, "user", "")

        # `fields` is a *synthetic* parameter we add to every read-only tool
        # (see tools_loader._build_input_schema). It is a server-side
        # projection, never forwarded to ESET - so we pop it before dispatch.
        arguments = dict(arguments)
        fields = arguments.pop("fields", None)
        max_bytes = settings.response_bytes_max

        # Composite tools dispatch first (they are not OpenAPI-derived).
        composite = await _dispatch_composite(http, name, arguments, fields, max_bytes)
        if composite is not None:
            tel["status"] = "200"
            if composite and composite[0].text:
                tel["bytes_out"] = len(composite[0].text.encode("utf-8"))
            return composite

        tool = tools_by_name.get(name)
        if tool is None:
            tel["status"] = "unknown_tool"
            raise ValueError(f"Unknown tool: {name}")
        check_mode_allows(tool.required_mode, settings.mode, name)
        try:
            result = await _execute_tool(http, tool, arguments)
        except ModeForbiddenError as e:
            tel["status"] = "mode_forbidden"
            return [TextContent(type="text", text=str(e))]
        except EsetApiError as e:
            tel["status"] = str(getattr(e, "status", "error"))
            return [TextContent(type="text", text=f"ESET API error: {e}")]
        shaped = _shape(result, fields, max_bytes)
        if isinstance(shaped, dict) and "_capped" in shaped:
            inc_capped(tool=name)
        text = _to_text(shaped)
        tel["bytes_out"] = len(text.encode("utf-8"))
        tel["status"] = "200"
        return [TextContent(type="text", text=text)]

    # --- RESOURCES ---
    @server.list_resources()
    async def _list_resources() -> list[Resource]:
        return [
            Resource(
                uri="eset://config/mode",
                name="ESET MCP mode (RO/RW)",
                description="Current server mode - independent of the API account's permissions.",
                mimeType="text/plain",
            ),
            Resource(
                uri="eset://config/region",
                name="ESET region",
                description="API region (eu/de/us/ca/jpn). Only meaningful for cloud deployments.",
                mimeType="text/plain",
            ),
            Resource(
                uri="eset://config/deployment",
                name="ESET deployment kind",
                description=(
                    "Per-request: 'cloud' (ESET Connect API) or 'onprem' "
                    "(customer-hosted ESET PROTECT console). In basic-auth "
                    "mode an X-ESET-Server-URL header switches the request "
                    "to on-prem."
                ),
                mimeType="text/plain",
            ),
            Resource(
                uri="eset://config/tools-catalog",
                name="Tools catalog",
                description="List of all tools with RO/RW split and mapping to ESET endpoints.",
                mimeType="application/json",
            ),
            Resource(
                uri="eset://docs/rate-limits",
                name="ESET API rate limits",
                description="10 req/s per credential/IP. Bursts subject to the Fair Use Policy.",
                mimeType="text/markdown",
            ),
        ]

    @server.read_resource()
    async def _read_resource(uri) -> str:
        # MCP SDK passes a pydantic AnyUrl; coerce to str so string comparisons work.
        uri = str(uri)
        if uri == "eset://config/mode":
            return settings.mode
        if uri == "eset://config/region":
            # In basic-auth mode this reflects the *current request's* region,
            # not just the .env default - agents can use this to confirm
            # which tenant they're hitting.
            try:
                return resolver.resolve().region
            except CredentialResolverError:
                return settings.region
        if uri == "eset://config/deployment":
            # For on-prem credentials we surface the server URL too - it's
            # the only useful "where am I" hint the agent has.
            try:
                creds = resolver.resolve()
            except CredentialResolverError:
                return settings.deployment
            if creds.deployment == "onprem":
                return f"onprem ({creds.server_url})"
            return "cloud"
        if uri == "eset://config/tools-catalog":
            catalog = [
                {
                    "name": t.name,
                    "mode": t.required_mode,
                    "method": t.method,
                    "path": t.path,
                    "service": t.service,
                    "description": t.description,
                }
                for t in tools
            ]
            return json.dumps(catalog, indent=2, ensure_ascii=False)
        if uri == "eset://docs/rate-limits":
            return (
                "# ESET Connect - rate limits\n\n"
                "- **10 req/s** per credential / account / originating IP.\n"
                "- 429 Too Many Requests on exceedance - the MCP server retries with backoff.\n"
                "- Bursts >1000 requests trip the Fair Use Policy: some get 202, "
                "some 50x (must be retried later).\n"
            )
        raise ValueError(f"Unknown resource URI: {uri}")

    # --- PROMPTS ---
    @server.list_prompts()
    async def _list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name="audit_inactive_devices",
                description="List devices that have not checked in for X days - offboarding candidates.",
                arguments=[
                    PromptArgument(name="days", description="Inactivity threshold in days (default 30).", required=False),
                ],
            ),
            Prompt(
                name="vulnerability_report",
                description="Build a CVE report: which devices have unpatched vulnerabilities, sorted by severity.",
                arguments=[],
            ),
            Prompt(
                name="incident_triage",
                description="Show open incidents + related detections. Suggest priorities.",
                arguments=[],
            ),
        ]

    @server.get_prompt()
    async def _get_prompt(name: str, arguments: dict[str, str] | None) -> GetPromptResult:
        args = arguments or {}
        if name == "audit_inactive_devices":
            days = args.get("days", "30")
            text = (
                f"Use the ESET MCP tools to list devices inactive for at least {days} days.\n"
                f"Steps:\n"
                f"1. `device_devices__list_devices` - fetch all.\n"
                f"2. Filter by `lastConnected` < now - {days}d.\n"
                f"3. Present as a table: name, OS, last seen, group.\n"
            )
        elif name == "vulnerability_report":
            text = (
                "Build a vulnerability report:\n"
                "1. `vuln_vulnerabilities__list_vulnerable_devices` - list of devices.\n"
                "2. For the top-N (e.g. 10) by severity → `vuln_vulnerabilities__list_device_vulnerabilities`.\n"
                "3. Group by CVE, sort by severity, show top 10.\n"
            )
        elif name == "incident_triage":
            text = (
                "Open incident review:\n"
                "1. `incident_incidents__list_incidents` with `status=open`.\n"
                "2. For each → `incident_incidents__get_incident` + `incident_detections__list_detections_v2`.\n"
                "3. Sort by severity and first-detection time. Propose priorities.\n"
            )
        else:
            raise ValueError(f"Unknown prompt: {name}")
        return GetPromptResult(
            description=name,
            messages=[PromptMessage(role="user", content=TextContent(type="text", text=text))],
        )

    return server


def _tool_to_mcp(t: ToolDef) -> Tool:
    """Convert ToolDef -> mcp.types.Tool with proper annotations.

    RO mode filters RW tools out of `list_tools` upstream, so by the time
    this runs `t` is already mode-appropriate. The call_tool gate stays as
    defence-in-depth for hard-coded RW tool names.
    """
    annotations = ToolAnnotations(
        title=f"{t.method} {t.path}",
        readOnlyHint=t.read_only,
        destructiveHint=t.destructive,
        idempotentHint=t.method.upper() in {"GET", "PUT", "DELETE"},
        openWorldHint=True,  # external API (ESET cloud)
    )
    return Tool(
        name=t.name,
        description=t.description,
        inputSchema=t.input_schema,
        annotations=annotations,
    )


async def _execute_tool(
    http: EsetHttpClient,
    tool: ToolDef,
    arguments: dict[str, Any],
) -> Any:
    """Turn (ToolDef + arguments) into an HTTP request against ESET.

    For on-prem credentials we pick :attr:`ToolDef.onprem_path` when one is
    registered for this tool - see ``openapi/onprem-path-overrides.json``.
    """
    args = dict(arguments)
    # Pick cloud or on-prem variant of the path before placeholder substitution.
    path = tool.path_for(http.credentials.deployment)
    for pname in tool.path_params:
        if pname not in args:
            raise ValueError(f"Missing required path parameter: {pname}")
        path = path.replace("{" + pname + "}", str(args.pop(pname)))

    # Query params: keep only the declared ones, leave the rest in args (e.g. body).
    query = {pname: args.pop(pname) for pname in tool.query_params if pname in args}

    body = args.pop("body", None) if tool.has_body else None
    if args:
        # Unknown parameters - silently drop, but log for debugging.
        _LOG.debug("Dropped unknown parameters for %s: %s", tool.name, list(args))

    return await http.request(tool.method, tool.service, path, query=query, json=body)


def _to_text(result: Any) -> str:
    """Render as JSON text - pretty-printed for readability."""
    try:
        return json.dumps(result, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(result)


def _emit_tool_call_telemetry(name: str, mode: str, tel: dict[str, Any]) -> None:
    """Emit the metric + log pair for a finished tool call.

    `tel` is the per-call mutable state that `_call_tool` keeps (deployment,
    user, status, bytes_out, plus `t0` from time.monotonic()). Passing the
    dict avoids a 7-argument signature and keeps the call-site readable.
    """
    import time as _time
    deployment = tel["deployment"]
    duration_s = _time.monotonic() - tel["t0"]
    status = tel["status"]
    bytes_out = tel["bytes_out"]
    user = tel["user"]

    inc_tool_call(tool=name, deployment=deployment, status=status)
    observe_tool_duration(tool=name, deployment=deployment, seconds=duration_s)
    if bytes_out > 0:
        observe_response_bytes(tool=name, deployment=deployment, n_bytes=bytes_out)
    log_event(
        _LOG, "tool_call",
        tool=name,
        deployment=deployment,
        user=user,
        mode=mode,
        status=status,
        duration_ms=int(duration_s * 1000),
        response_bytes=bytes_out,
    )


def _shape(result: Any, fields: list[str] | None, max_bytes: int) -> Any:
    """Apply field projection (if requested) and the global byte cap.

    Projection happens first so the cap, when it kicks in, kicks in on
    already-skinnier rows - giving the agent more items per call.
    """
    if fields:
        result = apply_fields_projection(result, fields)
    if max_bytes > 0:
        result, _ = cap_response_size(result, max_bytes)
    return result


async def _dispatch_composite(
    http: EsetHttpClient,
    name: str,
    arguments: dict[str, Any],
    fields: list[str] | None,
    max_bytes: int,
) -> list[TextContent] | None:
    """If `name` is one of the composite tools, run it and return MCP content.

    Returns None when `name` is not a composite - caller falls through to the
    OpenAPI-derived tool registry. Composite tools are always RO; we don't
    invoke the mode gate. Composites are expected to be moderately sized but
    we still apply the cap as a safety net.
    """
    try:
        if name == "eset_search":
            result = await eset_search(
                http,
                query=arguments["query"],
                kinds=arguments.get("kinds"),
                limit_per_kind=int(arguments.get("limit_per_kind", 20)),
            )
        elif name == "device_full_profile":
            result = await device_full_profile(http, device_uuid=arguments["deviceUuid"])
        elif name == "incident_full_context":
            result = await incident_full_context(http, incident_uuid=arguments["incidentUuid"])
        elif name == "latest_detections":
            result = await latest_detections(
                http,
                hours=int(arguments.get("hours", 24)),
                limit=int(arguments.get("limit", 10)),
                severity_min=arguments.get("severity_min"),
            )
        else:
            return None
    except EsetApiError as e:
        return [TextContent(type="text", text=f"ESET API error: {e}")]
    return [TextContent(type="text", text=_to_text(_shape(result, fields, max_bytes)))]
