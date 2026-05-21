"""Generate MCP tools from OpenAPI 3.0 specs.

Reads every file under `eset_mcp/openapi/*.json` and, for each operation,
builds a ToolDef with:
- name           — `{service-prefix}_{operation_id}`, snake_case
- description    — from OpenAPI summary/description
- input_schema   — built from parameters + requestBody (with $refs resolved)
- service        — OpenAPI spec basename (used to map to a domain)
- method, path
- read_only      — True if HTTP method is GET, False otherwise
- destructive    — True for DELETE/POST/PUT/PATCH (used for MCP annotations)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from .config import Mode

# OpenAPI service name → short tool-name prefix (more readable for the agent).
_SERVICE_PREFIX: dict[str, str] = {
    "business-account": "auth",
    "application-management": "app",
    "asset-management": "asset",
    "automation": "task",
    "device-management": "device",
    "iam": "iam",
    "incident-management": "incident",
    "installer-management": "installer",
    "mobile-device-management": "mobile",
    "network-access-protection": "nap",
    "patch-management": "patch",
    "policy-management": "policy",
    "quarantine-management": "quarantine",
    "user-management": "user",
    "vulnerability-management": "vuln",
    "web-access-protection": "wap",
}

_RO_METHODS = {"get"}


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]
    service: str
    method: str
    path: str
    operation_id: str
    read_only: bool

    @property
    def required_mode(self) -> Mode:
        return "RO" if self.read_only else "RW"

    @property
    def destructive(self) -> bool:
        # Treat POST/PUT/PATCH/DELETE as potentially destructive; only GET is pure RO.
        return not self.read_only

    # Lists of path / query parameter names — needed at runtime when building
    # the URL and the query string.
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    has_body: bool = False


def load_all_tools() -> list[ToolDef]:
    """Load all tools from every OpenAPI spec bundled with the package."""
    tools: list[ToolDef] = []
    pkg = resources.files("eset_mcp") / "openapi"
    for entry in sorted(pkg.iterdir()):
        if entry.suffix != ".json":
            continue
        service = entry.stem  # "device-management"
        spec = json.loads(entry.read_text(encoding="utf-8"))
        tools.extend(_tools_from_spec(service, spec))
    _disambiguate_names(tools)
    return tools


def _disambiguate_names(tools: list[ToolDef]) -> None:
    """If two tools end up with the same name (e.g. /v1 vs /v2), suffix with the version.

    Mutates the list in place. Invariant after the call: every t.name is unique.
    """
    counts: dict[str, int] = {}
    for t in tools:
        counts[t.name] = counts.get(t.name, 0) + 1
    for t in tools:
        if counts[t.name] > 1:
            m = re.match(r"^/v(\d+)/", t.path)
            version = f"v{m.group(1)}" if m else t.method.lower()
            t.name = f"{t.name}_{version}"
    # Sanity check — fall back to a path hash if a collision still remains.
    final_counts: dict[str, int] = {}
    for t in tools:
        final_counts[t.name] = final_counts.get(t.name, 0) + 1
    for t in tools:
        if final_counts[t.name] > 1:
            t.name = f"{t.name}_{abs(hash(t.path)) % 10_000:04d}"


def _tools_from_spec(service: str, spec: dict[str, Any]) -> list[ToolDef]:
    prefix = _SERVICE_PREFIX.get(service, service.replace("-", "_"))
    out: list[ToolDef] = []
    for path, ops in spec.get("paths", {}).items():
        for method, op in ops.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            op_id = op.get("operationId") or _fallback_op_id(method, path)
            name = f"{prefix}_{_snake(op_id)}"

            summary = op.get("summary") or ""
            description_text = op.get("description") or ""
            description = _build_description(method, path, summary, description_text)

            params = op.get("parameters", [])
            path_params = [p["name"] for p in params if p.get("in") == "path"]
            query_params = [p["name"] for p in params if p.get("in") == "query"]

            input_schema = _build_input_schema(
                params,
                op.get("requestBody"),
                spec,
                is_read_only=method.lower() in _RO_METHODS,
            )
            has_body = bool(op.get("requestBody"))

            out.append(
                ToolDef(
                    name=name,
                    description=description,
                    input_schema=input_schema,
                    service=service,
                    method=method.upper(),
                    path=path,
                    operation_id=op_id,
                    read_only=method.lower() in _RO_METHODS,
                    path_params=path_params,
                    query_params=query_params,
                    has_body=has_body,
                )
            )
    return out


def _build_description(method: str, path: str, summary: str, description: str) -> str:
    head = summary or description.split("\n", 1)[0] if description else f"{method.upper()} {path}"
    extra = description if summary and description and description != summary else ""
    pieces = [head.strip(), f"({method.upper()} {path})"]
    if extra:
        # Trim — the agent does not need the entire docstring in description.
        pieces.append(extra.strip()[:400])
    return " — ".join(p for p in pieces if p)


def _build_input_schema(
    params: list[dict[str, Any]],
    request_body: dict[str, Any] | None,
    spec: dict[str, Any],
    *,
    is_read_only: bool = False,
) -> dict[str, Any]:
    """Assemble a JSON Schema for the tool's input.

    Path / query params become individual properties.
    Request body becomes a `body` property with the schema resolved.
    Read-only (GET) tools additionally expose a synthetic ``fields`` property
    — a server-side projection (NOT a native ESET API parameter) that filters
    every list-item in the response down to the requested keys, drastically
    reducing token usage when the agent only needs a few attributes.
    """
    properties: dict[str, Any] = {}
    required: list[str] = []
    for p in params:
        if p.get("in") not in {"path", "query"}:
            continue
        name = p["name"]
        schema = p.get("schema", {"type": "string"})
        resolved = _resolve_refs(schema, spec)
        if "description" not in resolved and p.get("description"):
            resolved["description"] = p["description"]
        properties[name] = resolved
        if p.get("required") or p.get("in") == "path":
            required.append(name)

    if request_body:
        content = request_body.get("content", {})
        json_schema = (content.get("application/json") or {}).get("schema")
        if json_schema:
            properties["body"] = _resolve_refs(json_schema, spec)
            if request_body.get("required"):
                required.append("body")

    if is_read_only:
        properties["fields"] = {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Optional server-side projection: return only these keys for "
                "each list-item in the response. Reduces token usage on "
                "large list endpoints. Example: ['uuid','displayName']. "
                "Top-level fields (e.g. nextPageToken) are always preserved. "
                "Not forwarded to ESET — applied locally after fetch."
            ),
        }

    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _resolve_refs(node: Any, spec: dict[str, Any], _seen: set[str] | None = None) -> Any:
    """Resolve local $refs (#/components/schemas/...). Cycle-safe."""
    _seen = _seen or set()
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if ref in _seen:
                # Cycle — leave a stub instead of recursing forever.
                return {"description": f"(cyclic reference: {ref})"}
            target = _follow_ref(ref, spec)
            if target is None:
                return {}
            return _resolve_refs(target, spec, _seen | {ref})
        return {k: _resolve_refs(v, spec, _seen) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve_refs(v, spec, _seen) for v in node]
    return node


def _follow_ref(ref: str, spec: dict[str, Any]) -> Any:
    if not ref.startswith("#/"):
        return None
    cur: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _snake(s: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower().replace("-", "_").replace(":", "_")


def _fallback_op_id(method: str, path: str) -> str:
    # Used only if an OpenAPI op omits operationId.
    clean = re.sub(r"[^a-zA-Z0-9]+", "_", path).strip("_")
    return f"{method}_{clean}"
