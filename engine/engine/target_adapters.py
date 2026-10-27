"""Convert live target inputs and artifacts into protocol-neutral function profiles."""
import json
import os
import plistlib
import re
import zipfile
from urllib.parse import urljoin
from xml.etree import ElementTree

import function_profile as FP

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
QUOTED_PATH_RE = re.compile(r"[\"'`](/[A-Za-z0-9_./{}:\-]{2,})[\"'`]")
CALL_RE = re.compile(r"fetch|axios|httprequest|okhttp|nsurlsession|urlsession|alamofire|retrofit|httpurlconnection", re.I)


def http_profiles(endpoints, base_url=""):
    profiles = []
    for endpoint in endpoints or []:
        item = dict(endpoint)
        if base_url and item.get("url", "").startswith("/"):
            item["url"] = urljoin(base_url, item["url"])
        profiles.append(FP.from_endpoint(item))
    return FP.merge_profiles(profiles)


def _named_records(value):
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        records = []
        for name, item in value.items():
            if isinstance(item, dict):
                records.append(dict(item, name=item.get("name") or name))
        return records
    return []


def cloud_profiles(snapshot):
    resources = snapshot.get("resources") if isinstance(snapshot, dict) else snapshot
    profiles = []
    for resource in _named_records(resources):
        actors = dict(resource.get("actors") or {})
        if resource.get("public_principals"):
            actors["unauthenticated"] = True
        if resource.get("tenant") or resource.get("account"):
            actors["tenant"] = resource.get("tenant") or resource["account"]
        if resource.get("owner"):
            actors["owner"] = resource["owner"]
        permissions = resource.get("permissions") or resource.get("policy") or []
        profiles.append(FP.new_profile(
            action=resource.get("action") or "resource_access",
            resource=resource.get("id") or resource.get("arn") or resource.get("name") or "cloud-resource",
            protocol=resource.get("protocol") or "cloud-api",
            actors=actors,
            inputs=[{"name": "policy", "location": "policy", "type": "document"}],
            outputs={"permissions": permissions},
            effects=[{"type": "state_change"}] if resource.get("mutates") else [],
            preconditions=resource.get("preconditions") or [],
            state={"mutates": bool(resource.get("mutates"))},
            sensitivity=resource.get("sensitivity") or {"level": 0},
            provenance=[resource.get("provenance") or "cloud_config_artifact"],
            observations=resource.get("observations") or [],
            confidence=resource.get("confidence", "inferred"),
            metadata=resource,
        ))
    return FP.merge_profiles(profiles)


def llm_profiles(descriptor):
    profiles = []
    tools = descriptor.get("tools") or descriptor.get("functions") or []
    for tool in _named_records(tools):
        effects = []
        if tool.get("url") or tool.get("endpoint") or tool.get("callback"):
            effects.append({"type": "external_call", "target": tool.get("url") or tool.get("endpoint") or tool.get("callback")})
        if tool.get("mutates") or tool.get("action"):
            effects.append({"type": "state_change", "action": tool.get("action")})
        profiles.append(FP.new_profile(
            action=tool.get("name") or tool.get("id") or "tool_call",
            resource=tool.get("resource") or tool.get("description") or "llm-tool",
            protocol="llm-tool",
            actors=tool.get("actors") or {"authenticated": bool(descriptor.get("authenticated"))},
            inputs=tool.get("inputs") or tool.get("parameters") or [],
            outputs=tool.get("outputs") or {},
            effects=effects,
            preconditions=tool.get("preconditions") or [],
            state={"mutates": bool(tool.get("mutates") or tool.get("action"))},
            sensitivity=tool.get("sensitivity") or descriptor.get("sensitivity") or {"level": 0},
            provenance=["llm_descriptor_artifact"], confidence="inferred",
            observations=tool.get("observations") or [],
            metadata={"tool": tool, "memory": descriptor.get("memory") or descriptor.get("data_stores") or {}},
        ))
    stores = descriptor.get("data_stores") or descriptor.get("memory") or []
    for store in _named_records(stores):
        profiles.append(FP.new_profile(
            action="memory_access", resource=store.get("name") or "llm-memory",
            protocol="llm-memory", actors=store.get("actors") or {},
            outputs=store.get("data") or store.get("schema") or {},
            sensitivity=store.get("sensitivity") or {"level": 0},
            provenance=["llm_descriptor_artifact"], confidence="inferred", metadata=store,
        ))
    return FP.merge_profiles(profiles)


def _text_files(root, suffixes, max_files=500):
    count = 0
    for base, _, files in os.walk(root):
        for name in files:
            if not name.lower().endswith(suffixes):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    yield path, fh.read(2_000_000)
                count += 1
                if count >= max_files:
                    return
            except OSError:
                continue


def _profiles_from_text(text, source, protocol):
    profiles = []
    for match in URL_RE.finditer(text):
        context = text[max(0, match.start() - 400):match.end() + 400]
        profiles.append(FP.from_endpoint({
            "url": match.group(0)[:500], "method": "POST" if CALL_RE.search(context) else "GET",
            "function": "backend_call", "protocol": protocol,
            "provenance": "static_artifact_observation", "confidence": "inferred", "source": source,
        }))
    for match in QUOTED_PATH_RE.finditer(text):
        context = text[max(0, match.start() - 300):match.end() + 300]
        if CALL_RE.search(context):
            profiles.append(FP.from_endpoint({
                "url": match.group(1), "method": "POST", "function": "backend_call",
                "protocol": protocol, "provenance": "static_artifact_observation",
                "confidence": "inferred", "source": source,
            }))
    return profiles


def _artifact_profiles(root, suffixes, protocol):
    profiles = []
    for path, text in _text_files(root, suffixes):
        profiles.extend(_profiles_from_text(text, path, protocol))
    return FP.merge_profiles(profiles)


def _android_manifest(path):
    profiles = []
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return profiles
    android = "{http://schemas.android.com/apk/res/android}"
    for component in root.iter():
        if component.tag.rsplit("}", 1)[-1] not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        name = component.get(android + "name") or "unknown-component"
        explicit = component.get(android + "exported")
        has_intent = any(child.tag.rsplit("}", 1)[-1] == "intent-filter" for child in component)
        external = explicit == "true" or (explicit is None and has_intent)
        profiles.append(FP.new_profile(
            action="ipc_component", resource=name, protocol="android-ipc",
            actors={"external": external}, provenance=["android_manifest_artifact"], confidence="inferred",
            metadata={"manifest": path, "exported": external},
        ))
    return profiles


def android_profiles(scan_dir):
    profiles = _artifact_profiles(scan_dir, (".java", ".kt", ".smali", ".xml", ".json", ".js"), "android")
    for base, _, files in os.walk(scan_dir):
        if "AndroidManifest.xml" in files:
            profiles.extend(_android_manifest(os.path.join(base, "AndroidManifest.xml")))
    return FP.merge_profiles(profiles)


def _zip_read(archive, name, limit=2_000_000):
    info = archive.getinfo(name)
    if info.file_size > limit:
        return None
    return archive.read(name)


def ios_profiles(ipa_path):
    profiles = []
    with zipfile.ZipFile(ipa_path) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")][:1000]
        for name in names:
            lower = name.lower()
            data = _zip_read(archive, name)
            if data is None:
                continue
            if lower.endswith("info.plist"):
                try:
                    plist = plistlib.loads(data)
                except Exception:
                    continue
                for url_type in plist.get("CFBundleURLTypes") or []:
                    for scheme in url_type.get("CFBundleURLSchemes") or []:
                        profiles.append(FP.new_profile(
                            action="url_scheme", resource=str(scheme), protocol="ios-url-scheme",
                            actors={"external": True}, provenance=["ios_info_plist_artifact"],
                            confidence="inferred", metadata={"plist": name},
                        ))
            elif lower.endswith((".swift", ".m", ".mm", ".h", ".json", ".js")):
                text = data.decode("utf-8", errors="ignore")
                profiles.extend(_profiles_from_text(text, name, "ios"))
            elif lower.endswith(".entitlements"):
                try:
                    entitlements = plistlib.loads(data)
                except Exception:
                    entitlements = {"raw_excerpt": data.decode("utf-8", errors="ignore")[:2000]}
                profiles.append(FP.new_profile(
                    action="entitlement_boundary", resource=name, protocol="ios-entitlements",
                    actors={"privileged": True}, provenance=["ios_entitlements_artifact"],
                    confidence="inferred", metadata={"entitlements": entitlements},
                ))
    return FP.merge_profiles(profiles)


def operation_profiles(operations, protocol="operation", provenance="operation_descriptor"):
    """Normalize operations declared by any transport or tool descriptor."""
    profiles = []
    for operation in _named_records(operations):
        endpoint = dict(operation)
        endpoint.setdefault("protocol", operation.get("transport") or protocol)
        endpoint.setdefault("url", operation.get("url") or operation.get("href") or operation.get("name") or "operation")
        endpoint.setdefault("provenance", provenance)
        endpoint.setdefault("confidence", "inferred")
        profiles.append(FP.from_endpoint(endpoint))
    return FP.merge_profiles(profiles)


def infrastructure_profiles(document, source="infrastructure"):
    """Profile declarative resource shape and references, not a service-specific rule list."""
    documents = document if isinstance(document, list) else [document]
    profiles = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = metadata.get("name") or item.get("name") or item.get("id") or "unnamed-resource"
        resource_type = item.get("kind") or item.get("type") or "declared-resource"
        body = item.get("spec") or item.get("properties") or item.get("configuration") or item
        inputs = [{"name": str(key), "location": "configuration", "type": type(value).__name__}
                  for key, value in (body or {}).items() if key not in ("apiVersion", "kind", "metadata")]
        relationships = [{"type": "reference", "target": match.group(0)}
                         for match in URL_RE.finditer(json.dumps(item, default=str))]
        profiles.append(FP.new_profile(
            action="declared_configuration", resource=f"{resource_type}/{name}", protocol="infrastructure",
            inputs=inputs, relationships=relationships, provenance=["infrastructure_artifact"],
            confidence="inferred", metadata={"source": source, "declaration": item},
        ))
    return FP.merge_profiles(profiles)


def terraform_profiles(text, source="terraform"):
    """Extract resource declarations and their observed configuration fields."""
    profiles = []
    pattern = re.compile(r'\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.M)
    for match in pattern.finditer(text):
        start = match.end()
        depth, end = 1, start
        while end < len(text) and depth:
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
            end += 1
        body = text[start:end - 1]
        inputs = [{"name": key, "location": "configuration", "type": "expression"}
                  for key in re.findall(r'^\s*([A-Za-z_][\w-]*)\s*=', body, re.M)]
        profiles.append(FP.new_profile(
            action="declared_configuration", resource=f"{match.group(1)}/{match.group(2)}",
            protocol="infrastructure", inputs=inputs, provenance=["infrastructure_artifact"],
            confidence="inferred", metadata={"source": source},
        ))
    return FP.merge_profiles(profiles)


def desktop_plist_profiles(plist, source="desktop"):
    """Normalize externally reachable declarations and privileges in desktop metadata."""
    operations = []
    for item in plist.get("CFBundleURLTypes") or []:
        for scheme in item.get("CFBundleURLSchemes") or []:
            operations.append({"name": str(scheme), "protocol": "desktop-url-scheme",
                               "function": "external_invocation", "actors": {"external": True}})
    for key, value in plist.items():
        if isinstance(value, dict):
            for name in value:
                operations.append({"name": str(name), "protocol": "desktop-declaration",
                                   "function": str(key), "metadata": {"declaration": value[name]}})
        elif isinstance(value, list) and value:
            operations.append({"name": str(key), "protocol": "desktop-declaration",
                               "function": str(key), "outputs": {"declared_count": len(value)}})
    profiles = operation_profiles(operations, provenance="desktop_plist_artifact")
    if not profiles:
        profiles = [FP.new_profile("application_metadata", plist.get("CFBundleIdentifier") or source,
                                   protocol="desktop-application", inputs=[
                                       {"name": key, "location": "metadata", "type": type(value).__name__}
                                       for key, value in plist.items()],
                                   provenance=["desktop_plist_artifact"], confidence="inferred",
                                   metadata={"source": source})]
    return FP.merge_profiles(profiles)


def contract_profiles(text, source="contract-source"):
    """Extract callable source functions, arguments, guards, and observable effects."""
    profiles = []
    pattern = re.compile(r'\b(?:pub\s+)?(?:external\s+)?function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^\{]*)', re.M)
    for match in pattern.finditer(text):
        arguments = []
        for index, argument in enumerate(match.group(2).split(",")):
            argument = argument.strip()
            if argument:
                arguments.append({"name": argument.split()[0] if argument.split() else f"arg{index}",
                                  "location": "call", "type": "source-declared"})
        trailer = match.group(3)
        effects = [{"type": "state_change"}]
        if re.search(r'\b(?:pure|view)\b', trailer):
            effects = []
        profiles.append(FP.new_profile(
            action=match.group(1), resource=source, protocol="contract-source", inputs=arguments,
            effects=effects, preconditions=re.findall(r'\b(?:require|assert|only\w+)\b', trailer),
            state={"mutates": bool(effects)}, provenance=["contract_source_artifact"], confidence="inferred",
            metadata={"source": source, "declaration": match.group(0)[:500]},
        ))
    return FP.merge_profiles(profiles)


def adapt(source, base_url=""):
    """Adapt observed input by shape and artifact magic, retaining unknown residuals."""
    residuals = []
    adapter = "unknown"
    profiles = []
    try:
        if isinstance(source, dict):
            if "resources" in source:
                adapter, profiles = "cloud", cloud_profiles(source)
            elif any(key in source for key in ("tools", "functions", "memory", "data_stores")):
                adapter, profiles = "llm", llm_profiles(source)
            elif "endpoints" in source:
                adapter, profiles = "http", http_profiles(source.get("endpoints"), base_url)
            elif source.get("url") or source.get("path"):
                adapter, profiles = "http", http_profiles([source], base_url)
            else:
                residuals.append({"reason": "unrecognized_descriptor", "keys": sorted(source)[:30]})
        elif isinstance(source, list):
            adapter, profiles = "http", http_profiles(source, base_url)
        elif isinstance(source, (str, os.PathLike)):
            path = os.fspath(source)
            if os.path.isdir(path) and path.lower().endswith(".app"):
                plist_path = os.path.join(path, "Contents", "Info.plist")
                with open(plist_path, "rb") as fh:
                    adapter, profiles = "desktop", desktop_plist_profiles(plistlib.load(fh), path)
            elif os.path.isdir(path):
                adapter, profiles = "android", android_profiles(path)
            elif zipfile.is_zipfile(path):
                adapter, profiles = "ios", ios_profiles(path)
            elif os.path.isfile(path):
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read(2_000_000)
                suffix = os.path.splitext(path)[1].lower()
                if suffix == ".plist":
                    adapter, profiles = "desktop", desktop_plist_profiles(plistlib.loads(text.encode()), path)
                elif suffix == ".tf":
                    adapter, profiles = "infrastructure", terraform_profiles(text, path)
                elif suffix in (".yaml", ".yml"):
                    import yaml
                    adapter, profiles = "infrastructure", infrastructure_profiles(list(yaml.safe_load_all(text)), path)
                elif suffix in (".sol", ".vy", ".move", ".rs"):
                    adapter, profiles = "contract", contract_profiles(text, path)
                else:
                    try:
                        return adapt(json.loads(text), base_url)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        profiles = _profiles_from_text(text, path, "artifact")
                        adapter = "text-artifact" if profiles else "unknown"
                if not profiles:
                    residuals.append({"reason": "unparsed_artifact", "source": path})
            else:
                residuals.append({"reason": "input_not_found", "source": path})
        else:
            residuals.append({"reason": "unsupported_input_type", "type": type(source).__name__})
    except (OSError, ValueError, TypeError, zipfile.BadZipFile) as exc:
        residuals.append({"reason": f"{type(exc).__name__}: {exc}"})
    if residuals and profiles:
        status = "partial"
    elif profiles:
        status = "completed"
    elif residuals:
        status = "unavailable"
    else:
        status = "not_applicable"
        residuals.append({"reason": "no_functions_observed"})
    return {"adapter": adapter, "status": status, "profiles": FP.merge_profiles(profiles),
            "residuals": residuals}
