#!/usr/bin/env python3
"""Parse style policy commands and emit structured JSON."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ATTR_REGEX = re.compile(r"(\w+)=\"([^\"]*)\"|(\w+)=([^,;]+)")
TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DEFAULT_RULESET_MAP = Path("ruleset_mapping_template.json")
DEFAULT_OUTPUT_TEMPLATE = "{stem}_MAV_{timestamp}"
PROTOCOL_TOKENS = {
    "ANY": "ip",
    "IP": "ip",
    "TCP": "6",
    "UDP": "17",
    "ICMP": "1",
    "IGMP": "2",
    "SCTP": "132",
    "ESP": "50",
    "AH": "51",
}


def normalize_rule_name(name: str) -> str:
    return name.replace("&", "_")


def sanitize_identifier(value: Any) -> str:
    """Replace non-word characters with underscores for policy identifiers."""
    text = value if isinstance(value, str) else str(value or "")
    sanitized = re.sub(r"[^\w]", "_", text)
    sanitized = re.sub(r"_+", "_", sanitized)
    return sanitized or "_"


def parse_bool_flag(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return default


def default_usage_flags() -> Dict[str, bool]:
    return {"online": True, "offline": True, "monitoring": True}


def extract_rule_name(entry: Any) -> Optional[str]:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        name = entry.get("ruleName") or entry.get("name")
        if isinstance(name, str):
            return name
    return None


def extract_usage_flags(entry: Dict[str, Any]) -> Dict[str, bool]:
    flags = default_usage_flags()
    usage_block = entry.get("usage")
    for key in flags:
        if key in entry:
            flags[key] = parse_bool_flag(entry[key], flags[key])
        elif isinstance(usage_block, dict) and key in usage_block:
            flags[key] = parse_bool_flag(usage_block[key], flags[key])
    return flags


def cast_value(raw: str) -> Any:
    if raw.isdigit():
        return int(raw)
    try:
        return float(raw)
    except ValueError:
        pass
    upper = raw.upper()
    if upper in {"TRUE", "FALSE"}:
        return upper == "TRUE"
    return raw


def parse_attributes(command: str) -> Dict[str, Any]:
    if ":" not in command:
        return {}
    payload = command.split(":", 1)[1].rstrip(";")
    attributes: Dict[str, Any] = {}
    for match in ATTR_REGEX.finditer(payload):
        key = match.group(1) or match.group(3)
        raw_value = match.group(2) if match.group(2) is not None else match.group(4)
        if key is None or raw_value is None:
            continue
        value = cast_value(raw_value.strip())
        attributes[key.upper()] = value
    return attributes


def collect_commands(lines: List[str]) -> List[str]:
    commands: List[str] = []
    buffer = ""
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.upper().startswith("NAME") and ":" not in line:
            continue
        if line.upper() in {"ADD", "L7FILTERNAME"}:
            continue
        buffer = f"{buffer} {line}".strip() if buffer else line
        if line.endswith(";"):
            commands.append(buffer)
            buffer = ""
    if buffer:
        commands.append(buffer)
    return commands


def build_flow_filter(name: str, bindings: Dict[str, Dict[str, List[Any]]], filters: Dict[str, Dict[str, Any]], l7_filters: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if name not in bindings:
        return None
    entry = bindings[name]
    flow_filter: Dict[str, Any] = {}
    if entry.get("filters"):
        flow_filter["FLTBINDFLOWF"] = []
        for filter_name in entry["filters"]:
            filter_info: Dict[str, Any] = {"FILTERNAME": filter_name}
            definition = filters.get(filter_name)
            if definition:
                filter_info["FILTER"] = {k: v for k, v in definition.items() if k != "FILTERNAME"}
            flow_filter["FLTBINDFLOWF"].append(filter_info)
    if entry.get("protocolBindings"):
        flow_filter["PROTBINDFLOWF"] = []
        for binding in entry["protocolBindings"]:
            binding_payload = {k: v for k, v in binding.items() if k != "FLOWFILTERNAME"}
            l7_name = binding.get("L7FILTERNAME")
            if l7_name and l7_name in l7_filters:
                l7_payload = dict(l7_filters[l7_name])
                binding_payload["L7FILTER"] = l7_payload
            flow_filter["PROTBINDFLOWF"].append(binding_payload)
    return flow_filter or None


def build_policy_group(name: str, policy_groups: Dict[str, Dict[str, Any]], charge_props: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if name not in policy_groups:
        return None
    payload = dict(policy_groups[name])
    result: Dict[str, Any] = payload
    charge_name = payload.get("CHARGEPROPNAME")
    if charge_name and charge_name in charge_props:
        charge_payload = dict(charge_props[charge_name])
        result["CHARGEPROP"] = charge_payload
    return result


def parse_file(path: Path) -> Tuple[Dict[str, Any], Dict[str, List[Dict[str, Any]]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    commands = collect_commands(lines)

    rule_bindings: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    flow_bindings: Dict[str, Dict[str, List[Any]]] = {}
    filters: Dict[str, Dict[str, Any]] = {}
    l7_filters: Dict[str, Dict[str, Any]] = {}
    policy_groups: Dict[str, Dict[str, Any]] = {}
    charge_props: Dict[str, Dict[str, Any]] = {}
    ip_lists: Dict[str, List[Dict[str, Any]]] = {}

    for command in commands:
        if command.startswith("ADD RULEBINDING"):
            attrs = parse_attributes(command)
            if attrs:
                rule_bindings.append(attrs)
        elif command.startswith("ADD RULE"):
            attrs = parse_attributes(command)
            name = attrs.get("RULENAME")
            if name:
                rules[name] = attrs
        elif command.startswith("ADD FLTBINDFLOWF"):
            attrs = parse_attributes(command)
            flow_name = attrs.get("FLOWFILTERNAME")
            filter_name = attrs.get("FILTERNAME")
            if flow_name:
                entry = flow_bindings.setdefault(flow_name, {"filters": [], "protocolBindings": []})
                if filter_name:
                    entry["filters"].append(filter_name)
        elif command.startswith("ADD PROTBINDFLOWF"):
            attrs = parse_attributes(command)
            flow_name = attrs.get("FLOWFILTERNAME")
            if flow_name:
                entry = flow_bindings.setdefault(flow_name, {"filters": [], "protocolBindings": []})
                entry["protocolBindings"].append(attrs)
        elif command.startswith("ADD FILTER"):
            attrs = parse_attributes(command)
            name = attrs.get("FILTERNAME")
            if name:
                filters[name] = attrs
        elif command.startswith("ADD L7FILTER"):
            attrs = parse_attributes(command)
            name = attrs.get("L7FILTERNAME")
            if name:
                l7_filters[name] = attrs
        elif command.startswith("ADD PCCPOLICYGRP"):
            attrs = parse_attributes(command)
            name = attrs.get("PCCPOLICYGRPNM")
            if name:
                policy_groups[name] = attrs
        elif command.startswith("ADD CHARGEPROP"):
            attrs = parse_attributes(command)
            name = attrs.get("CHARGEPROPNAME")
            if name:
                charge_props[name] = attrs
        elif command.startswith("ADD IPLIST"):
            attrs = parse_attributes(command)
            name = attrs.get("IPLISTNAME")
            if name:
                entry = {k: v for k, v in attrs.items() if k != "IPLISTNAME"}
                ip_lists.setdefault(name, []).append(entry)

    output: Dict[str, Any] = {}
    for binding in rule_bindings:
        profile = binding.get("USERPROFILENAME")
        rule_name = binding.get("RULENAME")
        if not profile:
            continue
        profile_entry = output.setdefault(profile, {"RULEBINDING": [], "RULE": {}})
        binding_payload = dict(binding)
        binding_payload.pop("USERPROFILENAME", None)
        profile_entry["RULEBINDING"].append(binding_payload)
        if rule_name and rule_name in rules:
            rule_attrs = rules[rule_name]
            rule_payload = dict(rule_attrs)
            flow_name = rule_attrs.get("FLOWFILTERNAME")
            if isinstance(flow_name, str):
                flow_filter = build_flow_filter(flow_name, flow_bindings, filters, l7_filters)
                if flow_filter:
                    if flow_filter.get("FLTBINDFLOWF"):
                        rule_payload["FLTBINDFLOWF"] = flow_filter["FLTBINDFLOWF"]
                    if flow_filter.get("PROTBINDFLOWF"):
                        rule_payload["PROTBINDFLOWF"] = flow_filter["PROTBINDFLOWF"]
            policy_name = rule_attrs.get("POLICYNAME")
            if isinstance(policy_name, str):
                policy_group = build_policy_group(policy_name, policy_groups, charge_props)
                if policy_group:
                    rule_payload["PCCPOLICYGRP"] = policy_group
            profile_entry["RULE"][rule_name] = rule_payload
    return output, ip_lists


def load_ruleset_map(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        raise SystemExit("A rule-set mapping file is required")
    try:
        mapping_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"Rule-set mapping file not found: {path}")
    mapping_data = json.loads(mapping_text)
    entries = mapping_data.get("ruleSetMap", [])
    if not isinstance(entries, list):
        raise SystemExit("ruleSetMap must be an array")
    return entries


def filter_profiles(data: Dict[str, Any], mapping: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    filtered_json: Dict[str, Any] = {}
    command_profiles: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for entry in mapping:
        profile_name = entry.get("userProfileName")
        rule_set = entry.get("ruleSet")
        allowed_rules = entry.get("rules", []) or []
        if not isinstance(profile_name, str) or not isinstance(rule_set, str):
            continue
        profile_data = data.get(profile_name)
        if not profile_data:
            warnings.append(f"Profile {profile_name} not found in source commands")
            continue
        allowed_set = {
            name
            for name in (extract_rule_name(rule_entry) for rule_entry in allowed_rules)
            if isinstance(name, str)
        }
        rule_payload = profile_data.get("RULE", {}) or {}
        filtered_rules = {name: payload for name, payload in rule_payload.items() if name in allowed_set}
        if not filtered_rules:
            warnings.append(f"Profile {profile_name} has no matching rules from mapping list")
            continue
        filtered_bindings = [
            binding
            for binding in profile_data.get("RULEBINDING", []) or []
            if binding.get("RULENAME") in allowed_set
        ]
        usage_flags = extract_usage_flags(entry)
        profile_entry = {
            "RULEBINDING": filtered_bindings,
            "RULE": filtered_rules,
        }
        filtered_json[profile_name] = profile_entry
        command_profiles.append({
            "USERPROFILENAME": profile_name,
            "RULESET": rule_set,
            "RULEBINDING": filtered_bindings,
            "RULE": filtered_rules,
            "USAGE_FLAGS": usage_flags,
        })
    return filtered_json, command_profiles, warnings


def precedence_for_rule(rule_name: str, bindings: Iterable[Dict[str, Any]], fallback: Any) -> Any:
    for binding in bindings:
        if binding.get("RULENAME") == rule_name and "PRIORITY" in binding:
            return binding["PRIORITY"]
    return fallback


def refchg_and_thr(rule_name: str, rule_data: Dict[str, Any]) -> Tuple[str, str]:
    policy_group = rule_data.get("PCCPOLICYGRP") or {}
    ref_chg = None
    thr_source = None
    if isinstance(policy_group, dict):
        ref_chg = policy_group.get("CHARGEPROPNAME")
        if not ref_chg:
            charge = policy_group.get("CHARGEPROP")
            if isinstance(charge, dict):
                ref_chg = charge.get("CHARGEPROPNAME")
        thr_source = policy_group.get("PCCPOLICYGRPNM")
    if not thr_source:
        thr_source = rule_data.get("POLICYNAME")
    if not isinstance(thr_source, str) or not thr_source:
        raise ValueError(f"Rule {rule_name} missing PCCPOLICYGRPNM/POLICYNAME")
    if not isinstance(ref_chg, str) or not ref_chg:
        raise ValueError(f"Rule {rule_name} missing CHARGEPROPNAME")
    return ref_chg, thr_source


def monitoring_key_for_rule(rule_data: Dict[str, Any]) -> Optional[Any]:
    key = rule_data.get("MONITORINGKEY")
    if key is not None:
        return key
    policy_group = rule_data.get("PCCPOLICYGRP")
    if isinstance(policy_group, dict):
        return policy_group.get("MONITORINGKEY")
    return None


def collect_filter_names(rule_data: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for entry in rule_data.get("FLTBINDFLOWF", []) or []:
        if isinstance(entry, dict):
            name = entry.get("FILTERNAME")
            if isinstance(name, str):
                names.append(name)
    for entry in rule_data.get("PROTBINDFLOWF", []) or []:
        if isinstance(entry, dict):
            name = entry.get("L7FILTERNAME")
            if isinstance(name, str):
                names.append(name)
    deduped: List[str] = []
    seen = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def protocol_token(value: Any) -> str:
    if isinstance(value, str):
        lookup = PROTOCOL_TOKENS.get(value.upper())
        if lookup:
            return lookup
        return value.lower()
    if isinstance(value, (int, float)):
        return str(int(value))
    return "ip"


def netmask_to_prefix(mask: str) -> Optional[int]:
    try:
        parts = [int(part) for part in mask.split(".")]
    except ValueError:
        return None
    if len(parts) != 4:
        return None
    binary = "".join(f"{part:08b}" for part in parts)
    return binary.count("1")


def format_ip_with_mask(
    ip: Optional[str], mask_type: Optional[str], mask_value: Optional[Any], mask_len: Optional[Any]
) -> Optional[str]:
    if not isinstance(ip, str) or not ip:
        return None
    suffix = ""
    if isinstance(mask_type, str):
        mask_type_upper = mask_type.upper()
        if mask_type_upper == "LENGTHTYPE" and isinstance(mask_len, int):
            suffix = f"/{mask_len}"
        elif mask_type_upper == "IPTYPE" and isinstance(mask_value, str) and mask_value != "0.0.0.0":
            prefix = netmask_to_prefix(mask_value)
            if prefix is not None:
                suffix = f"/{prefix}"
    return f"{ip}{suffix}"


def format_ip_list_entry(entry: Dict[str, Any]) -> Optional[str]:
    ip = entry.get("IPV4ADDR") or entry.get("IPV6ADDR")
    if not isinstance(ip, str):
        return None
    mask_value = entry.get("MASKVALUE")
    if isinstance(mask_value, int):
        return f"{ip}/{mask_value}"
    return ip


def resolve_ip_targets(prefix: str, filter_data: Dict[str, Any], ip_lists: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    mode = filter_data.get(f"{prefix}IPMODE")
    mode_upper = mode.upper() if isinstance(mode, str) else ""
    if not mode_upper or mode_upper == "ANY":
        return ["any"]
    if mode_upper == "IP":
        desc = format_ip_with_mask(
            filter_data.get(f"{prefix}IP"),
            filter_data.get(f"{prefix}IPMASKTYPE"),
            filter_data.get(f"{prefix}IPMASK"),
            filter_data.get(f"{prefix}IPMASKLEN"),
        )
        return [desc or "any"]
    if mode_upper == "IPLIST":
        list_name = filter_data.get(f"{prefix}IPLISTNAME")
        entries = ip_lists.get(list_name, [])
        resolved = [value for value in (format_ip_list_entry(entry) for entry in entries) if value]
        if resolved:
            return resolved
        return [list_name or "any"]
    if mode_upper == "IPRANGE":
        start = filter_data.get(f"{prefix}IPSTART")
        end = filter_data.get(f"{prefix}IPEND")
        if isinstance(start, str) and isinstance(end, str):
            return [f"{start}-{end}"]
    return ["any"]


def format_port_suffix(start: Any, end: Any) -> str:
    if not isinstance(start, int) or not isinstance(end, int):
        return ""
    if start == 0 and end == 65535:
        return ""
    if start == end:
        return f" {start}"
    return f" {start}-{end}"


def format_filter_statements(filter_data: Dict[str, Any], ip_lists: Dict[str, List[Dict[str, Any]]]) -> List[str]:
    proto = protocol_token(filter_data.get("L34PROTOCOL"))
    server_targets = resolve_ip_targets("SVR", filter_data, ip_lists)
    ue_targets = resolve_ip_targets("MS", filter_data, ip_lists)
    server_port_suffix = format_port_suffix(filter_data.get("SVRSTARTPORT"), filter_data.get("SVRENDPORT"))
    ue_port_suffix = format_port_suffix(filter_data.get("MSSTARTPORT"), filter_data.get("MSENDPORT"))
    statements: List[str] = []
    for server in server_targets or ["any"]:
        srv_desc = server or "any"
        for ue in ue_targets or ["any"]:
            ue_desc = ue or "any"
            statements.append(
                f"permit out {proto} from {srv_desc}{server_port_suffix} to {ue_desc}{ue_port_suffix}"
            )
    return statements


def build_filter_commands(
    filters: Dict[str, Dict[str, Any]], ip_lists: Dict[str, List[Dict[str, Any]]]
) -> List[str]:
    if not filters:
        return ["# No L3/L4 filters referenced"]
    lines: List[str] = []
    for name, payload in filters.items():
        statements = format_filter_statements(payload, ip_lists)
        if not statements:
            continue
        lines.append(f"# {name}")
        for description in statements:
            lines.append(
                f"set UPFFunction Policy upfpolicy packetFilters {name} flowInfo flowDescription \"{description}\""
            )
        lines.append(
            f"set UPFFunction Policy upfpolicy packetFilters {name} flowInfo flowDirection bidirectional"
        )
        lines.append(
            f"set UPFFunction Policy upfpolicy packetFilters {name} flowInfo packetFilterUsage true"
        )
        lines.append("")
    if lines:
        lines.pop()
    return lines or ["# No L3/L4 filters referenced"]


def rating_group_from_charge(charge_name: str) -> str:
    match = re.search(r"(\d+)$", charge_name)
    if match:
        return match.group(1)
    return "xxxxxxxxxx"


def needs_dual_usage_reporting(rule_data: Dict[str, Any]) -> Optional[str]:
    policy_group = rule_data.get("PCCPOLICYGRP")
    if not isinstance(policy_group, dict):
        return None
    charge = policy_group.get("CHARGEPROP")
    if not isinstance(charge, dict):
        return None
    required_fields = [
        "CHARGEPROPNAME",
        "DOWNCBBIDNAME",
        "UPCBBIDNAME",
        "ONLDNCBBIDNAME",
        "ONLUPCBBIDNAME",
    ]
    if not all(field in charge for field in required_fields):
        return None
    offline_down = charge.get("DOWNCBBIDNAME")
    offline_up = charge.get("UPCBBIDNAME")
    online_down = charge.get("ONLDNCBBIDNAME")
    online_up = charge.get("ONLUPCBBIDNAME")
    if offline_down == online_down and offline_up == online_up:
        return None
    thr_source = policy_group.get("PCCPOLICYGRPNM") or rule_data.get("POLICYNAME")
    if not thr_source:
        return None
    return thr_source


def render_rule(
    rule_set: str, rule_name: str, rule_data: Dict[str, Any], bindings: List[Dict[str, Any]]
) -> Tuple[List[str], str, str]:
    if not rule_set:
        raise ValueError(f"Rule {rule_name} missing ruleSet identifier")
    precedence = precedence_for_rule(rule_name, bindings, rule_data.get("PRIORITY"))
    ref_chg, thr_source = refchg_and_thr(rule_name, rule_data)
    safe_rule_name = normalize_rule_name(rule_name)
    thr_source_token = sanitize_identifier(thr_source)
    rule_set_token = sanitize_identifier(rule_set)
    thr_rule_token = sanitize_identifier(safe_rule_name)
    thr_identifier = f"thr_{thr_source_token}_{rule_set_token}_{thr_rule_token}"
    commands = [
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} precedence {precedence}",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} refChgData {ref_chg}",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} trafficHandlingRules [ {thr_identifier} ]",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} status active",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} tethering false",
    ]
    return commands, thr_identifier, ref_chg


def build_command_list(
    profiles: List[Dict[str, Any]], ip_lists: Dict[str, List[Dict[str, Any]]]
) -> Tuple[List[str], List[str], List[str]]:
    output_lines: List[str] = []
    errors: List[str] = []
    next_online_urr = 101
    next_offline_urr = 301
    next_monitoring_urr = 501
    next_pdr_id = 601
    collected_filters: Dict[str, Dict[str, Any]] = {}
    for profile in profiles:
        user_profile = profile.get("USERPROFILENAME", "")
        rule_set = profile.get("RULESET") or (user_profile.upper() if isinstance(user_profile, str) else "")
        rule_map = profile.get("RULE", {})
        usage_flags = profile.get("USAGE_FLAGS") or default_usage_flags()
        if not isinstance(user_profile, str) or not isinstance(rule_map, dict):
            continue
        binding_index: Dict[str, List[Dict[str, Any]]] = {}
        for entry in profile.get("RULEBINDING", []) or []:
            if not isinstance(entry, dict):
                continue
            rule_name = entry.get("RULENAME")
            if not isinstance(rule_name, str):
                continue
            binding_index.setdefault(rule_name, []).append(entry)
        for rule_name, rule_data in rule_map.items():
            if not isinstance(rule_data, dict):
                continue
            bindings = binding_index.get(rule_name, [])
            try:
                rule_commands, thr_identifier, ref_chg = render_rule(rule_set, rule_name, rule_data, bindings)
                safe_rule_name = normalize_rule_name(rule_name)
                monitoring_enabled = usage_flags.get("monitoring", True)
                online_enabled = usage_flags.get("online", True)
                offline_enabled = usage_flags.get("offline", True)
                if output_lines and output_lines[-1] != "":
                    output_lines.append("")
                output_lines.append(f"# {rule_set} - {safe_rule_name}")
                output_lines.extend(rule_commands)
                rating_group = rating_group_from_charge(ref_chg)
                output_lines.append(
                    f"set SMFFunction Policy smfpolicy chargingData {ref_chg} ratingGroup {rating_group}"
                )
                monitoring_key = monitoring_key_for_rule(rule_data)
                usage_commands: List[str] = []
                thr_usage: Dict[str, List[int]] = {}
                thr_order: List[str] = []

                def add_thr_usage(thr_tag: str, urr_id: int) -> None:
                    if thr_tag not in thr_usage:
                        thr_usage[thr_tag] = []
                        thr_order.append(thr_tag)
                    thr_usage[thr_tag].append(urr_id)

                if monitoring_enabled and monitoring_key is not None:
                    monitoring_urr = next_monitoring_urr
                    next_monitoring_urr += 1
                    output_lines.append(
                        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {safe_rule_name} monitoringKey {monitoring_key}"
                    )
                    add_thr_usage(thr_identifier, monitoring_urr)
                    usage_commands.append(
                        f"set SMFFunction Policy smfpolicy usageReportRules {monitoring_urr} urrType UM"
                    )
                usage_thr = needs_dual_usage_reporting(rule_data)
                if usage_thr and (online_enabled or offline_enabled):
                    if online_enabled:
                        online_id = next_online_urr
                        next_online_urr += 1
                        add_thr_usage(thr_identifier, online_id)
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {online_id} urrType online"
                        )
                    if offline_enabled:
                        offline_id = next_offline_urr
                        next_offline_urr += 1
                        add_thr_usage(thr_identifier, offline_id)
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {offline_id} urrType offline"
                        )
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {offline_id} measurementMethod both"
                        )
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {offline_id} reportingTriggers [ LIUSA ]"
                        )
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {offline_id} linkedUrrId 1"
                        )
                        usage_commands.append(
                            f"set SMFFunction Policy smfpolicy usageReportRules {offline_id} udrProfileIndex 1"
                        )
                for thr_tag in thr_order:
                    ids = " ".join(str(value) for value in thr_usage[thr_tag])
                    output_lines.append(
                        f"set SMFFunction Policy smfpolicy trafficHandlingRules {thr_tag} usageReportRules [ {ids} ]"
                    )
                output_lines.extend(usage_commands)
                filter_names = collect_filter_names(rule_data)
                sanitized_filter_names: List[str] = []
                seen_sanitized_filters = set()
                for name in filter_names:
                    sanitized_name = sanitize_identifier(name)
                    if sanitized_name not in seen_sanitized_filters:
                        seen_sanitized_filters.add(sanitized_name)
                        sanitized_filter_names.append(sanitized_name)
                for filter_entry in rule_data.get("FLTBINDFLOWF", []) or []:
                    if not isinstance(filter_entry, dict):
                        continue
                    filter_name = filter_entry.get("FILTERNAME")
                    filter_payload = filter_entry.get("FILTER")
                    if isinstance(filter_name, str) and isinstance(filter_payload, dict):
                        sanitized_filter_name = sanitize_identifier(filter_name)
                        if sanitized_filter_name not in collected_filters:
                            collected_filters[sanitized_filter_name] = filter_payload
                if sanitized_filter_names:
                    filter_block = " ".join(sanitized_filter_names)
                    output_lines.append(
                        f"set SMFFunction Policy smfpolicy pccRules {safe_rule_name} pdrId {next_pdr_id}"
                    )
                    output_lines.append(
                        f"set SMFFunction Policy smfpolicy pccRules {safe_rule_name} filterList [ {filter_block} ]"
                    )
                    output_lines.append(
                        f"set SMFFunction Policy smfpolicy pccRules {safe_rule_name} trafficControlStatus enableBidirectional"
                    )
                    next_pdr_id += 1
                output_lines.append("")
            except ValueError as exc:
                errors.append(str(exc))
    if collected_filters:
        if output_lines and output_lines[-1] != "":
            output_lines.append("")
        output_lines.append("# Packet filter definitions")
        for filter_name in collected_filters:
            output_lines.append(
                f"set SMFFunction Policy smfpolicy packetFilters {filter_name} flowInfo flowDescription \"permit out ip from any to assigned\""
            )
            output_lines.append(
                f"set SMFFunction Policy smfpolicy packetFilters {filter_name} flowInfo flowDirection bidirectional"
            )
            output_lines.append(
                f"set SMFFunction Policy smfpolicy packetFilters {filter_name} flowInfo packetFilterUsage false"
            )
            output_lines.append("")
    if output_lines:
        output_lines.pop()
    filter_commands = build_filter_commands(collected_filters, ip_lists)
    return output_lines, filter_commands, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate JSON and MAV commands from policy commands")
    parser.add_argument("-i", "--input", dest="input_path", type=Path, help="Text file containing ADD commands")
    parser.add_argument("legacy_input", nargs="?", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "-o",
        "--output",
        dest="commands_output",
        type=Path,
        help="Path to write MAV command output (defaults to <input>_MAV_<timestamp>.txt)",
    )
    parser.add_argument(
        "-r",
        "--ruleset-map",
        dest="ruleset_map",
        type=Path,
        default=DEFAULT_RULESET_MAP,
        help="JSON file describing ruleSet/userProfile mappings",
    )
    args = parser.parse_args()

    input_path = args.input_path or args.legacy_input
    if input_path is None:
        parser.error("An input file must be specified via -i/--input")

    data, ip_lists = parse_file(input_path)
    ruleset_entries = load_ruleset_map(args.ruleset_map)
    filtered_json, profiles, mapping_warnings = filter_profiles(data, ruleset_entries)

    timestamp = datetime.now().strftime(TIMESTAMP_FORMAT)
    default_base_name = DEFAULT_OUTPUT_TEMPLATE.format(stem=input_path.stem, timestamp=timestamp)
    default_base = Path.cwd() / default_base_name
    default_commands_path = default_base.with_suffix(".txt")
    commands_path = args.commands_output or default_commands_path
    json_path = commands_path.with_suffix(".json")
    json_path.write_text(json.dumps(filtered_json, indent=2, sort_keys=True), encoding="utf-8")
    print(f"JSON written to {json_path}")

    commands, filter_commands, errors = build_command_list(profiles, ip_lists)
    commands_path.write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")
    print(f"Commands written to {commands_path}")
    filters_path = Path.cwd() / f"{input_path.stem}_UPF_Filters_{timestamp}.txt"
    filters_path.write_text("\n".join(filter_commands) + ("\n" if filter_commands else ""), encoding="utf-8")
    print(f"Filters written to {filters_path}")
    for warning in mapping_warnings:
        print(f"Mapping warning: {warning}")
    if errors:
        print("Skipped rules:")
        for message in errors:
            print(f"  - {message}")


if __name__ == "__main__":
    main()
