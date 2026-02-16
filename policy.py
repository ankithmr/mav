#!/usr/bin/env python3
"""Parse policy commands and emit structured JSON."""

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ATTR_REGEX = re.compile(r"(\w+)=\"([^\"]*)\"|(\w+)=([^,;]+)")


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


def parse_file(path: Path) -> Dict[str, Any]:
    lines = path.read_text(encoding="utf-8").splitlines()
    commands = collect_commands(lines)

    rule_bindings: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    flow_bindings: Dict[str, Dict[str, List[Any]]] = {}
    filters: Dict[str, Dict[str, Any]] = {}
    l7_filters: Dict[str, Dict[str, Any]] = {}
    policy_groups: Dict[str, Dict[str, Any]] = {}
    charge_props: Dict[str, Dict[str, Any]] = {}

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
    return output


def load_ruleset_map(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    try:
        mapping_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    mapping_data = json.loads(mapping_text)
    entries = mapping_data.get("ruleSetMap", [])
    return entries if isinstance(entries, list) else []


def filter_profiles(data: Dict[str, Any], mapping: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    if not mapping:
        profiles = []
        for user_profile, payload in data.items():
            profiles.append({
                "USERPROFILENAME": user_profile,
                "RULESET": user_profile.upper(),
                "RULEBINDING": payload.get("RULEBINDING", []),
                "RULE": payload.get("RULE", {}),
            })
        return data, profiles, []

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
        allowed_set = {name for name in allowed_rules if isinstance(name, str)}
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
        profile_entry = {
            "RULESET": rule_set,
            "RULEBINDING": filtered_bindings,
            "RULE": filtered_rules,
        }
        filtered_json[profile_name] = profile_entry
        command_profiles.append({
            "USERPROFILENAME": profile_name,
            **profile_entry,
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


def render_rule(rule_set: str, rule_name: str, rule_data: Dict[str, Any], bindings: List[Dict[str, Any]]) -> List[str]:
    if not rule_set:
        raise ValueError(f"Rule {rule_name} missing ruleSet identifier")
    precedence = precedence_for_rule(rule_name, bindings, rule_data.get("PRIORITY"))
    ref_chg, thr_source = refchg_and_thr(rule_name, rule_data)
    return [
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {rule_name} precedence {precedence}",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {rule_name} refChgData {ref_chg}",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {rule_name} trafficHandlingRules [ thr_{thr_source} ]",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {rule_name} status active",
        f"set SMFFunction Policy smfpolicy ruleSets {rule_set} rules {rule_name} tethering false",
    ]


def build_command_list(profiles: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    output_lines: List[str] = []
    errors: List[str] = []
    for profile in profiles:
        user_profile = profile.get("USERPROFILENAME", "")
        rule_set = profile.get("RULESET") or (user_profile.upper() if isinstance(user_profile, str) else "")
        rule_map = profile.get("RULE", {})
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
                output_lines.extend(render_rule(rule_set, rule_name, rule_data, bindings))
                output_lines.append("")
            except ValueError as exc:
                errors.append(str(exc))
    if output_lines:
        output_lines.pop()
    return output_lines, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate JSON and MAV commands from policy commands")
    parser.add_argument("input", type=Path, help="Text file containing ADD commands")
    parser.add_argument("-o", "--output", dest="json_output", type=Path, help="Path to write JSON output")
    parser.add_argument("-m", "--mav-output", dest="commands_output", type=Path, help="Path to write MAV commands")
    parser.add_argument(
        "-r",
        "--ruleset-map",
        dest="ruleset_map",
        type=Path,
        default=Path("ruleset_mapping_template.json"),
        help="JSON file describing ruleSet/userProfile mappings",
    )
    args = parser.parse_args()

    data = parse_file(args.input)
    ruleset_entries = load_ruleset_map(args.ruleset_map)
    filtered_json, profiles, mapping_warnings = filter_profiles(data, ruleset_entries)

    json_path = args.json_output or args.input.with_suffix(".json")
    json_path.write_text(json.dumps(filtered_json, indent=2, sort_keys=True), encoding="utf-8")
    print(f"JSON written to {json_path}")

    commands, errors = build_command_list(profiles)
    commands_path = args.commands_output or Path("mav.txt")
    commands_path.write_text("\n".join(commands) + ("\n" if commands else ""), encoding="utf-8")
    print(f"Commands written to {commands_path}")
    for warning in mapping_warnings:
        print(f"Mapping warning: {warning}")
    if errors:
        print("Skipped rules:")
        for message in errors:
            print(f"  - {message}")


if __name__ == "__main__":
    main()
