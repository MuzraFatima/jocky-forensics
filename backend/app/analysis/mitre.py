"""
JOCKY MITRE ATT&CK Matrix Correlation & Forensic Analysis Module (Phase 5)

Connects Advanced Technique Findings to the MITRE ATT&CK Enterprise Matrix:
- Groups forensic findings by kill-chain tactics (Initial Access, Execution, Persistence, etc.)
- Maps observable indicators and explanations to authoritative MITRE Technique IDs (T1059, T1055, T1571, etc.)
- Preserves direct traceability back to sealed Evidence Vault IDs
- Produces structured matrix summaries and narrative explanations
"""

from typing import Any, Dict, List, Optional, Set
from .registry import TechniqueCategory, get_technique_registry

# Standard Enterprise ATT&CK Kill-Chain Tactic Sequence
MITRE_TACTIC_SEQUENCE = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Fallback category to MITRE tactic mapping for unmapped techniques
CATEGORY_TO_DEFAULT_TACTIC = {
    TechniqueCategory.PROCESS_HIERARCHY_INJECTION: "Execution",
    TechniqueCategory.PERSISTENCE_MECHANISMS: "Persistence",
    TechniqueCategory.COMMAND_AND_CONTROL_NETWORK: "Command and Control",
    TechniqueCategory.EXECUTION_DEFENSE_EVASION: "Defense Evasion",
    TechniqueCategory.PRIVILEGE_DISCOVERY: "Discovery",
    TechniqueCategory.INTEGRITY_TAMPER_DETECTION: "Defense Evasion",
    TechniqueCategory.CROSS_ARTIFACT_CORRELATION: "Lateral Movement",
}


def build_mitre_analysis(
    findings: List[Any],
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Synthesizes a structured MITRE ATT&CK correlation matrix from a list of technique findings.
    
    Preserves:
    - Evidence Vault IDs (traceability)
    - Observable indicators & timestamps
    - Forensic explanations & recommendations
    """
    registry = get_technique_registry()
    findings_list = findings or []

    tactics_map: Dict[str, Dict[str, Any]] = {}
    traceability_map: Dict[str, Dict[str, Any]] = {}
    all_evidence_ids: Set = set()
    mapped_mitre_ids: Set = set()

    for f in findings_list:
        f_dict = f.model_dump() if hasattr(f, "model_dump") else (dict(f) if isinstance(f, dict) else {})
        f_id = f_dict.get("finding_id", "FINDING-UNKNOWN")
        tech_id = f_dict.get("technique_id") or f_dict.get("technique") or "TECH-UNKNOWN"
        tech_name = f_dict.get("technique_name") or tech_id
        mitre_id = f_dict.get("mitre_id")
        mitre_name = f_dict.get("mitre_name") or tech_name
        mitre_tactic = f_dict.get("mitre_tactic")
        category_str = str(f_dict.get("category", ""))
        ev_ids = f_dict.get("evidence_ids") or []
        obs_ind = f_dict.get("observed_indicator") or ""
        explanation = f_dict.get("explanation") or ""
        ts = f_dict.get("timestamp") or ""
        target_ent = f_dict.get("target_entity") or ""
        confidence = f_dict.get("confidence", "HIGH")
        status = f_dict.get("status", "DETECTED")

        # Fallback to registry if MITRE mapping is missing on the finding
        if not mitre_id or not mitre_tactic:
            reg_entry = registry.get(tech_id)
            if reg_entry and reg_entry.mitre_mapping:
                mitre_id = mitre_id or reg_entry.mitre_mapping.id
                mitre_name = mitre_name or reg_entry.mitre_mapping.name
                mitre_tactic = mitre_tactic or reg_entry.mitre_mapping.tactic

        # Fallback tactic inference from category
        if not mitre_tactic:
            for cat_enum, def_tactic in CATEGORY_TO_DEFAULT_TACTIC.items():
                if cat_enum.value.lower() in category_str.lower() or cat_enum.name.lower() in category_str.lower():
                    mitre_tactic = def_tactic
                    break
        mitre_tactic = mitre_tactic or "Defense Evasion"

        if mitre_id:
            mapped_mitre_ids.add(mitre_id)
        for ev in ev_ids:
            all_evidence_ids.add(ev)

        # 1. Populate Tactics Grouping
        if mitre_tactic not in tactics_map:
            tactics_map[mitre_tactic] = {
                "tactic": mitre_tactic,
                "technique_count": 0,
                "techniques": [],
                "evidence_ids": [],
                "highest_severity": "LOW",
            }

        t_group = tactics_map[mitre_tactic]
        t_group["evidence_ids"] = list(set(t_group["evidence_ids"] + ev_ids))

        # Check if technique already listed in this tactic
        existing_t = next((item for item in t_group["techniques"] if item.get("technique_id") == tech_id), None)
        if not existing_t:
            t_group["techniques"].append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/" if mitre_id else None,
                "confidence": confidence,
                "status": status,
                "findings_count": 1,
                "target_entities": [target_ent] if target_ent else [],
                "evidence_ids": ev_ids,
            })
            t_group["technique_count"] += 1
        else:
            existing_t["findings_count"] += 1
            if target_ent and target_ent not in existing_t["target_entities"]:
                existing_t["target_entities"].append(target_ent)
            existing_t["evidence_ids"] = list(set(existing_t["evidence_ids"] + ev_ids))

        # 2. Populate Traceability Matrix
        trace_key = mitre_id or tech_id
        if trace_key not in traceability_map:
            traceability_map[trace_key] = {
                "key": trace_key,
                "technique_id": tech_id,
                "technique_name": tech_name,
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "mitre_tactic": mitre_tactic,
                "evidence_ids": ev_ids,
                "timestamps": [ts] if ts else [],
                "target_entities": [target_ent] if target_ent else [],
                "observed_indicators": [obs_ind] if obs_ind else [],
                "explanations": [explanation] if explanation else [],
                "findings": [f_id],
            }
        else:
            trace = traceability_map[trace_key]
            trace["evidence_ids"] = list(set(trace["evidence_ids"] + ev_ids))
            if ts and ts not in trace["timestamps"]:
                trace["timestamps"].append(ts)
            if target_ent and target_ent not in trace["target_entities"]:
                trace["target_entities"].append(target_ent)
            if obs_ind and obs_ind not in trace["observed_indicators"]:
                trace["observed_indicators"].append(obs_ind)
            if f_id not in trace["findings"]:
                trace["findings"].append(f_id)

    # 3. Build Ordered Tactic Matrix
    tactic_matrix: List[Dict[str, Any]] = []
    # Add ordered tactics that have findings
    for tactic_name in MITRE_TACTIC_SEQUENCE:
        if tactic_name in tactics_map:
            tactic_matrix.append(tactics_map[tactic_name])

    # Add any custom/unlisted tactics
    for tactic_name, tactic_data in tactics_map.items():
        if tactic_name not in MITRE_TACTIC_SEQUENCE:
            tactic_matrix.append(tactic_data)

    # 4. Generate Narrative Kill-Chain Explanation
    explanations: List[str] = []
    if tactic_matrix:
        tactics_summary = ", ".join(t["tactic"] for t in tactic_matrix)
        explanations.append(
            f"Forensic evidence correlated against {len(tactic_matrix)} ATT&CK tactic(s): {tactics_summary}."
        )
        for t in tactic_matrix:
            tech_names = ", ".join(item["technique_name"] for item in t["techniques"])
            explanations.append(
                f"Tactic [{t['tactic']}]: detected {t['technique_count']} technique(s) ({tech_names}) backed by "
                f"{len(t['evidence_ids'])} Evidence Vault artifact(s)."
            )
    else:
        explanations.append("Clean baseline telemetry: 0 MITRE ATT&CK techniques identified.")

    return {
        "summary": {
            "total_findings": len(findings_list),
            "total_techniques": sum(t["technique_count"] for t in tactic_matrix),
            "total_tactics": len(tactic_matrix),
            "mitre_mapped_count": len(mapped_mitre_ids),
            "evidence_ids_covered": sorted(list(all_evidence_ids)),
        },
        "tactics": tactics_map,
        "tactic_matrix": tactic_matrix,
        "traceability": traceability_map,
        "explanations": explanations,
    }
