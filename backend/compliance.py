"""
compliance.py
-------------
The shared contract's controls table stores framework_tags as a
comma-separated string, e.g. "ISO27001-A.9,NIST-PR.AC,CIS-5". There is no
separate compliance-clause table in the schema, so /api/compliance/mapping
is built by parsing those tags at request time and grouping controls by
(framework, clause).

Tag format assumed: "<FRAMEWORK>-<CLAUSE>", split on the FIRST hyphen only,
since clause identifiers themselves can contain hyphens/dots (e.g.
"NIST-PR.AC" -> framework="NIST", clause="PR.AC"; "RBI-Cyber-1" ->
framework="RBI", clause="Cyber-1"). A hardcoded set of known framework
prefixes disambiguates the common cases; anything else falls back to a
naive first-hyphen split.
"""

KNOWN_FRAMEWORK_PREFIXES = ["ISO27001", "NIST-CSF", "NIST", "CIS", "RBI"]


def parse_tag(tag: str):
    tag = tag.strip()
    if not tag:
        return None
    for prefix in KNOWN_FRAMEWORK_PREFIXES:
        if tag.startswith(prefix + "-"):
            return prefix, tag[len(prefix) + 1:]
    # Fallback: naive split on first hyphen
    if "-" in tag:
        framework, clause = tag.split("-", 1)
        return framework, clause
    return tag, ""


def build_compliance_mapping(controls: list):
    """
    controls: list of dicts with id, framework_tags (comma-separated string)
    Returns: [ {framework, clause, related_control_ids: [...]} ]
    """
    grouped = {}  # (framework, clause) -> set of control ids
    for control in controls:
        tags = (control.get("framework_tags") or "").split(",")
        for raw_tag in tags:
            parsed = parse_tag(raw_tag)
            if not parsed:
                continue
            framework, clause = parsed
            key = (framework, clause)
            grouped.setdefault(key, set()).add(control["id"])

    mapping = [
        {
            "framework": framework,
            "clause": clause,
            "related_control_ids": sorted(control_ids),
        }
        for (framework, clause), control_ids in sorted(grouped.items())
    ]
    return mapping
