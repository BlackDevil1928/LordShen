"""Scan pipeline stage definitions and profiles."""

from dataclasses import dataclass, field


@dataclass
class Stage:
    """A scan pipeline stage definition."""
    name: str
    display_name: str
    tools: list[str] = field(default_factory=list)
    parallel: bool = True
    requires_previous: bool = False


SCAN_STAGES: list[Stage] = [
    Stage(
        name="passive_recon",
        display_name="Passive Recon",
        tools=[
            "SubfinderWrapper", "AmassWrapper", "CrtshWrapper",
            "GauWrapper", "WaybackurlsWrapper", "TheHarvesterWrapper",
            "ParamSpiderWrapper",
        ],
        parallel=True,
    ),
    Stage(
        name="active_recon",
        display_name="Active Recon",
        tools=[
            "HttpxWrapper", "DnsxWrapper", "MasscanWrapper",
            "NmapWrapper", "WhatWebWrapper", "Wafw00fWrapper",
        ],
        parallel=True,
        requires_previous=True,
    ),
    Stage(
        name="vuln_scan",
        display_name="Vulnerability Scan",
        tools=[
            "NucleiWrapper", "TestsslWrapper", "NiktoWrapper",
            "SubjackWrapper", "SshAuditWrapper",
        ],
        parallel=True,
        requires_previous=True,
    ),
    Stage(
        name="webapp_scan",
        display_name="Web App Testing",
        tools=[
            "FfufWrapper", "FeroxbusterWrapper", "DalfoxWrapper",
            "ArjunWrapper", "WapitiWrapper", "CorsScannerWrapper",
        ],
        parallel=True,
        requires_previous=True,
    ),
    Stage(
        name="network_scan",
        display_name="Network Testing",
        tools=["NetexecWrapper", "HydraWrapper"],
        parallel=True,
        requires_previous=True,
    ),
    Stage(
        name="cloud_scan",
        display_name="Cloud Security",
        tools=["S3CheckWrapper", "TrivyWrapper"],
        parallel=True,
    ),
]

PROFILES: dict[str, list[str]] = {
    "quick": ["passive_recon"],
    "standard": ["passive_recon", "active_recon", "vuln_scan"],
    "deep": [
        "passive_recon", "active_recon", "vuln_scan",
        "webapp_scan", "network_scan", "cloud_scan",
    ],
}


def get_stages_for_profile(profile: str) -> list[Stage]:
    """Return stage list for a given scan profile."""
    stage_names = PROFILES.get(profile, PROFILES["standard"])
    return [s for s in SCAN_STAGES if s.name in stage_names]
