"""
Deterministic data generator for the mock Wazuh Indexer.

Generates agents, CVEs, and vulnerability detections using a seeded PRNG,
so the same seed always produces identical data. No data is persisted —
detections are generated lazily by position index.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------

OS_PROFILES = [
    {"platform": "ubuntu", "version": "22.04",  "full": "Ubuntu 22.04.4 LTS",      "family": "deb"},
    {"platform": "ubuntu", "version": "24.04",  "full": "Ubuntu 24.04.1 LTS",      "family": "deb"},
    {"platform": "debian", "version": "12",     "full": "Debian GNU/Linux 12 (bookworm)", "family": "deb"},
    {"platform": "centos", "version": "9",      "full": "CentOS Stream 9",          "family": "rpm"},
    {"platform": "rhel",   "version": "9.4",    "full": "Red Hat Enterprise Linux 9.4",   "family": "rpm"},
    {"platform": "windows", "version": "2022",  "full": "Windows Server 2022 Datacenter", "family": "win"},
]

PACKAGES_BY_FAMILY = {
    "deb":  [("openssl",       "3.0.13"), ("libssl3",       "3.0.13"),
             ("openssh-server","9.6p1"),  ("nginx",         "1.24.0"),
             ("apache2",       "2.4.62"), ("mysql-server",  "8.0.37"),
             ("postgresql",    "16.3"),   ("python3",       "3.12.4"),
             ("curl",          "8.9.1"),  ("wget",          "1.24.5"),
             ("git",           "2.45.2"), ("bash",          "5.2.32"),
             ("systemd",       "255.4"),  ("libcrypto",     "3.0.13"),
             ("zlib",          "1.3.1"),  ("sqlite3",       "3.46.0"),
             ("nodejs",        "20.15.0"),("php",           "8.3.9")],
    "rpm":  [("openssl",       "3.2.2"),  ("openssh-server","9.8p1"),
             ("nginx",         "1.26.1"), ("httpd",         "2.4.62"),
             ("mysql-server",  "8.4.2"),  ("postgresql",    "16.3"),
             ("python3",       "3.12.4"), ("curl",          "8.9.1"),
             ("wget",          "1.24.5"), ("git",           "2.45.2"),
             ("bash",          "5.2.26"), ("systemd",       "255.4"),
             ("libcrypto",     "3.2.2"),  ("zlib",          "1.3.1"),
             ("sqlite",        "3.46.0"), ("nodejs",        "20.15.0")],
    "win":  [("openssl",       "3.2.2"),  ("openssh",       "9.6.0.0"),
             ("iis",           "10.0"),   ("mysql",         "8.0.37"),
             ("postgresql",    "16.3"),   ("python3",       "3.12.4"),
             ("curl",          "8.9.1"),  ("git",           "2.45.2"),
             ("powershell",    "7.4.4"),  ("netframework",  "4.8.1")],
}


# ---------------------------------------------------------------------------
# Helpers — fast deterministic PRNG (no crypto hashes)
# ---------------------------------------------------------------------------

def _det_rand(seed: int, position: int) -> int:
    """
    Fast deterministic pseudo-random integer from seed + position.
    Uses a simple LCG + bitmix so we don't need sha256 per record.
    """
    x = (seed & 0xFFFFFFFF) ^ (position & 0xFFFFFFFF)
    x = (x * 1103515245 + 12345) & 0x7FFFFFFF
    x = ((x >> 16) ^ x) * 0x45D9F3B
    x = ((x >> 16) ^ x) * 0x45D9F3B
    x = (x >> 16) ^ x
    return x & 0x7FFFFFFF


# ---------------------------------------------------------------------------
# Agent generation
# ---------------------------------------------------------------------------

HOSTNAME_PREFIXES = ["srv-web", "srv-db", "srv-app", "node-prod", "node-dev",
                     "worker", "gateway", "monitor", "backup", "cache"]

def generate_agents(
    count: int = 500, seed: int = 42
) -> List[Dict[str, Any]]:
    agents = []
    rng = random.Random(seed)
    for i in range(count):
        prefix = HOSTNAME_PREFIXES[i % len(HOSTNAME_PREFIXES)]
        agent_id = f"{i:04d}"
        os_profile = OS_PROFILES[i % len(OS_PROFILES)]
        agents.append({
            "id": agent_id,
            "name": f"{prefix}-{agent_id}",
            "os": {
                "full": os_profile["full"],
                "platform": os_profile["platform"],
                "version": os_profile["version"],
            },
            "ip": f"10.0.{i // 256}.{i % 256}",
            "os_family": os_profile["family"],
        })
    return agents


# ---------------------------------------------------------------------------
# CVE catalog generation
# ---------------------------------------------------------------------------

SEVERITY_CONFIG = [
    ("Critical", 9.0, 10.0, 0.05),
    ("High",     7.0, 8.9,  0.20),
    ("Medium",   4.0, 6.9,  0.40),
    ("Low",      0.1, 3.9,  0.35),
]

CVE_DESCRIPTIONS = [
    "Buffer overflow in {component} allowing remote code execution",
    "Privilege escalation vulnerability in {component} via crafted input",
    "SQL injection in {component} leading to data exposure",
    "Cross-site scripting (XSS) vulnerability in {component}",
    "Use-after-free in {component} that may lead to arbitrary code execution",
    "Integer overflow in {component} causing denial of service",
    "Improper input validation in {component} leading to memory corruption",
    "Path traversal vulnerability in {component} allowing file disclosure",
    "Information disclosure through {component} due to improper error handling",
    "Authentication bypass in {component} via session manipulation",
    "Improper certificate validation in {component}",
    "Race condition in {component} allowing privilege escalation",
    "Heap overflow in {component} leading to remote code execution",
    "Out-of-bounds read in {component} causing information leak",
    "XML external entity (XXE) injection in {component}",
]


def generate_cves(
    count: int = 20000, seed: int = 42
) -> Dict[str, Dict[str, Any]]:
    """Returns {cve_id: {severity, cvss_score, description}, ...}."""
    rng = random.Random(seed + 1)
    cves: Dict[str, Dict[str, Any]] = {}
    for i in range(count):
        cve_idx = i + 1
        cve_id = f"CVE-2026-{cve_idx:05d}"

        # Pick severity band from weighted config
        roll = rng.random()
        cum = 0.0
        chosen = SEVERITY_CONFIG[-1]
        for sev, lo, hi, weight in SEVERITY_CONFIG:
            cum += weight
            if roll <= cum:
                chosen = (sev, lo, hi, weight)
                break

        severity, score_lo, score_hi, _ = chosen
        cvss = round(rng.uniform(score_lo, score_hi), 1)

        desc = rng.choice(CVE_DESCRIPTIONS).format(
            component=rng.choice(["OpenSSL", "SystemD", "glibc", "Kernel",
                                  "nginx", "Apache", "PostgreSQL",
                                  "MySQL", "Python", "cURL"])
        )

        cves[cve_id] = {
            "severity": severity,
            "cvss_score": cvss,
            "description": desc,
        }
    return cves


# ---------------------------------------------------------------------------
# Detection generation (lazy — by position)
# ---------------------------------------------------------------------------

def generate_batch(
    start_position: int,
    batch_size: int,
    total: int,
    agents: List[Dict[str, Any]],
    cves: Dict[str, Dict[str, Any]],
    start_date: datetime,
    end_date: datetime,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """
    Generate a batch of hits in OpenSearch _search response format,
    starting from *start_position* in the global sort order.

    Optimized for speed: pre-computes lookups, avoids repeated list() calls,
    and builds dicts with literal syntax.
    """
    num_agents = len(agents)
    cve_keys = list(cves.keys())
    num_cves = len(cve_keys)
    ts_total_sec = (end_date - start_date).total_seconds()
    max_pos = max(total - 1, 1)

    hits = []
    for offset in range(batch_size):
        pos = start_position + offset
        if pos >= total:
            break

        # -- position → timestamp --
        detected_at_iso = (start_date + timedelta(
            seconds=ts_total_sec * pos / max_pos
        )).strftime("%Y-%m-%dT%H:%M:%SZ")

        # -- agent --
        agent = agents[pos % num_agents]
        aid = agent["id"]
        aname = agent["name"]
        aos = agent["os"]
        family = agent.get("os_family", "deb")

        # -- CVE --
        cve_id = cve_keys[_det_rand(seed, pos) % num_cves]
        cve = cves[cve_id]

        # -- _id --
        _id = f"sim-{pos:08d}"

        # -- package --
        pkg_pool = PACKAGES_BY_FAMILY.get(family, PACKAGES_BY_FAMILY["deb"])
        pkg_name, pkg_ver = pkg_pool[_det_rand(seed + 1, pos) % len(pkg_pool)]

        # -- index name --
        index_date = detected_at_iso[:10].replace("-", ".")
        index = f"wazuh-states-vulnerabilities-{index_date}"

        _source = {
            "agent": {"id": aid, "name": aname, "os": aos},
            "host": {"os": aos},
            "package": {
                "name": pkg_name,
                "version": pkg_ver,
                "type": "deb" if family != "win" else "msi",
                "architecture": "amd64",
            },
            "vulnerability": {
                "id": cve_id,
                "severity": cve["severity"],
                "score": {"base": cve["cvss_score"], "version": "3.1"},
                "detected_at": detected_at_iso,
                "published_at": None,
                "description": cve["description"],
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "scanner": {"vendor": "wazuh"},
            },
        }

        hits.append({
            "_index": index,
            "_id": _id,
            "_score": None,
            "_source": _source,
            "sort": [detected_at_iso, _id],
        })

    return hits


def position_from_search_after(search_after: List[str]) -> int:
    """
    Extract the 0-based position from a search_after cursor.

    The cursor is [detected_at_iso, _id].  The _id has the form
    ``sim-{position:08d}`` so we can decode it in O(1).
    """
    if not search_after or len(search_after) < 2:
        return 0
    _id = search_after[1]
    if _id.startswith("sim-"):
        try:
            return int(_id[4:]) + 1  # start AFTER this document
        except ValueError:
            return 0
    return 0
