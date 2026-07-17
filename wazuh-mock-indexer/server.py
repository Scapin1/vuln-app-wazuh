"""
Mock Wazuh Indexer — simulates the OpenSearch _search API that the real
Wazuh Indexer exposes for vulnerability states.

Usage
-----
    python server.py                      # defaults (500 agents, 4M detections)
    python server.py --agents 200 --detections 500000 --port 9200
    python server.py --seed 99 --duration-days 90

The app connects by creating a Wazuh connection with
``indexer_url = http://<host>:<port>`` and any user/password (Basic Auth is
accepted but not enforced).
"""

import argparse
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from data_generator import (
    generate_agents,
    generate_cves,
    generate_batch,
    position_from_search_after,
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_AGENTS = 500
DEFAULT_DETECTIONS = 4_000_000
DEFAULT_CVES = 20_000
DEFAULT_SEED = 42
DEFAULT_PORT = 9200
DEFAULT_START = "2026-04-01T00:00:00Z"
DEFAULT_END = "2026-07-01T00:00:00Z"

logger = logging.getLogger("wazuh-mock-indexer")

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    num_agents: int = DEFAULT_AGENTS,
    num_detections: int = DEFAULT_DETECTIONS,
    num_cves: int = DEFAULT_CVES,
    seed: int = DEFAULT_SEED,
    start_date_str: str = DEFAULT_START,
    end_date_str: str = DEFAULT_END,
) -> FastAPI:

    start_date = datetime.fromisoformat(start_date_str.replace("Z", "+00:00"))
    end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))

    agents = generate_agents(count=num_agents, seed=seed)
    cves = generate_cves(count=num_cves, seed=seed)
    logger.info(
        "Simulation ready: %d agents, %d CVEs, %d detections, "
        "time range %s → %s",
        len(agents), len(cves), num_detections,
        start_date.isoformat(), end_date.isoformat(),
    )

    app = FastAPI(title="Wazuh Mock Indexer")

    # ---- Health / connection check ----------------------------------------

    @app.get("/")
    @app.head("/")
    async def root():
        """Connection check endpoint — the real Wazuh Indexer returns 200."""
        return {"status": "ok", "cluster_name": "wazuh-mock", "version": "7.10.2"}

    @app.get("/health")
    async def health():
        return {"status": "UP", "simulated_agents": len(agents),
                "simulated_detections": num_detections}

    # ---- _search endpoint -------------------------------------------------

    @app.post("/{index}/_search")
    @app.post("/{index}/_search/template")  # ignored, respond same
    async def search(index: str, request: Request):
        """
        Mimics the OpenSearch _search endpoint used by the Wazuh sync.

        Supports ``size``, ``sort``, and ``search_after``.
        The ``_source`` and ``sort`` fields are consumed per real client usage.
        """
        body: Dict[str, Any] = {}
        try:
            body = await request.json()
        except Exception:
            pass

        batch_size = min(body.get("size", 5000), 10000)
        search_after: Optional[List[str]] = body.get("search_after")

        # Calculate start position
        if search_after:
            start_pos = position_from_search_after(search_after)
        else:
            start_pos = 0

        # Guard against out-of-range
        if start_pos >= num_detections:
            return JSONResponse({
                "took": 0,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {
                    "total": {"value": num_detections, "relation": "eq"},
                    "max_score": None,
                    "hits": [],
                },
            })

        hits = generate_batch(
            start_position=start_pos,
            batch_size=batch_size,
            total=num_detections,
            agents=agents,
            cves=cves,
            start_date=start_date,
            end_date=end_date,
            seed=seed,
        )

        return JSONResponse({
            "took": 5,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {
                "total": {"value": num_detections, "relation": "eq"},
                "max_score": None,
                "hits": hits,
            },
        })

    @app.get("/_cat/indices")
    async def cat_indices():
        """Emulates the OpenSearch cat indices endpoint (informational)."""
        return JSONResponse([
            {
                "index": "wazuh-states-vulnerabilities-",
                "health": "green",
                "status": "open",
                "docs.count": str(num_detections),
                "store.size": "8.2gb",
            }
        ])

    return app


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mock Wazuh Indexer — simulate a Wazuh Indexer for testing"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Listen port (default {DEFAULT_PORT})")
    parser.add_argument("--agents", type=int, default=DEFAULT_AGENTS,
                        help=f"Number of simulated agents (default {DEFAULT_AGENTS})")
    parser.add_argument("--detections", type=int, default=DEFAULT_DETECTIONS,
                        help=f"Number of simulated vulnerability detections "
                             f"(default {DEFAULT_DETECTIONS:,})")
    parser.add_argument("--cves", type=int, default=DEFAULT_CVES,
                        help=f"Number of unique CVEs (default {DEFAULT_CVES})")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help=f"PRNG seed for deterministic data (default {DEFAULT_SEED})")
    parser.add_argument("--start", type=str, default=DEFAULT_START,
                        help=f"Start of detection time range (default {DEFAULT_START})")
    parser.add_argument("--end", type=str, default=DEFAULT_END,
                        help=f"End of detection time range (default {DEFAULT_END})")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="Bind address (default 0.0.0.0)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    app = create_app(
        num_agents=args.agents,
        num_detections=args.detections,
        num_cves=args.cves,
        seed=args.seed,
        start_date_str=args.start,
        end_date_str=args.end,
    )

    logger.info("Starting mock Wazuh Indexer on %s:%s", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
