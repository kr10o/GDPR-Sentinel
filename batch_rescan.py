#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skripta za masovno (batch) učitavanje domena iz data/scans/*.json ili tekstualne datoteke,
njihovo konkurentno dubinsko skeniranje i izvoz sažetog nadzornog izvještaja.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from scanner import GDPRScanner


async def run_batch_pipeline(
    scans_dir: str = "data/scans",
    extra_domains_file: str = "",
    max_pages_per_domain: int = 15,
    domain_concurrency: int = 3,
) -> List[Dict[str, Any]]:
    scanner = GDPRScanner(
        max_pages=max_pages_per_domain,
        max_depth=2,
        concurrency=4,
        scans_dir=scans_dir,
    )

    targets: Dict[str, Dict[str, str]] = {}

    # 1. Učitaj sve postojeće domene iz data/scans/*.json
    for item in scanner.load_existing_domains():
        targets[item["domain"]] = {
            "url": item["url"],
            "scan_id": item["scan_id"],
        }

    # 2. Dodaj domene iz opcionalne tekstualne datoteke (jedna domena po retku)
    if extra_domains_file and Path(extra_domains_file).is_file():
        with Path(extra_domains_file).open("r", encoding="utf-8") as fh:
            for line in fh:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                try:
                    norm_url, norm_dom = scanner.normalize_target_url(raw)
                    if norm_dom not in targets:
                        targets[norm_dom] = {"url": norm_url, "scan_id": ""}
                except ValueError:
                    continue

    if not targets:
        print("[INFO] Nisu pronađene domene u 'data/scans/'. Skeniram demonstracijsku domenu iz repozitorija...")
        targets["beat-battle-royale.com"] = {
            "url": "https://beat-battle-royale.com",
            "scan_id": "a8ffde08",
        }

    sem = asyncio.Semaphore(domain_concurrency)

    async def _scan_single(domain_key: str, meta: Dict[str, str]) -> Dict[str, Any]:
        async with sem:
            sid = meta["scan_id"] if meta["scan_id"] else None
            return await scanner.scan_domain_async(meta["url"], save_to_disk=True, scan_id=sid)

    results = await asyncio.gather(
        *(_scan_single(dom, meta) for dom, meta in targets.items()),
        return_exceptions=False,
    )

    # Spremi agregirani pregled svih učitanih domena
    summary_path = Path("data") / "batch_audit_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_payload = {
        "total_domains_scanned": len(results),
        "average_score": round(
            sum(r.get("score", 0) for r in results) / max(1, len(results)), 1
        ),
        "domains": [
            {
                "scan_id": r["id"],
                "domain": r["domain"],
                "score": r["score"],
                "risk_level": r["risk_level"],
                "pages_crawled": r["pages_scanned_count"],
                "cookies_found": r["cookies_count"],
                "trackers_found": r["trackers_detected"],
                "has_privacy_policy": r["has_privacy_policy"],
                "has_cookie_banner": r["has_cookie_banner"],
                "issues_count": len(r["issues"]),
            }
            for r in results
        ],
    }
    with summary_path.open("w", encoding="utf-8") as fh:
        json.dump(summary_payload, fh, ensure_ascii=False, indent=2)

    print(f"\n=== GDPR SENTINEL BATCH IZVJEŠTAJ ({len(results)} DOMENA) ===")
    print(f"Prosječna ocjena usklađenosti: {summary_payload['average_score']}/100")
    print(f"Sažetak spremljen u: {summary_path}\n")
    for d in summary_payload["domains"]:
        print(
            f" * [{d['scan_id']}] {d['domain']:<28} | Ocjena: {d['score']:>3}/100 ({d['risk_level']:<8}) "
            f"| Podstranica: {d['pages_crawled']:>2} | Kolačići: {d['cookies_found']:>2} | Prekršaji: {d['issues_count']}"
        )

    return results


if __name__ == "__main__":
    extra_file = sys.argv[1] if len(sys.argv) > 1 else ""
    asyncio.run(run_batch_pipeline(extra_domains_file=extra_file))
