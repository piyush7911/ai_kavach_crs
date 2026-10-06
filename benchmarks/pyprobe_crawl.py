"""Point-and-probe: discover an app's attack surface by CRAWLING it over HTTP, then run the oracles.

The most general entry point — needs no spec, no framework introspection, no source: just a URL. It reads
the app's own links/forms to find routes + parameters, infers auth/bodies dynamically, and runs every
probe family. Use when handed a running app and nothing else (e.g. a raw HTTP service like DSVW).

    python -m benchmarks.pyprobe_crawl http://127.0.0.1:8899
"""
import sys

from src.pyauto.probes import ProbeCtx, enrich_routes, probe, routes_from_crawl


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: python -m benchmarks.pyprobe_crawl <base_url>")
        return 2
    base = argv[0].rstrip("/")
    routes = routes_from_crawl(base)
    print(f"crawled {len(routes)} routes from {base}:")
    for r in routes:
        print(f"  {r.method} {r.path}  params={r.query_fields}")
    ctx = ProbeCtx(base, auth={}, reseed=None)
    enrich_routes(routes, ctx)
    print("\nprobing ...")
    found = probe(routes, ctx)
    for f in found:
        print(f"  CONFIRMED  {f.klass:24} {f.evidence['route']}  ::  {f.reason[:60]}")
    print(f"\nautonomously discovered + confirmed: {len(found)} bugs")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
