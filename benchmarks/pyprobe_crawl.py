"""Point-and-probe: discover an app's attack surface over HTTP, then run the oracles.

The most general entry point — needs no spec, framework, or source, just a URL. Routes come from three
HTTP-only sources (links/forms crawl, sitemap.xml, plus any query params already in those URLs); when a
route exposes no parameter names (a SPA over a JSON API), `mine_params` finds the live ones by probing a
name wordlist. Then auth/bodies are inferred and every oracle family runs.

    python -m benchmarks.pyprobe_crawl http://127.0.0.1:9090/VulnerableApp
"""
import sys
from urllib.parse import urlparse

from src.pyauto.probes import (ProbeCtx, enrich_routes, mine_params, probe,
                               routes_from_crawl, routes_from_sitemap)


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: python -m benchmarks.pyprobe_crawl <base_url> [--mine]")
        return 2
    arg = argv[0].rstrip("/")
    mine = "--mine" in argv
    pu = urlparse(arg)
    origin = f"{pu.scheme}://{pu.netloc}"
    ctx_path = pu.path.rstrip("/")                           # e.g. /VulnerableApp (context path)

    # gather routes from every HTTP-only source, dedup by (method, path), merge their params
    merged: dict = {}
    sources = (routes_from_crawl(origin, seeds=((ctx_path + "/") or "/",))
               + routes_from_sitemap(f"{origin}{ctx_path}/sitemap.xml")
               + routes_from_sitemap(f"{origin}/sitemap.xml"))
    for r in sources:
        merged.setdefault((r.method, r.path), set()).update(r.query_fields)
    from src.pyauto.probes import Route
    routes = [Route(m, p, query_fields=sorted(ps)) for (m, p), ps in sorted(merged.items())]
    print(f"discovered {len(routes)} routes (crawl + sitemap)")

    ctx = ProbeCtx(origin, auth={}, reseed=None)
    if mine:
        print("mining parameter names (no forms/spec exposed) ...")
        mine_params(origin, routes, ctx)
        withp = sum(1 for r in routes if r.query_fields)
        print(f"  {withp} routes have live parameters after mining")
    enrich_routes(routes, ctx)
    print("probing ...")
    found = probe(routes, ctx)
    for f in found:
        print(f"  CONFIRMED  {f.klass:20} {f.evidence['route']}  ::  {f.reason[:55]}")
    print(f"\nautonomously discovered + confirmed: {len(found)} bugs")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
