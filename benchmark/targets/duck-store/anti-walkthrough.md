Load the pentest skill. Then create an engagement:

```
python scripts/violin_guard.py init-engagement \
  --scope-file C:/Users/Hello/Repos/violin/benchmark/targets/duck-store/scope.yaml \
  --session-id duck-store-benchmark \
  engagements/duck-store-benchmark
```

BENCHMARK RULES:
- Use violin_exec for ALL target-touching commands — never raw terminal
- Follow the pentest playbook phases: scoping → recon → vuln-research → exploitation
- Create hypotheses via hypotheses.md for every discovery
- Update PTT after every batch
- Web search is ALLOWED only for: NVD/CVE lookup by version, ExploitDB, OWASP technique references
- FORBIDDEN: searching "duck store vulnerability/walkthrough/writeup"
- Every finding must have a PoC request/response saved to evidence/

Target: duck-store.escape.tech
OpenAPI spec: https://duck-store.escape.tech/openapi.json
Register an account first. DB resets every 2h.
