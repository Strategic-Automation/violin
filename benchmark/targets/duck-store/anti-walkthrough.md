Load the pentest skill. Then bootstrap the engagement:

```
python scripts/violin_guard.py init-engagement \
  --host duck-store.escape.tech \
  --session-id duck-store-benchmark \
  engagements/duck-store-benchmark
```

Then replace the generated scope with our pre-baked benchmark scope:

```
cp C:/Users/Hello/Repos/violin/benchmark/targets/duck-store/scope.yaml \
   engagements/duck-store-benchmark/scope/scope.yaml
```

Run check-bootstrap to confirm:
```
python scripts/violin_guard.py check-bootstrap engagements/duck-store-benchmark
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
