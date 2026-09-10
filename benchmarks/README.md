# STOF benchmark manifests

Ground-truth files for `stof bench` (see `stof/bench/score.py`) --
turns "154 techniques" into a measured claim instead of a vanity
number, per every one of four independent external reviews of this
project naming precision/recall benchmarking as the highest-leverage
validation work still missing.

## Why two kinds of target

- **Recall** needs a target with **known, real vulnerabilities** and a
  manifest listing exactly what should be found (`expected_findings`).
  OWASP Juice Shop, WebGoat, crAPI, and DVWA are the standard choices
  in this space.
- **False-positive rate** needs the opposite: a target **explicitly
  known to have none** of the vulnerability classes under test (a
  hardened/patched benchmark build, or a small reference app built
  specifically to have none of these bugs). Every `FAIL` finding
  against it is, by definition, a false positive.

A recall number alone is a poster. A recall number without a
false-positive number from a clean target is half a benchmark -- see
`stof/bench/score.py`'s own docstring for the full reasoning.

## Manifest shape

```json
{
  "name": "OWASP Juice Shop",
  "target": "http://192.168.1.73:3001",
  "expected_findings": [
    {
      "technique_id": "TC-022.1",
      "endpoint_pattern": "/rest/user/login",
      "description": "demo/demo default credentials accepted -- verified live 2026-09-10"
    }
  ]
}
```

- `technique_id` can name either an exact sub-technique ("TC-022.1")
  or just the top-level family ("TC-022"), which matches any of its
  sub-techniques -- use the family form when it doesn't matter WHICH
  sub-technique catches the bug, only that the class was found.
- `endpoint_pattern` is matched as a substring against the finding's
  endpoint URL, not a regex -- keep it to the stable path, since a
  benchmark app's own session-scoped ids/query strings aren't
  predictable in advance.
- Every entry must be something a human actually verified live against
  the real target (a live curl/browser confirmation, not "STOF should
  probably find this"). An unverified entry makes the recall number
  meaningless in the direction that matters most -- claiming credit for
  detecting something that was never confirmed to actually be there.

## Running it

```bash
# 1. Crawl + scan the benchmark target as normal.
stof crawl --config config/juiceshop.json
stof scan --config config/juiceshop.json --output data/reports/

# 2. Score the resulting report against the manifest.
stof bench --report data/reports/scan_<id>.json --manifest benchmarks/juiceshop.json

# 3. (Optional, for the false-positive half) scan a clean/hardened
#    target the same way, then pass its report too:
stof bench --report data/reports/scan_<vuln-id>.json \
           --manifest benchmarks/juiceshop.json \
           --clean-report data/reports/scan_<clean-id>.json
```

## Current manifests

- `juiceshop.json` -- **one** verified entry (`TC-022.1`, live-confirmed
  2026-09-10, see this session's own request/response replay: `demo`/
  `demo` accepted at `POST /rest/user/login`, returns a real, usable
  JWT). Deliberately not padded with unverified guesses -- expand this
  file only with entries that have been independently confirmed live
  against the real target, the same way this one was, not by assuming
  a technique "should" catch something.
- No clean-target manifest/report exists yet -- the false-positive half
  of the benchmark is scaffolded (`score_false_positives`, the
  `--clean-report` flag) but not yet run against a real clean target.
  This is the next concrete step for anyone picking this up.
