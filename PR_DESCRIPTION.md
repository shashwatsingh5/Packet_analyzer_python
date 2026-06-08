Title: Port to Python — add multi-worker sharding, compiled rule matching, and tests

Summary:
- Implemented an offline Python DPI engine using `dpkt`.
- Added `LoadBalancer`-based sharding and `--workers N` CLI option to process large PCAPs in parallel while ensuring all packets from the same 5-tuple are handled by the same worker.
- Optimized rule matching by compiling rules as regex patterns and added basic timing metrics.
- Added `fast_path` heuristics and `load_balancer` sharding.
- Added unit tests validating parsing, SNI extraction, rule matching, connection tracking, and multi-worker consistency.

How to push and open a PR:

1. Create a remote branch and push:

```bash
git remote add origin <your-repo-url>
git push -u origin py-port-multiworker
```

2. Open a PR on your Git hosting provider (GitHub/GitLab/Azure) from `py-port-multiworker` into your target branch.

Notes:
- The local repo is not yet initialized in this workspace; the branch and commit were made locally. If you want, I can attempt to add a remote and push, but you'll need to provide the remote repository URL or set it up.
