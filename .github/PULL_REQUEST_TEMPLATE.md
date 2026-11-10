## Summary

Describe the change and why it is needed.

## Verification Checklist

- [ ] `python scripts/check_release.py --root .` passes (`0 issues`)
- [ ] `python -m unittest discover -s tests -v` passes
- [ ] Zero runtime dependencies added (`dependencies = []` in `pyproject.toml`)
- [ ] No secrets (`nsec1...`, 64-char hex keys, or federated bearer tokens) or private paths included
