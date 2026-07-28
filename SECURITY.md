# Security

## The files in `samples/` are intentionally vulnerable

Everything under `samples/` (and `eval/corpus/`) is **deliberately insecure
Infrastructure-as-Code, written as test fixtures**. Public S3 ACLs, `0.0.0.0/0` ingress
rules, wildcard IAM policies, containers running as root, and hardcoded credentials are all
present on purpose — they are the input this tool is built to detect and remediate.

Any credentials in those files are fake placeholders (`AKIA_FAKE_KEY`,
`SuperInsecurePassword123!`). None of them are real, and none of them have ever been valid.

**Do not deploy these files.** They are scanner fixtures, not templates.

Automated secret scanners will flag this repository. That is expected behaviour and not a
finding.

## Reporting a real issue

If you find an actual vulnerability in the tool itself — as opposed to in the fixtures —
please open a GitHub issue, or contact the maintainer directly if you consider it sensitive.
