# Negative controls — correct infrastructure

Everything in `samples/` one directory up is deliberately broken. That makes precision
unmeasurable in the one direction reviewers care most about: on a file where every
resource is misconfigured, almost any finding the pipeline emits is *plausibly* right, so
"how often does it flag something that isn't a problem?" has no denominator.

These four files are that denominator. They are the control group: realistic, hardened IaC
that both static scanners pass clean. Anything the pipeline reports on a file in this
directory is a false alarm, with no adjudication needed.

| file | what it is | lines |
| --- | --- | ---: |
| `secure_minimal.tf` | The easiest possible clean case — a rotated customer-managed KMS key and one log group encrypted with it. If the pipeline cries wolf here, nothing downstream is worth reading. | 68 |
| `secure_s3.tf` | A hardened S3 data bucket and the access-log bucket it writes to: CMK encryption with bucket keys, versioning, full public-access block, ownership enforced, lifecycle rules, TLS-only bucket policies, and cross-region replication under a least-privilege role. | 459 |
| `secure_network.tf` | A private VPC: flow logs to an encrypted log group with a retention period, a locked-down default security group, private subnets with no auto-assigned public IPs, and an app security group whose ingress and egress are scoped to the VPC CIDR on single ports. | 271 |
| `secure_app.Dockerfile` | A multi-stage Go build onto a digest-pinned distroless base, running as uid 65532 with a `HEALTHCHECK` and no secrets in any layer. | 35 |

## Measured result

Run 2026-07-29 with **checkov 3.2.489** and **trivy 0.68.1** on Python 3.13, one file at a
time, exactly the way `iac_agent.scanners` invokes them:

```sh
.venv/bin/checkov -f samples/secure/<file> -o json --compact --quiet \
    --framework <terraform|dockerfile>
trivy config --quiet --format json samples/secure/<file>
```

| file | checkov failed | checkov passed | trivy failed |
| --- | ---: | ---: | ---: |
| `secure_minimal.tf` | **0** | 7 | **0** |
| `secure_s3.tf` | **0** | 46 | **0** |
| `secure_network.tf` | **0** | 38 | **0** |
| `secure_app.Dockerfile` | **0** | 43 | **0** |

**Residual findings: none.** All four files are at zero on both scanners. The same numbers
come back through the pipeline's own `CheckovScanner` / `TrivyScanner` wrappers, not just
the CLIs.

The `passed` column matters as much as the zero next to it: it is the evidence that the
graph checks which need several resources to cooperate actually *ran* and were satisfied,
rather than being skipped because the file gave them nothing to look at. Confirmed
individually — `CKV2_AWS_6` (S3 public access block), `CKV_AWS_144` (cross-region
replication) and `CKV2_AWS_62` (event notifications) pass on `secure_s3.tf`; `CKV2_AWS_5`
(security group actually attached to something), `CKV2_AWS_11` (VPC flow logs) and
`CKV2_AWS_12` (default security group restricts all traffic) pass on `secure_network.tf`.

## Leakage

The vulnerable fixtures added alongside these carry no comments naming their flaws,
because this project measured 13.5 points of label leakage from the original corpus
annotating its own bugs. The mirror-image mistake is just as easy to make here: a header
comment reading *"negative control — nothing wrong with this file"* hands a model the
answer and would inflate any false-alarm number measured on it.

So the four files contain no such comment. Their headers describe what the infrastructure
is, in the register an ordinary production module would use, and the fact that they are
controls lives only in this README. What is **not** fixed is the filenames — `secure_*`
is a give-away, and anything that feeds the file path to a model alongside its contents
will leak. If these are ever wired into a scored run, pass them under neutral names.

## What "zero" does and does not mean

Zero is a property of *these files against these two rule sets at these versions*, not a
claim that the infrastructure is secure. Four things are worth knowing before anyone
quotes the number.

**1. One of the zeros is a scanner blind spot, not a fix.** `secure_minimal.tf` first
reported `CKV2_AWS_64` — "Ensure KMS key Policy is defined". Writing that policy as an
`aws_iam_policy_document` data source traded one finding for three: `CKV_AWS_111`,
`CKV_AWS_356` and `CKV_AWS_109` all fire on the AWS-recommended default key policy, whose
whole point is to give the account root `kms:*` on the key so the key does not become
unmanageable. Expressing the *identical* policy inline with `jsonencode` reports zero,
because checkov's IAM policy checks parse the data source and not the encoded string. The
files here use the `jsonencode` form. That is a real difference in how checkov sees two
spellings of the same policy, and it is recorded here rather than quietly enjoyed.

**2. `secure_s3.tf` is long because of one check.** `CKV_AWS_144` (cross-region
replication) failed on both buckets until a genuine `aws_s3_bucket_replication_configuration`
and a scoped replication role were added. The destination buckets and replica key live in
another region and are referenced by ARN through `locals`, so this file is not standalone
`terraform apply`-able — it assumes the disaster-recovery stack exists.

**3. The container digests are placeholders.** The two `sha256:` digests in
`secure_app.Dockerfile` are illustrative and were never resolved against a registry;
neither scanner verifies that a digest exists, only that one is present. Re-resolve them
before building. Same for `arn:aws:iam::111122223333:root` and the KMS key UUID, which are
AWS documentation placeholders, and for the hardcoded `eu-west-1`.

**4. Passing two policy engines is not a threat model.** Neither scanner has an opinion
about whether replicating access logs cross-region is appropriate for your data residency
rules, whether a 2555-day retention is legal where you operate, or whether the VPC CIDR is
a meaningful trust boundary in your network. Those are the questions that actually decide
whether this configuration is safe, and no rule ID covers them.

## These are safe to read

Unlike every other file in `samples/`, these are not traps. They are a reasonable starting
point for how the controls in this corpus are supposed to look, and the flaws planted in
`samples/*.tf` and `samples/*.Dockerfile` mostly have their corrected counterpart
somewhere in this directory.

They are still not safe to deploy unreviewed — see the four caveats above, plus the
obvious: bucket names must be globally unique, there is no backend or state configuration,
and nothing here has been `terraform validate`d (no Terraform binary is available in this
environment; the syntax check these files have passed is checkov's HCL parser reporting
zero parsing errors).

## Not part of the scored corpus (yet)

`eval.fixture_paths()` enumerates `samples/` with `iterdir()` and keeps only files, so this
subdirectory is skipped and these four files are **not** currently picked up by
`eval/run_eval.py`. Wiring them in is a change to the eval harness, not to this directory.
Two things will need deciding when someone does:

- They have no `eval/labels/*.labels.yaml` files, and should not — a label set with zero
  labels is the correct ground truth for a clean file, but the loader currently treats a
  missing label file as an error.
- `eval.fixture_key()` flattens to `samples/<basename>`, so `secure_s3.tf` would key as
  `samples/secure_s3.tf` and collide with any future top-level file of that name.
