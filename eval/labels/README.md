# Ground-truth labels

One YAML file per fixture in `samples/`, naming the flaws that were **deliberately planted**
in that fixture. This is the recall denominator. Without it, any claim about how much the
pipeline finds is unfalsifiable — which is exactly the failure mode this directory exists to
fix.

| label file | fixture |
| --- | --- |
| `vulnerable_main.labels.yaml` | `samples/vulnerable_main.tf` |
| `s3_public.labels.yaml` | `samples/s3_public.tf` |
| `ec2_open.labels.yaml` | `samples/ec2_open.tf` |
| `vulnerable_network.labels.yaml` | `samples/vulnerable_network.tf` |
| `docker_insecure.labels.yaml` | `samples/docker_insecure.Dockerfile` |
| `vulnerable.labels.yaml` | `samples/vulnerable.Dockerfile` |

The filename is `<fixture stem>.labels.yaml`, i.e. `Path(fixture).stem + ".labels.yaml"`.

## Schema

```yaml
schema_version: 1
fixture: samples/vulnerable_main.tf   # repo-relative path to the file these labels describe
framework: terraform                  # terraform | dockerfile — matches IaCType
labels:
  - id: RDS-PUBLICLY-ACCESSIBLE       # stable, unique within the file, SCREAMING-KEBAB
    resource: aws_db_instance.bad_rds # see "Addressing" below
    lines: [109]                      # source lines; [] means whole-file scope
    description: "RDS instance is reachable from the public internet"
    category: public-exposure
    severity_expected: critical
    checkov_ids: [CKV_AWS_17]         # verified against real output; [] if none fires
    trivy_ids: [AVD-AWS-0180]         # verified against real output; [] if none fires
    detectable_by_scanner: true       # false exactly when both id lists are empty
    aliases: ["publicly accessible", "public database", "publicly_accessible = true"]
```

**`id`** is the join key. Ids are intentionally reused across fixtures when the same flaw is
planted twice (`SG-UNRESTRICTED-EGRESS` appears in three files, `CONTAINER-RUNS-AS-ROOT` in
both Dockerfiles) so per-flaw detection can be compared across fixtures. Ids are unique
*within* a file, not globally.

**`category`** is one of: `public-exposure`, `secrets`, `encryption`, `iam-overprivilege`,
`network-open`, `supply-chain`, `container-hardening`.

**`severity_expected`** is `critical` | `high` | `medium` | `low`, hand-assigned with this
rubric: *critical* = an unauthenticated attacker reaches data or credentials directly;
*high* = a serious weakening that still needs a second step; *medium* = hardening gap;
*low* = hygiene. It is descriptive only — **do not** match on it. Scanners disagree wildly
about severity (Trivy rates unrestricted egress `CRITICAL` and public-read S3 `HIGH`), and
Checkov's community rule set emits no severity at all, so the field carries our judgement,
not theirs.

**`aliases`** are phrasings a model might plausibly use for the same flaw, to give automatic
matching something to work with beyond exact string equality. They are hints, not an
exhaustive vocabulary; a matcher that relies on them alone will under-count.

### Addressing (`resource` / `lines`)

- Terraform: the Terraform address — `aws_db_instance.bad_rds`, `var.api_key`,
  `output.exposed_api_key`.
- Dockerfile: the instruction and enough of its argument to identify it — `EXPOSE 22`,
  `RUN chmod 777 /app/data`, `ADD https://example.com/tools/toolkit.tar.gz`. Flaws that are
  properties of the whole image rather than of a line (no `USER`, no `HEALTHCHECK`) use the
  pseudo-resource `image` with `lines: []`.
- An empty `lines` list always means whole-file scope. It never means "unknown".
- `resource` is the *planted* address. A scanner may attribute its equivalent finding
  somewhere else: for `IAM-POLICY-ATTACHED-TO-USER`, Checkov reports
  `aws_iam_user_policy_attachment.attach_danger` while Trivy reports
  `aws_iam_user.danger_user`. Matching on `(rule_id, resource)` alone will miss that.

## Planted vs incidental

**Planted** = a flaw the fixture author wrote on purpose. The fixtures make this easy: the
Terraform files annotate their flaws inline (`# <- public-read is insecure`) and the two
Dockerfiles number theirs in comments (`# 9) Embedding plaintext credentials in ENV`). Those
annotations are the flaw inventory, and each label's `description` quotes the comment number
it came from. Two exceptions were admitted, both noted in the file that contains them:
`SG-UNRESTRICTED-EGRESS` in `ec2_open.tf` and `vulnerable_network.tf` carries no inline
comment, but is the identical insecure literal that *is* annotated in `vulnerable_main.tf`.

**Incidental** = everything else a scanner reports. Overwhelmingly these are *omissions* —
controls the fixture never mentioned: no bucket versioning, no access logging, no VPC flow
logs, no IMDSv2, no detailed monitoring, no lifecycle rule. They are real findings and not
noise, but nobody planted them, so counting them as ground truth would silently inflate the
denominator with things the fixture was never testing for.

The rule:

- **Recall** is measured over planted labels only. Missing a planted flaw is a false negative.
- **Precision** counts a reported issue as a false positive only if it matches no label
  *and* no scanner finding. An issue that matches an incidental scanner finding is
  **excluded from both** — neither credit nor penalty. It is a true observation about the
  file that this ground truth does not adjudicate.
- **Before/after deltas** ignore this distinction entirely. They are pure scanner set
  arithmetic over `ScanResult.keys()`, so incidental findings count fully there. A fix that
  removes the planted flaw but leaves 20 incidental findings should, and will, show a small
  delta.

How the two populations fall out, from the scans described below:

| fixture | planted labels | detectable | not detectable | checkov mapped/total | trivy mapped/total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `vulnerable_main.tf` | 12 | 9 | 3 | 16 / 37 | 7 / 23 |
| `s3_public.tf` | 1 | 1 | 0 | 1 / 8 | 1 / 10 |
| `ec2_open.tf` | 2 | 2 | 0 | 2 / 8 | 2 / 6 |
| `vulnerable_network.tf` | 3 | 3 | 0 | 3 / 7 | 2 / 5 |
| `docker_insecure.Dockerfile` | 18 | 7 | 11 | 5 / 5 | 7 / 7 |
| `vulnerable.Dockerfile` | 16 | 6 | 10 | 5 / 5 | 6 / 6 |
| **total** | **52** | **28** | **24** | **32 / 70** | **25 / 57** |

The Terraform fixtures are mostly incidental findings; the Dockerfiles are the reverse —
every one of their 23 scanner findings maps to a planted label, and 21 planted flaws are
invisible to both scanners.

## `detectable_by_scanner`

`false` means: **neither scanner reports this flaw when invoked the way `iac_agent.scanners`
invokes them.** That is a claim about this pipeline, not about the tools in general. Checkov
run with `--framework secrets` would catch some of these; `iac_agent` runs
`--framework terraform` / `--framework dockerfile` only.

The 24 undetectable labels are the only honest basis for claiming the LLM layer finds
anything static analysis cannot. Each was confirmed by checking that no failing rule covers
it, and — where a rule *exists but passes* — by saying so in a comment on the label. Those
near-misses are the interesting ones:

- `EC2-USERDATA-PLAINTEXT-SECRET` — Checkov's `CKV_AWS_46` ("no hard-coded secrets exist in
  EC2 user data") **passes**: it matches AWS-key-shaped strings, and the planted secret is
  `DB_PASSWORD=SuperInsecurePassword123!`. Trivy catches it, so the label is still
  `detectable_by_scanner: true`.
- `TF-VARIABLE-HARDCODED-API-KEY` — Checkov's `CKV_AWS_41` passes because it only inspects
  `provider` blocks, not variable defaults.
- `BASE-IMAGE-NOT-PINNED` — `CKV_DOCKER_7` and `DS001` both pass. The comment claims a
  `latest` tag; the code says `python:3.10-slim`. Mutable, but not `latest`.
- `ADD-USED-FOR-REMOTE-ARCHIVE` — Trivy's `DS005` passes because it permits `ADD` for remote
  URLs. Checkov's `CKV_DOCKER_4` does not, so the label is detectable.
- `SECRETS-FILE-COPIED-INTO-IMAGE` — `DS031`'s title mentions copied secret files, but it
  fires only on the `ENV` lines. The `COPY ./secrets.env` line is flagged by nothing.

## How the ids were verified

Every `checkov_ids` / `trivy_ids` entry was copied out of a real scan of that exact fixture.
None were written from memory. This matters: the project's original submitted report
contained a results table whose policy ids described entirely different policies
(`CKV_AWS_3` is EBS encryption, not security groups; `CKV_AWS_7` is CMK rotation, not IAM
wildcards), because they were recalled rather than read.

Commands, run 2026-07-28 with **checkov 3.2.489** and **trivy 0.68.1** on Python 3.13:

```sh
.venv/bin/checkov -f samples/<file> -o json --compact --quiet --framework <terraform|dockerfile>
trivy config --quiet --format json samples/<file>
```

To confirm a "no policy fires" claim, the same commands were re-run without `--quiet` and
with `--include-non-failures` respectively, so that rules which *exist and pass* could be
told apart from rules that do not exist.

### Trivy's `ID` field is not always the AVD id

`iac_agent.scanners.TrivyScanner` puts Trivy's `ID` field into `Finding.rule_id`. For some
rules that field is a legacy slug rather than the `AVD-...` id, and the slug sometimes
describes a *different* rule than the one that fired:

| emitted `ID` | `AVDID` | what actually fired |
| --- | --- | --- |
| `aws-autoscaling-no-public-ip` | `AVD-AWS-0029` | sensitive data in EC2 user data |
| `aws-vpc-no-public-ingress-sgr` | `AVD-AWS-0164` | subnet auto-assigns public IP |
| `aws-vpc-no-public-egress-sgr` | `AVD-AWS-0104` | unrestricted egress |
| `aws-autoscaling-enable-at-rest-encryption` | `AVD-AWS-0178` | VPC flow logs disabled |

Where the two differ, **both strings are listed** in `trivy_ids`: the emitted `ID` first
(that is what `Finding.rule_id` will contain) and the `AVDID` second (that is what a human
will look up). A matcher should treat `trivy_ids` as a set of acceptable identifiers, not as
a single canonical id. Dockerfile rules follow the same convention (`DS031` and
`AVD-DS-0031`).

## One flaw, many rules

Checkov fires ten separate policies on the single wildcard IAM policy in
`vulnerable_main.tf` (`CKV_AWS_62`, `_63`, `_355`, `_286`–`_290`, `CKV2_AWS_40`). All ten are
listed on `IAM-POLICY-WILDCARD-ADMIN`. Conversely, Trivy raises `DS031` three times for the
three credential-bearing `ENV` lines, and one label `ENV-PLAINTEXT-CREDENTIALS` covers all
three, because a reviewer or a model would report that as one issue.

So: **a label matches if *any* id in its lists is present**, and one scanner finding may be
consumed by only one label. Splitting these into one label per rule id would make recall a
measure of how verbosely Checkov happens to describe a single mistake.

## Status: hand-authored, single annotator

These labels are one person's reading of six files. The scanner ids in them are mechanically
verified; **the label set itself is not.** A second annotator should review it, and the
judgement calls most worth arguing with are:

1. **Granularity.** Comment 3 in both Dockerfiles bundles three flaws (sudo installed,
   missing `--no-install-recommends`, excessive toolchain) and is split into three labels;
   comment 8/9's three `ENV` lines are merged into one. Both choices are defensible in the
   other direction.
2. **`s3_public.tf` has exactly one label** while the scanners produce 18 findings on it. The
   file is four lines long and plants one flaw. If that reads as under-labelling, the fix is
   to add planted flaws to the fixture, not labels to this file.
3. **Un-annotated egress rules** in `ec2_open.tf` and `vulnerable_network.tf` are treated as
   planted. A stricter reading — annotation or nothing — would drop two labels.
4. **Comments that overstate the code.** Both Dockerfiles claim a `latest` tag and a
   non-minimal base image; the code uses `python:3.10-slim`, which is neither. No label was
   created for "non-minimal base" because the flaw is not actually present, and inventing
   ground truth to match a comment would corrupt the measurement.
5. **`IAM-POLICY-ATTACHED-TO-USER`** is labelled from the section header's wording
   ("attached to a user") rather than from an inline `# <- insecure` marker.

Changing a label id changes the join key for every stored evaluation result. Add an id
rather than renaming one, and bump `schema_version` if the field set changes.
