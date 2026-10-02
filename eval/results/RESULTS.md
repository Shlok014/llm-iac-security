<!--
  GENERATED FILE — DO NOT EDIT BY HAND.

  Regenerate with:

      .venv/bin/python -m eval.run_eval report

  Every number below is computed by eval/metrics.py from eval/results/results.json,
  eval/results/baseline.json and eval/labels/*.labels.yaml. Nothing here is typed in.

  That rule is not tidiness. The project this replaces shipped a hand-written results
  table whose policy ids described entirely different policies, because they were
  recalled rather than read. A hand-edited results file is a claim; a generated one is a
  measurement, and the difference is the whole point of this directory.
-->
# Evaluation results
All figures are descriptive statistics over repeat runs — `mean [min, max]`. **n is far too small for confidence intervals**, significance tests, or any claim that one configuration beats another; the range answers only *how much does this number move when nothing changes?*
## Run configuration
| parameter | value |
| --- | --- |
| model snapshot | `gpt-4o-mini-2024-07-18` |
| prompt_version | `v2` |
| temperature | 0.0 |
| seed | 42 |
| repeat runs | 3 |
| variants | commented, stripped |
| checkov | `3.2.489` |
| trivy | `0.68.1` |
| python | `3.13.14` |
| timestamp (UTC) | 2026-07-28T20:21:41+00:00 |
| cache hits / misses | 0 / 72 |
| live model calls | 72 |
| system_fingerprints | none recorded |

## 1. Scanner-only baseline (B1 / B2) — what the LLM has to beat
Checkov and Trivy run in about a second each, need no API key and cost nothing. Any claim on behalf of a pipeline that costs money and can hallucinate has to be a claim about something these two do not already do for free. **The absence of this table was the largest hole in the original report.**

### Variant: `commented`
| fixture | checkov failed | trivy findings | planted labels | of which scanner-detectable |
| --- | --- | --- | --- | --- |
| `samples/docker_insecure.Dockerfile` | 5 | 7 | 18 | 7 |
| `samples/ec2_open.tf` | 8 | 6 | 2 | 2 |
| `samples/s3_public.tf` | 8 | 10 | 1 | 1 |
| `samples/vulnerable.Dockerfile` | 5 | 6 | 16 | 6 |
| `samples/vulnerable_main.tf` | 37 | 23 | 12 | 9 |
| `samples/vulnerable_network.tf` | 7 | 5 | 3 | 3 |
| **total** | 70 | 57 | 52 | 28 |

Those two totals are counts of **rule violations, not of flaws**, and they do not sum: one planted flaw trips many rules, and the two rulesets overlap. The recall denominator is the label column.

**Scanner recall against the ground truth**
| scanner | findings | mapped to a planted label | incidental | labels detected | recall (all labels) | recall (detectable subset) |
| --- | --- | --- | --- | --- | --- | --- |
| checkov | 70 | 32 | 38 | 24 | 46.2% | 85.7% |
| trivy | 57 | 25 | 32 | 21 | 40.4% | 75.0% |
| union | n/a (see note) | — | — | 28 | 53.8% | 100.0% |

`recall (detectable subset)` should be 1.000 by construction — `detectable_by_scanner` is *defined* as 'a rule in one of these two tools fires on it'. A value below 1.0 means a label's ids are wrong, not that a scanner underperformed.

### Variant: `stripped`
| fixture | checkov failed | trivy findings | planted labels | of which scanner-detectable |
| --- | --- | --- | --- | --- |
| `samples/docker_insecure.Dockerfile` | 5 | 7 | 18 | 7 |
| `samples/ec2_open.tf` | 8 | 6 | 2 | 2 |
| `samples/s3_public.tf` | 8 | 10 | 1 | 1 |
| `samples/vulnerable.Dockerfile` | 5 | 6 | 16 | 6 |
| `samples/vulnerable_main.tf` | 37 | 23 | 12 | 9 |
| `samples/vulnerable_network.tf` | 7 | 5 | 3 | 3 |
| **total** | 70 | 57 | 52 | 28 |

Those two totals are counts of **rule violations, not of flaws**, and they do not sum: one planted flaw trips many rules, and the two rulesets overlap. The recall denominator is the label column.

**Scanner recall against the ground truth**
| scanner | findings | mapped to a planted label | incidental | labels detected | recall (all labels) | recall (detectable subset) |
| --- | --- | --- | --- | --- | --- | --- |
| checkov | 70 | 32 | 38 | 24 | 46.2% | 85.7% |
| trivy | 57 | 25 | 32 | 21 | 40.4% | 75.0% |
| union | n/a (see note) | — | — | 28 | 53.8% | 100.0% |

`recall (detectable subset)` should be 1.000 by construction — `detectable_by_scanner` is *defined* as 'a rule in one of these two tools fires on it'. A value below 1.0 means a label's ids are wrong, not that a scanner underperformed.

**Label id verification: passed.** Every label with a non-empty id list has at least one of those ids present in that fixture's baseline scan.

## 2. Finding delta (headline)
`delta = (before - after) / before`, over every rule violation, planted or incidental. **`introduced` is never netted against `resolved`**: a run that resolves 40 and introduces 10 would otherwise be indistinguishable from one that resolves 30 and introduces 0, and the first wrote ten new misconfigurations into the user's infrastructure. An output that failed the validity gate is scored as `after = before` — nothing usable was produced, so nothing was fixed.

### Variant: `commented`
| scanner | before | after | delta | resolved | introduced | persisted | invalid outputs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| checkov | 70.0 | 42.3 [42.0, 43.0] | 39.5% [38.6%, 40.0%] | 27.7 [27.0, 28.0] | 0.0 | 42.3 [42.0, 43.0] | 0.0 |
| trivy | 57.0 | 30.3 [18.0, 37.0] | 46.8% [35.1%, 68.4%] | 22.7 [16.0, 35.0] | 0.0 | 28.3 [16.0, 35.0] | 0.0 |

`resolved - introduced` need not equal `before - after`: `Finding.key()` is `(rule_id, resource)` and is not injective — Trivy raises `DS031` three times on three `ENV` lines with an empty resource, so three findings share one key. The key is also unstable under renaming, which inflates `resolved` and `introduced` together; read them beside the drift table, not alone.

**Per-rule resolution — checkov** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `CKV_AWS_20` | 2 | 0 | 2 |
| `CKV_AWS_24` | 2 | 0 | 2 |
| `CKV_DOCKER_1` | 2 | 0 | 2 |
| `CKV_DOCKER_2` | 2 | 0 | 2 |
| `CKV_DOCKER_3` | 2 | 0 | 2 |
| `CKV_DOCKER_4` | 2 | 0 | 2 |
| `CKV2_AWS_40` | 1 | 0 | 1 |
| `CKV2_DOCKER_1` | 2 | 1 | 1 |
| `CKV_AWS_130` | 1 | 0 | 1 |
| `CKV_AWS_17` | 1 | 0 | 1 |
| `CKV_AWS_260` | 1 | 0 | 1 |
| `CKV_AWS_286` | 1 | 0 | 1 |
| `CKV_AWS_287` | 1 | 0 | 1 |
| `CKV_AWS_288` | 1 | 0 | 1 |
| `CKV_AWS_289` | 1 | 0 | 1 |
| `CKV_AWS_290` | 1 | 0 | 1 |
| `CKV_AWS_355` | 1 | 0 | 1 |
| `CKV_AWS_382` | 3 | 2 | 1 |
| `CKV_AWS_62` | 1 | 0 | 1 |
| `CKV_AWS_63` | 1 | 0 | 1 |
| `CKV_AWS_70` | 1 | 0 | 1 |
| `CKV_AWS_8` | 2 | 1 | 1 |

Rules listed: the 22 whose count changed. 25 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

**Per-rule resolution — trivy** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `DS031` | 6 | 0 | 6 |
| `AVD-AWS-0092` | 2 | 0 | 2 |
| `AVD-AWS-0107` | 2 | 0 | 2 |
| `DS002` | 2 | 0 | 2 |
| `DS004` | 2 | 0 | 2 |
| `DS026` | 2 | 0 | 2 |
| `AVD-AWS-0028` | 2 | 1 | 1 |
| `AVD-AWS-0077` | 1 | 0 | 1 |
| `AVD-AWS-0080` | 1 | 0 | 1 |
| `AVD-AWS-0086` | 2 | 1 | 1 |
| `AVD-AWS-0087` | 2 | 1 | 1 |
| `AVD-AWS-0088` | 2 | 1 | 1 |
| `AVD-AWS-0090` | 2 | 1 | 1 |
| `AVD-AWS-0091` | 2 | 1 | 1 |
| `AVD-AWS-0093` | 2 | 1 | 1 |
| `AVD-AWS-0094` | 2 | 1 | 1 |
| `AVD-AWS-0131` | 2 | 1 | 1 |
| `AVD-AWS-0132` | 2 | 1 | 1 |
| `AVD-AWS-0133` | 1 | 0 | 1 |
| `AVD-AWS-0143` | 1 | 0 | 1 |
| `AVD-AWS-0176` | 1 | 0 | 1 |
| `AVD-AWS-0177` | 1 | 0 | 1 |
| `AVD-AWS-0180` | 1 | 0 | 1 |
| `DS029` | 1 | 0 | 1 |
| `aws-autoscaling-no-public-ip` | 1 | 0 | 1 |
| `aws-vpc-add-description-to-security-group-rule` | 5 | 4 | 1 |
| `aws-vpc-no-public-egress-sgr` | 3 | 2 | 1 |
| `aws-vpc-no-public-ingress-sgr` | 1 | 0 | 1 |
| `s3-bucket-logging` | 2 | 1 | 1 |

Rules listed: the 29 whose count changed. 1 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

### Variant: `stripped`
| scanner | before | after | delta | resolved | introduced | persisted | invalid outputs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| checkov | 70.0 | 42.3 [41.0, 44.0] | 39.5% [37.1%, 41.4%] | 27.7 [26.0, 29.0] | 0.0 | 42.3 [41.0, 44.0] | 0.0 |
| trivy | 57.0 | 37.7 [37.0, 38.0] | 33.9% [33.3%, 35.1%] | 15.3 [15.0, 16.0] | 0.0 | 35.7 [35.0, 36.0] | 0.0 |

`resolved - introduced` need not equal `before - after`: `Finding.key()` is `(rule_id, resource)` and is not injective — Trivy raises `DS031` three times on three `ENV` lines with an empty resource, so three findings share one key. The key is also unstable under renaming, which inflates `resolved` and `introduced` together; read them beside the drift table, not alone.

**Per-rule resolution — checkov** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `CKV_AWS_20` | 2 | 0 | 2 |
| `CKV_AWS_24` | 2 | 0 | 2 |
| `CKV_AWS_382` | 3 | 1 | 2 |
| `CKV_DOCKER_1` | 2 | 0 | 2 |
| `CKV_DOCKER_2` | 2 | 0 | 2 |
| `CKV_DOCKER_3` | 2 | 0 | 2 |
| `CKV_DOCKER_4` | 2 | 0 | 2 |
| `CKV2_AWS_40` | 1 | 0 | 1 |
| `CKV_AWS_130` | 1 | 0 | 1 |
| `CKV_AWS_17` | 1 | 0 | 1 |
| `CKV_AWS_260` | 1 | 0 | 1 |
| `CKV_AWS_286` | 1 | 0 | 1 |
| `CKV_AWS_287` | 1 | 0 | 1 |
| `CKV_AWS_288` | 1 | 0 | 1 |
| `CKV_AWS_289` | 1 | 0 | 1 |
| `CKV_AWS_290` | 1 | 0 | 1 |
| `CKV_AWS_355` | 1 | 0 | 1 |
| `CKV_AWS_62` | 1 | 0 | 1 |
| `CKV_AWS_63` | 1 | 0 | 1 |
| `CKV_AWS_70` | 1 | 0 | 1 |
| `CKV_AWS_8` | 2 | 1 | 1 |

Rules listed: the 21 whose count changed. 26 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

**Per-rule resolution — trivy** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `DS031` | 6 | 0 | 6 |
| `AVD-AWS-0092` | 2 | 0 | 2 |
| `AVD-AWS-0107` | 2 | 0 | 2 |
| `DS002` | 2 | 0 | 2 |
| `DS004` | 2 | 0 | 2 |
| `DS026` | 2 | 0 | 2 |
| `AVD-AWS-0131` | 2 | 1 | 1 |
| `AVD-AWS-0180` | 1 | 0 | 1 |
| `aws-vpc-no-public-ingress-sgr` | 1 | 0 | 1 |

Rules listed: the 9 whose count changed. 21 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

## 3. Detection precision and recall
Scored against `eval/labels/*.labels.yaml`. The recall denominator is **planted labels only** — incidental scanner findings are excluded from both precision and recall while still counting fully in the delta above.
| variant | labels | TP_label | FN | recall | findings | TP_finding | FP_strict | precision (strict) | precision (adjudicated) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| commented | 52 | 27.3 [25.0, 30.0] | 24.7 [22.0, 27.0] | 52.6% [48.1%, 57.7%] | 40.0 | 27.3 [25.0, 30.0] | 12.7 [10.0, 15.0] | 68.3% [62.5%, 75.0%] | 78.0% [73.5%, 83.3%] |
| stripped | 52 | 20.3 [19.0, 21.0] | 31.7 [31.0, 33.0] | 39.1% [36.5%, 40.4%] | 33.7 [32.0, 35.0] | 20.0 [18.0, 22.0] | 13.7 [13.0, 14.0] | 59.3% [56.2%, 62.9%] | 73.1% [69.2%, 75.9%] |

`precision_strict = TP_finding / |findings|` is the defensible floor — it calls every unmatched finding wrong, including genuine flaws the annotator never planted. `precision_adjudicated = TP_finding / (|findings| - |plausible|)` excludes unmatched-but-plausible findings from the denominator instead of penalising them; they are counted separately below. The gap between the two measures how incomplete the labels are, and the adjudicated figure is produced by the system's own author judging the system's output.
| variant | unmatched but plausible | unmatched, no support (hallucination) | precision (adjudicated, credited form) |
| --- | --- | --- | --- |
| commented | 5.0 [4.0, 6.0] | 7.7 [6.0, 9.0] | 80.8% [77.5%, 85.0%] |
| stripped | 6.3 [6.0, 7.0] | 7.3 [7.0, 8.0] | 78.1% [75.0%, 80.0%] |

The last column is the alternative spelling from `docs/EVALUATION.md` §5.2, `(TP_finding + |plausible|) / |findings|`, which credits plausible findings in the numerator rather than removing them from the denominator. Both appear in the project's own documents, so both are printed rather than one being quietly chosen.

**Per fixture — `commented` (first repeat)**
| fixture | labels | TP_label | recall | findings | TP_finding | FP_strict | missed labels |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `samples/docker_insecure.Dockerfile` | 18 | 12 | 66.7% | 13 | 12 | 1 | `BASE-IMAGE-NOT-PINNED`, `EXPOSE-DOCKER-DAEMON-PORT-2375`, `PKG-APT-MISSING-NO-INSTALL-RECOMMENDS`, `PKG-EXCESSIVE-TOOLCHAIN`, `PKG-SUDO-INSTALLED`, `SSHD-INSIDE-CONTAINER` |
| `samples/ec2_open.tf` | 2 | 1 | 50.0% | 2 | 1 | 1 | `SG-UNRESTRICTED-EGRESS` |
| `samples/s3_public.tf` | 1 | 1 | 100.0% | 1 | 1 | 0 | — |
| `samples/vulnerable.Dockerfile` | 16 | 11 | 68.8% | 13 | 11 | 2 | `BASE-IMAGE-NOT-PINNED`, `EXPOSE-DOCKER-DAEMON-PORT-2375`, `PIP-INSTALL-WITHOUT-HASHES`, `PKG-SUDO-INSTALLED`, `SECRETS-FILE-COPIED-INTO-IMAGE` |
| `samples/vulnerable_main.tf` | 12 | 4 | 33.3% | 8 | 4 | 4 | `EC2-ROOT-VOLUME-UNENCRYPTED`, `IAM-POLICY-ATTACHED-TO-USER`, `IAM-POLICY-WILDCARD-ADMIN`, `RDS-HARDCODED-PASSWORD`, `S3-BUCKET-POLICY-PUBLIC-PRINCIPAL`, `SG-SSH-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS`, `TF-OUTPUT-EXPOSES-SECRET` |
| `samples/vulnerable_network.tf` | 3 | 1 | 33.3% | 3 | 1 | 2 | `SG-HTTP-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS` |

**Per fixture — `stripped` (first repeat)**
| fixture | labels | TP_label | recall | findings | TP_finding | FP_strict | missed labels |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `samples/docker_insecure.Dockerfile` | 18 | 9 | 50.0% | 9 | 8 | 1 | `ADD-USED-FOR-REMOTE-ARCHIVE`, `COPY-ENTIRE-BUILD-CONTEXT`, `PIP-INSTALL-WITHOUT-HASHES`, `PKG-APT-MISSING-NO-INSTALL-RECOMMENDS`, `PKG-EXCESSIVE-TOOLCHAIN`, `PKG-SUDO-INSTALLED`, `REMOTE-SCRIPT-PIPED-TO-SHELL`, `SECRETS-FILE-COPIED-INTO-IMAGE`, `SSHD-INSIDE-CONTAINER` |
| `samples/ec2_open.tf` | 2 | 0 | 0.0% | 2 | 0 | 2 | `SG-SSH-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS` |
| `samples/s3_public.tf` | 1 | 1 | 100.0% | 1 | 1 | 0 | — |
| `samples/vulnerable.Dockerfile` | 16 | 7 | 43.8% | 10 | 7 | 3 | `ADD-USED-FOR-REMOTE-ARCHIVE`, `COPY-ENTIRE-BUILD-CONTEXT`, `EXPOSE-DOCKER-DAEMON-PORT-2375`, `PIP-INSTALL-WITHOUT-HASHES`, `PKG-EXCESSIVE-TOOLCHAIN`, `PKG-SUDO-INSTALLED`, `REMOTE-SCRIPT-PIPED-TO-SHELL`, `SECRETS-FILE-COPIED-INTO-IMAGE`, `SSHD-INSIDE-CONTAINER` |
| `samples/vulnerable_main.tf` | 12 | 3 | 25.0% | 9 | 3 | 6 | `EC2-ROOT-VOLUME-UNENCRYPTED`, `EC2-USERDATA-PLAINTEXT-SECRET`, `IAM-POLICY-ATTACHED-TO-USER`, `IAM-POLICY-WILDCARD-ADMIN`, `RDS-HARDCODED-PASSWORD`, `S3-BUCKET-POLICY-PUBLIC-PRINCIPAL`, `SG-SSH-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS`, `TF-OUTPUT-EXPOSES-SECRET` |
| `samples/vulnerable_network.tf` | 3 | 1 | 33.3% | 3 | 1 | 2 | `SG-HTTP-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS` |

## 4. Label leakage (B4)
The fixtures annotate their own planted flaws inline, so a detection score measured on them is contaminated — the model can read the answer key. `eval/corpus/stripped/` is the variant with those comments removed, verified by the invariant that **the scanner finding counts must be identical before and after stripping**.
| quantity | value |
| --- | --- |
| recall, commented | 52.6% [48.1%, 57.7%] |
| recall, stripped (headline) | 39.1% [36.5%, 40.4%] |
| **label_leak** | 13.5% |

label_leak = recall(commented) - recall(stripped). A large positive gap means the headline detection number was mostly comment comprehension. A gap near zero means the model read the code. The stripped variant is less contaminated, not provably clean: string literals such as heredoc bodies and resource names like `insecure_sg` still leak.

## 5. Validity rate
`validity_rate = outputs that parse / generation attempts`, measured over **attempts** — including any a refinement loop discarded, because validity measured on accepted outputs is 100% by construction. A syntax gate only: `hcl2` parses the grammar, it does not resolve references or check provider schemas, so a file can pass this and still fail `terraform validate`.
| variant | framework | attempts | parsed | validity rate |
| --- | --- | --- | --- | --- |
| commented | dockerfile | 6 | 6 | 100.0% |
| commented | terraform | 12 | 12 | 100.0% |
| commented | **all** | 18 | 18 | 100.0% |
| stripped | dockerfile | 6 | 6 | 100.0% |
| stripped | terraform | 12 | 12 | 100.0% |
| stripped | **all** | 18 | 18 | 100.0% |

## 6. Semantic drift — the number that audits the headline
The cheapest way to make a finding disappear is to delete the resource it was about. That scores a **perfect** finding delta, passes the validity gate, and leaves precision and recall untouched, while destroying the user's infrastructure. `drift_touches_flaw()` is the only signal in this protocol that can tell that apart from a real fix.
| variant | valid outputs | of which Terraform | drifted | drift rate (Terraform) | **drift touched a flaw-carrying resource** | deleted | renamed | added |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| commented | 18 | 12 | 3 | 25.0% | 3 | 3 | 0 | 0 |
| stripped | 18 | 12 | 2 | 16.7% | 2 | 2 | 0 | 0 |

The quoted rate uses **Terraform** outputs. These stored runs predate the Dockerfile structural gate and contain no Dockerfile drift measurements; new runs record removed application structure separately. Terraform renames count as drift because state keys on the address. Additions alone do not: fixing a public bucket correctly can require adding resources.

**Drift events — `commented`** (listed individually, not just counted)
| fixture | run | summary | flaw-carrying resources lost |
| --- | --- | --- | --- |
| `samples/vulnerable_main.tf` | 0 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |
| `samples/vulnerable_main.tf` | 1 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |
| `samples/vulnerable_main.tf` | 2 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |

**Drift events — `stripped`** (listed individually, not just counted)
| fixture | run | summary | flaw-carrying resources lost |
| --- | --- | --- | --- |
| `samples/vulnerable_main.tf` | 0 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |
| `samples/vulnerable_main.tf` | 1 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |

---
Method, denominators and threats to validity: [`docs/EVALUATION.md`](../../docs/EVALUATION.md). Ground truth and the planted-versus-incidental rule: [`eval/labels/README.md`](../labels/README.md).
