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
| repeat runs | 1 |
| variants | stripped |
| checkov | `3.2.489` |
| trivy | `0.68.1` |
| python | `3.13.14` |
| timestamp (UTC) | 2026-07-28T19:33:45+00:00 |
| cache hits / misses | 0 / 12 |
| live model calls | 12 |
| system_fingerprints | none recorded |
> **Note.** Label leakage not measured: it needs detection results for BOTH the commented and stripped variants (run with --variant both).

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

### Variant: `stripped`
| scanner | before | after | delta | resolved | introduced | persisted | invalid outputs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| checkov | 70.0 | 43.0 | 38.6% | 27.0 | 0.0 | 43.0 | 0.0 |
| trivy | 57.0 | 38.0 | 33.3% | 15.0 | 0.0 | 36.0 | 0.0 |

`resolved - introduced` need not equal `before - after`: `Finding.key()` is `(rule_id, resource)` and is not injective — Trivy raises `DS031` three times on three `ENV` lines with an empty resource, so three findings share one key. The key is also unstable under renaming, which inflates `resolved` and `introduced` together; read them beside the drift table, not alone.

**Per-rule resolution — checkov** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `CKV_AWS_20` | 2 | 0 | 2 |
| `CKV_AWS_24` | 2 | 0 | 2 |
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
| `CKV_DOCKER_1` | 2 | 1 | 1 |

Rules listed: the 22 whose count changed. 25 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

**Per-rule resolution — trivy** (first repeat)
| rule_id | before | after | resolved |
| --- | --- | --- | --- |
| `DS031` | 6 | 0 | 6 |
| `AVD-AWS-0092` | 2 | 0 | 2 |
| `AVD-AWS-0107` | 2 | 0 | 2 |
| `DS002` | 2 | 0 | 2 |
| `DS026` | 2 | 0 | 2 |
| `AVD-AWS-0131` | 2 | 1 | 1 |
| `AVD-AWS-0180` | 1 | 0 | 1 |
| `DS004` | 2 | 1 | 1 |
| `aws-vpc-no-public-egress-sgr` | 3 | 2 | 1 |
| `aws-vpc-no-public-ingress-sgr` | 1 | 0 | 1 |

Rules listed: the 10 whose count changed. 20 further rules fired before and were still failing afterwards at the same count; the full per-rule table is in `eval/results/results.json`.

## 3. Detection precision and recall
Scored against `eval/labels/*.labels.yaml`. The recall denominator is **planted labels only** — incidental scanner findings are excluded from both precision and recall while still counting fully in the delta above.
| variant | labels | TP_label | FN | recall | findings | TP_finding | FP_strict | precision (strict) | precision (adjudicated) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stripped | 52 | 19.0 | 33.0 | 36.5% | 32.0 | 18.0 | 14.0 | 56.2% | 69.2% |

`precision_strict = TP_finding / |findings|` is the defensible floor — it calls every unmatched finding wrong, including genuine flaws the annotator never planted. `precision_adjudicated = TP_finding / (|findings| - |plausible|)` excludes unmatched-but-plausible findings from the denominator instead of penalising them; they are counted separately below. The gap between the two measures how incomplete the labels are, and the adjudicated figure is produced by the system's own author judging the system's output.
| variant | unmatched but plausible | unmatched, no support (hallucination) | precision (adjudicated, credited form) |
| --- | --- | --- | --- |
| stripped | 6.0 | 8.0 | 75.0% |

The last column is the alternative spelling from `docs/EVALUATION.md` §5.2, `(TP_finding + |plausible|) / |findings|`, which credits plausible findings in the numerator rather than removing them from the denominator. Both appear in the project's own documents, so both are printed rather than one being quietly chosen.

**Per fixture — `stripped` (first repeat)**
| fixture | labels | TP_label | recall | findings | TP_finding | FP_strict | missed labels |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `samples/docker_insecure.Dockerfile` | 18 | 7 | 38.9% | 8 | 7 | 1 | `ADD-USED-FOR-REMOTE-ARCHIVE`, `COPY-ENTIRE-BUILD-CONTEXT`, `EXPOSE-DOCKER-DAEMON-PORT-2375`, `EXPOSE-SSH-PORT-22`, `PIP-INSTALL-WITHOUT-HASHES`, `PKG-APT-MISSING-NO-INSTALL-RECOMMENDS`, `PKG-SUDO-INSTALLED`, `REMOTE-SCRIPT-PIPED-TO-SHELL`, `SECRETS-FILE-COPIED-INTO-IMAGE`, `SSHD-INSIDE-CONTAINER`, `WORLD-WRITABLE-TMP-ARTIFACT` |
| `samples/ec2_open.tf` | 2 | 0 | 0.0% | 2 | 0 | 2 | `SG-SSH-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS` |
| `samples/s3_public.tf` | 1 | 1 | 100.0% | 1 | 1 | 0 | — |
| `samples/vulnerable.Dockerfile` | 16 | 8 | 50.0% | 10 | 7 | 3 | `ADD-USED-FOR-REMOTE-ARCHIVE`, `COPY-ENTIRE-BUILD-CONTEXT`, `PIP-INSTALL-WITHOUT-HASHES`, `PKG-EXCESSIVE-TOOLCHAIN`, `PKG-SUDO-INSTALLED`, `REMOTE-SCRIPT-PIPED-TO-SHELL`, `SECRETS-FILE-COPIED-INTO-IMAGE`, `SSHD-INSIDE-CONTAINER` |
| `samples/vulnerable_main.tf` | 12 | 2 | 16.7% | 8 | 2 | 6 | `EC2-ROOT-VOLUME-UNENCRYPTED`, `EC2-USERDATA-PLAINTEXT-SECRET`, `IAM-POLICY-ATTACHED-TO-USER`, `IAM-POLICY-WILDCARD-ADMIN`, `RDS-HARDCODED-PASSWORD`, `S3-BUCKET-POLICY-PUBLIC-PRINCIPAL`, `SG-SSH-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS`, `TF-OUTPUT-EXPOSES-SECRET`, `TF-VARIABLE-HARDCODED-API-KEY` |
| `samples/vulnerable_network.tf` | 3 | 1 | 33.3% | 3 | 1 | 2 | `SG-HTTP-OPEN-TO-WORLD`, `SG-UNRESTRICTED-EGRESS` |

## 5. Validity rate
`validity_rate = outputs that parse / generation attempts`, measured over **attempts** — including any a refinement loop discarded, because validity measured on accepted outputs is 100% by construction. A syntax gate only: `hcl2` parses the grammar, it does not resolve references or check provider schemas, so a file can pass this and still fail `terraform validate`.
| variant | framework | attempts | parsed | validity rate |
| --- | --- | --- | --- | --- |
| stripped | dockerfile | 2 | 2 | 100.0% |
| stripped | terraform | 4 | 4 | 100.0% |
| stripped | **all** | 6 | 6 | 100.0% |

## 6. Semantic drift — the number that audits the headline
The cheapest way to make a finding disappear is to delete the resource it was about. That scores a **perfect** finding delta, passes the validity gate, and leaves precision and recall untouched, while destroying the user's infrastructure. `drift_touches_flaw()` is the only signal in this protocol that can tell that apart from a real fix.
| variant | valid outputs | of which Terraform | drifted | drift rate (Terraform) | **drift touched a flaw-carrying resource** | deleted | renamed | added |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| stripped | 6 | 4 | 1 | 25.0% | 1 | 1 | 0 | 0 |

The drift rate is quoted over **Terraform** outputs: a Dockerfile has no addressable resources, so it can never drift, and including Dockerfiles in the denominator would dilute the rate with outputs structurally incapable of moving it. Renames count as drift — Terraform keys state on the address, so a rename destroys and recreates on the next apply. Additions never do, because fixing a public bucket correctly *requires* adding resources.

**Drift events — `stripped`** (listed individually, not just counted)
| fixture | run | summary | flaw-carrying resources lost |
| --- | --- | --- | --- |
| `samples/vulnerable_main.tf` | 0 | DRIFT: deleted aws_s3_bucket_policy.public_policy; count drops: aws_s3_bucket_policy 1->0 | `aws_s3_bucket_policy.public_policy` |

---
Method, denominators and threats to validity: [`docs/EVALUATION.md`](../../docs/EVALUATION.md). Ground truth and the planted-versus-incidental rule: [`eval/labels/README.md`](../labels/README.md).
