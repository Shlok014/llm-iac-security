"""Tests for the shared model-output parser.

These are regression tests against *observed* model behaviour, not hypotheticals. The
original code parsed model JSON with a bare `json.loads` and, when that failed, returned
`{"raw_output": "..."}` — a success-shaped value. Downstream code could not distinguish
"the model found nothing" from "we could not read the model's answer", so a parse failure
silently became a clean security report.

So the contract under test is two-part:
  1. every realistic malformed-but-recoverable shape must parse, and
  2. every unrecoverable shape must raise ValueError — never return a sentinel.

`strip_code_fences` gets the same treatment: it feeds files straight to a scanner, so a
surviving backtick is a parse error in Checkov, and a parse error used to read as a pass.
"""

from __future__ import annotations

import pytest

from iac_agent.parsing import extract_json, normalise_findings, strip_code_fences

# ---------------------------------------------------------------------------
# extract_json — recoverable shapes
# ---------------------------------------------------------------------------

ONE_FINDING = [{"issue": "S3 bucket is public", "severity": "HIGH"}]


def test_bare_json_array() -> None:
    assert extract_json('[{"issue": "S3 bucket is public", "severity": "HIGH"}]') == ONE_FINDING


def test_json_fence_with_language_tag() -> None:
    text = '```json\n[{"issue": "S3 bucket is public", "severity": "HIGH"}]\n```'
    assert extract_json(text) == ONE_FINDING


def test_bare_triple_backtick_fence() -> None:
    text = '```\n[{"issue": "S3 bucket is public", "severity": "HIGH"}]\n```'
    assert extract_json(text) == ONE_FINDING


def test_fence_with_a_wrong_language_tag() -> None:
    """Models routinely tag JSON as ```python. The bracket-slice stage must rescue it."""
    text = '```python\n[{"issue": "S3 bucket is public", "severity": "HIGH"}]\n```'
    assert extract_json(text) == ONE_FINDING


def test_prose_before_and_after() -> None:
    text = (
        "Sure! I reviewed the Terraform and found one issue:\n"
        '[{"issue": "S3 bucket is public", "severity": "HIGH"}]\n'
        "Let me know if you would like remediated HCL."
    )
    assert extract_json(text) == ONE_FINDING


def test_prose_around_a_fenced_block() -> None:
    text = (
        "Here are the findings:\n"
        '```json\n[{"issue": "S3 bucket is public", "severity": "HIGH"}]\n```\n'
        "That is everything."
    )
    assert extract_json(text) == ONE_FINDING


def test_first_fenced_block_wins() -> None:
    """A JSON block followed by a code block must yield the JSON, not a merge of both."""
    text = (
        '```json\n[{"issue": "public bucket"}]\n```\n\n'
        "And the fix:\n```hcl\nresource \"aws_s3_bucket\" \"b\" { acl = \"private\" }\n```"
    )
    assert extract_json(text) == [{"issue": "public bucket"}]


def test_trailing_comma_before_closing_bracket() -> None:
    assert extract_json('[{"issue": "a"}, {"issue": "b"},]') == [{"issue": "a"}, {"issue": "b"}]


def test_trailing_comma_before_closing_brace() -> None:
    assert extract_json('{"issue": "a", "severity": "high",}') == {"issue": "a", "severity": "high"}


def test_trailing_commas_in_both_positions() -> None:
    assert extract_json('[{"issue": "a", "severity": "low",},]') == [{"issue": "a", "severity": "low"}]


def test_findings_envelope_is_returned_intact() -> None:
    """extract_json does not unwrap; normalise_findings owns that step."""
    assert extract_json('{"findings": [{"issue": "a"}]}') == {"findings": [{"issue": "a"}]}


def test_single_bare_object_not_a_list() -> None:
    parsed = extract_json('{"issue": "S3 bucket is public", "severity": "HIGH"}')
    assert isinstance(parsed, dict)
    assert parsed["issue"] == "S3 bucket is public"


def test_python_dict_style_single_quotes() -> None:
    """The ast.literal_eval stage: models sometimes echo a Python repr, not JSON."""
    parsed = extract_json("[{'issue': 'S3 bucket is public', 'severity': 'HIGH'}]")
    assert parsed == ONE_FINDING


def test_python_literals_true_false_none() -> None:
    """`True`/`None` are not JSON tokens; only the literal_eval stage handles them."""
    parsed = extract_json("[{'issue': 'a', 'fixed': True, 'line': None}]")
    assert parsed == [{"issue": "a", "fixed": True, "line": None}]


def test_single_quotes_inside_a_fence_with_trailing_comma() -> None:
    """All three fallback stages compounded, which is how they actually show up."""
    text = "```json\n[{'issue': 'a', 'severity': 'HIGH',},]\n```"
    assert extract_json(text) == [{"issue": "a", "severity": "HIGH"}]


def test_nested_structures_survive() -> None:
    text = '{"findings": [{"issue": "a", "meta": {"lines": [1, 2, 3]}}]}'
    assert extract_json(text)["findings"][0]["meta"]["lines"] == [1, 2, 3]


def test_leading_whitespace_and_newlines() -> None:
    assert extract_json('\n\n   [{"issue": "a"}]  \n') == [{"issue": "a"}]


# ---------------------------------------------------------------------------
# extract_json — unrecoverable shapes MUST raise, never return a sentinel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("", id="empty-string"),
        pytest.param("   \n\t  ", id="whitespace-only"),
        pytest.param(None, id="none"),
        pytest.param("I'm sorry, I can't help with that.", id="refusal-prose"),
        pytest.param("No security issues were found.", id="prose-no-json"),
        pytest.param("```json\n\n```", id="empty-fence"),
        pytest.param('{"issue": "a"', id="truncated-object"),
        pytest.param('[{"issue": "a"', id="truncated-array"),
        pytest.param("{not: valid, json", id="garbage-braces"),
    ],
)
def test_unparseable_input_raises_value_error(bad: object) -> None:
    """The whole point of the module: failure is an exception, not a value.

    Regression for `{"raw_output": ...}`, which callers happily treated as a finding list.
    """
    with pytest.raises(ValueError):
        extract_json(bad)  # type: ignore[arg-type]


def test_failure_messages_are_distinguishable() -> None:
    """Empty input and unparseable input are different operator problems."""
    with pytest.raises(ValueError, match="no text to parse"):
        extract_json(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="empty response"):
        extract_json("")
    with pytest.raises(ValueError, match="could not parse"):
        extract_json("definitely not json")


# ---------------------------------------------------------------------------
# strip_code_fences
# ---------------------------------------------------------------------------

TERRAFORM_TAGS = ("hcl", "terraform", "tf")
DOCKERFILE_TAGS = ("dockerfile", "docker")

HCL_BODY = 'resource "aws_s3_bucket" "b" {\n  bucket = "mybucket"\n  acl    = "private"\n}'
DOCKER_BODY = "FROM alpine:3.19\nRUN adduser -D app\nUSER app"


@pytest.mark.parametrize(
    ("tag", "body", "tags"),
    [
        pytest.param("hcl", HCL_BODY, TERRAFORM_TAGS, id="hcl"),
        pytest.param("terraform", HCL_BODY, TERRAFORM_TAGS, id="terraform"),
        pytest.param("tf", HCL_BODY, TERRAFORM_TAGS, id="tf"),
        pytest.param("dockerfile", DOCKER_BODY, DOCKERFILE_TAGS, id="dockerfile"),
        pytest.param("docker", DOCKER_BODY, DOCKERFILE_TAGS, id="docker"),
        pytest.param("json", '{"a": 1}', (), id="json"),
        pytest.param("", HCL_BODY, TERRAFORM_TAGS, id="bare-fence"),
        # The bug that motivated the `tags` parameter: main.py stripped only ```hcl,
        # ```terraform and bare ```, so a Dockerfile answer leaked its fence into the file
        # that was then handed to a scanner.
        pytest.param("dockerfile", DOCKER_BODY, TERRAFORM_TAGS, id="dockerfile-tag-wrong-tags"),
        pytest.param("Dockerfile", DOCKER_BODY, DOCKERFILE_TAGS, id="capitalised-tag"),
    ],
)
def test_fenced_code_is_unwrapped(tag: str, body: str, tags: tuple[str, ...]) -> None:
    out = strip_code_fences(f"```{tag}\n{body}\n```", tags)
    assert out == body
    assert "```" not in out


def test_unfenced_text_is_returned_unchanged() -> None:
    assert strip_code_fences(HCL_BODY, TERRAFORM_TAGS) == HCL_BODY


def test_unfenced_text_keeps_internal_formatting() -> None:
    body = "FROM alpine\n\n# a blank line above must survive\nUSER app"
    assert strip_code_fences(body, DOCKERFILE_TAGS) == body


def test_surrounding_whitespace_is_trimmed() -> None:
    assert strip_code_fences(f"\n\n```hcl\n{HCL_BODY}\n```\n\n", TERRAFORM_TAGS) == HCL_BODY


def test_single_line_fence_without_newlines() -> None:
    out = strip_code_fences("```hcl resource {} ```", TERRAFORM_TAGS)
    assert "```" not in out
    assert "resource {}" in out


def test_no_backticks_survive_any_shape() -> None:
    """Backticks are HCL/Dockerfile syntax errors; a scanner parse error used to read as a pass."""
    shapes = [
        f"```hcl\n{HCL_BODY}\n```",
        f"```\n{HCL_BODY}\n```",
        f"```terraform\n{HCL_BODY}```",
        f"Here you go:\n```hcl\n{HCL_BODY}\n```\nDone.",
        f"```json\n{HCL_BODY}\n```",
    ]
    for shape in shapes:
        assert "`" not in strip_code_fences(shape, TERRAFORM_TAGS), shape


def test_empty_input_is_empty_output() -> None:
    assert strip_code_fences("", TERRAFORM_TAGS) == ""
    assert strip_code_fences("   \n  ", TERRAFORM_TAGS) == ""


def test_default_tags_still_handle_json_and_bare_fences() -> None:
    """Callers that pass no tags (the JSON path) must still get a clean unwrap."""
    assert strip_code_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert strip_code_fences('```\n{"a": 1}\n```') == '{"a": 1}'


# ---------------------------------------------------------------------------
# normalise_findings
# ---------------------------------------------------------------------------

EXPECTED_KEYS = {"issue", "severity", "resource", "recommendation"}


def test_every_output_row_has_exactly_the_four_contract_keys() -> None:
    rows = normalise_findings([{"anything": "at all"}, {"issue": "x"}])
    assert all(set(row) == EXPECTED_KEYS for row in rows)


def test_title_aliases_to_issue() -> None:
    assert normalise_findings([{"title": "Public bucket"}])[0]["issue"] == "Public bucket"


def test_description_aliases_to_issue() -> None:
    assert normalise_findings([{"description": "Public bucket"}])[0]["issue"] == "Public bucket"


def test_remediation_aliases_to_recommendation() -> None:
    row = normalise_findings([{"remediation": "Set acl = private"}])[0]
    assert row["recommendation"] == "Set acl = private"


def test_canonical_key_wins_over_alias() -> None:
    row = normalise_findings(
        [
            {
                "issue": "canonical",
                "title": "alias",
                "description": "alias",
                "recommendation": "canonical",
                "remediation": "alias",
            }
        ]
    )[0]
    assert row["issue"] == "canonical"
    assert row["recommendation"] == "canonical"


def test_keys_are_matched_case_insensitively() -> None:
    """Models capitalise keys about as often as not; Trivy-shaped JSON always does."""
    row = normalise_findings(
        [{"Title": "Public bucket", "Severity": "HIGH", "Resource": "aws_s3_bucket.b", "Remediation": "fix it"}]
    )[0]
    assert row == {
        "issue": "Public bucket",
        "severity": "high",
        "resource": "aws_s3_bucket.b",
        "recommendation": "fix it",
    }


@pytest.mark.parametrize("raw", ["HIGH", "High", "hIgH", " high "])
def test_severity_is_lowercased_and_trimmed(raw: str) -> None:
    assert normalise_findings([{"severity": raw}])[0]["severity"] == "high"


def test_missing_severity_defaults_to_unknown() -> None:
    assert normalise_findings([{"issue": "x"}])[0]["severity"] == "unknown"


def test_empty_severity_defaults_to_unknown() -> None:
    assert normalise_findings([{"issue": "x", "severity": ""}])[0]["severity"] == "unknown"


def test_missing_string_fields_default_to_empty_string() -> None:
    row = normalise_findings([{"severity": "low"}])[0]
    assert row["issue"] == ""
    assert row["resource"] == ""
    assert row["recommendation"] == ""


def test_values_are_stringified_not_dropped() -> None:
    """A model returning a number or list must not blow up the pipeline."""
    row = normalise_findings([{"issue": 42, "resource": ["aws_s3_bucket.b"]}])[0]
    assert row["issue"] == "42"
    assert row["resource"] == "['aws_s3_bucket.b']"


def test_whitespace_around_values_is_stripped() -> None:
    row = normalise_findings([{"issue": "  padded  ", "resource": "\n aws_s3_bucket.b \t"}])[0]
    assert row["issue"] == "padded"
    assert row["resource"] == "aws_s3_bucket.b"


@pytest.mark.parametrize(
    "junk",
    [
        pytest.param("a bare string", id="str"),
        pytest.param(42, id="int"),
        pytest.param(None, id="none"),
        pytest.param(["nested", "list"], id="list"),
    ],
)
def test_non_dict_list_items_are_skipped(junk: object) -> None:
    rows = normalise_findings([{"issue": "real"}, junk, {"issue": "also real"}])
    assert [r["issue"] for r in rows] == ["real", "also real"]


def test_list_of_only_junk_yields_empty_list() -> None:
    assert normalise_findings(["junk", None, 7]) == []


def test_empty_list_yields_empty_list() -> None:
    assert normalise_findings([]) == []


@pytest.mark.parametrize("envelope_key", ["findings", "issues", "vulnerabilities", "results"])
def test_envelopes_are_unwrapped(envelope_key: str) -> None:
    rows = normalise_findings({envelope_key: [{"issue": "a"}, {"issue": "b"}]})
    assert [r["issue"] for r in rows] == ["a", "b"]


def test_single_bare_object_is_wrapped_into_a_one_row_list() -> None:
    rows = normalise_findings({"issue": "only one", "severity": "MEDIUM"})
    assert len(rows) == 1
    assert rows[0]["issue"] == "only one"
    assert rows[0]["severity"] == "medium"


@pytest.mark.parametrize("junk", ["a string", 42, None, True])
def test_scalar_input_raises_rather_than_returning_empty(junk: object) -> None:
    """Empty-list-on-garbage is the fail-open shape this package exists to remove."""
    with pytest.raises(ValueError, match="expected a list of findings"):
        normalise_findings(junk)


# ---------------------------------------------------------------------------
# The two functions together, on a realistically messy response
# ---------------------------------------------------------------------------


def test_end_to_end_on_a_messy_model_response() -> None:
    response = (
        "I analysed the Terraform file. Here is what I found:\n\n"
        "```json\n"
        "{\n"
        '  "findings": [\n'
        '    {"Title": "S3 bucket allows public READ", "Severity": "CRITICAL",\n'
        '     "Resource": "aws_s3_bucket.example", "Remediation": "Set acl to private",},\n'
        '    {"description": "No versioning", "resource": "aws_s3_bucket.example"},\n'
        "  ]\n"
        "}\n"
        "```\n\n"
        "Want me to produce the remediated HCL?"
    )
    rows = normalise_findings(extract_json(response))
    assert len(rows) == 2
    assert rows[0] == {
        "issue": "S3 bucket allows public READ",
        "severity": "critical",
        "resource": "aws_s3_bucket.example",
        "recommendation": "Set acl to private",
    }
    assert rows[1]["issue"] == "No versioning"
    assert rows[1]["severity"] == "unknown"
