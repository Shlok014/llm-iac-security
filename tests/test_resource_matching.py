"""Resource identity must not be weakened by matching a shared Terraform type."""

from eval.matching import terraform_resource_matches


def test_two_fully_named_resources_do_not_match_by_type_alone() -> None:
    assert not terraform_resource_matches("aws_s3_bucket.private", "aws_s3_bucket.public")


def test_module_prefixed_resource_matches_unprefixed_address() -> None:
    assert terraform_resource_matches(
        "module.site.aws_s3_bucket.public", "aws_s3_bucket.public"
    )
    assert not terraform_resource_matches(
        "module.site.aws_s3_bucket.private", "aws_s3_bucket.public"
    )


def test_two_distinct_module_paths_do_not_collapse_to_same_resource() -> None:
    assert not terraform_resource_matches(
        "module.site.aws_s3_bucket.public", "module.backup.aws_s3_bucket.public"
    )


def test_data_source_does_not_match_managed_resource_at_same_address() -> None:
    assert not terraform_resource_matches("data.aws_ami.ubuntu", "aws_ami.ubuntu")


def test_dotted_variable_and_var_addresses_are_the_same_object() -> None:
    assert terraform_resource_matches("variable.api_key", "var.api_key")


def test_quoted_and_bare_spellings_remain_supported() -> None:
    assert terraform_resource_matches('resource "aws_s3_bucket" "public"', "aws_s3_bucket.public")
    assert terraform_resource_matches("public", "aws_s3_bucket.public")
