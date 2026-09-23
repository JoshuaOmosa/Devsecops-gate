config {
  module          = false
  force           = false
  format          = "json"
  required_version = ">= 1.0"
}

plugin "aws" {
  enabled = true
  version = "0.24.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "terraform_unused_required_providers" { enabled = true }
rule "terraform_unused_declarations"        { enabled = true }
rule "terraform_documented_outputs"         { enabled = true }
rule "terraform_documented_variables"       { enabled = true }
rule "terraform_typed_variables"            { enabled = true }
rule "aws_instance_metadata_options"        { enabled = true }
rule "aws_s3_bucket_server_side_encryption_enabled" { enabled = true }
rule "aws_s3_bucket_versioning_enabled"     { enabled = true }
rule "aws_security_group_rule_has_description" { enabled = true }
rule "aws_iam_policy_no_statements_with_admin_access" { enabled = true }
