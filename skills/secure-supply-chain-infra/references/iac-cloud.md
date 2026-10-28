# Cloud & IaC secure defaults

## AWS (Terraform)
```hcl
resource "aws_s3_bucket" "data" { bucket = var.bucket_name }
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted = true
  deletion_protection = true
  iam_database_authentication_enabled = true
  backup_retention_period = 7
  manage_master_user_password = true  # Secrets Manager-managed
}
resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "required"  # IMDSv2
  }
}
```
IAM: scope `Action` and `Resource`, and add `Condition`s (`aws:SourceArn`, `aws:PrincipalOrgID`). Use roles for workloads and Identity Center for humans.

## GCP
Uniform bucket-level access plus public access prevention. No `allUsers`/`allAuthenticatedUsers` bindings. Workload Identity instead of SA keys. Cloud SQL private IP plus `require_ssl`.

## Azure
Storage `allow_blob_public_access = false`, `min_tls_version = "TLS1_2"`. Managed identities. Key Vault with RBAC. NSGs without `*` inbound.

## Serverless
Least-privilege function roles. Function URLs with auth (`AWS_IAM`), not `NONE`, unless public by design and rate-limited. Secrets come from the secret manager, not plaintext env in the template.

## State & secrets
Remote state backend (S3 + DynamoDB lock / GCS / Terraform Cloud) with encryption. Mark outputs `sensitive = true`. Never commit `.tfstate`, `.tfvars` with secrets, or `*.auto.tfvars` containing credentials.

## Scanners
Checkov, Trivy (`trivy config .`), KICS, tfsec, cfn-nag, Prowler (runtime posture).
