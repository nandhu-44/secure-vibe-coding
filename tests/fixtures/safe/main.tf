resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls   = true
  block_public_policy = true
}
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
