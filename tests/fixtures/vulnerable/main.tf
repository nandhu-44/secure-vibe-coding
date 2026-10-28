resource "aws_s3_bucket_acl" "b" {
  acl = "public-read" # expect: SV-IAC-001
}
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"] # expect: SV-IAC-002
}
resource "aws_db_instance" "db" {
  publicly_accessible = true # expect: SV-IAC-001
  storage_encrypted   = false # expect: SV-IAC-004
}
