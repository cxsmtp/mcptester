# KICS Terraform misconfigurations (AWS). Intentionally insecure.

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                     # hardcoded credentials
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# S3 bucket: public, unencrypted, no logging, no versioning
resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl    = "public-read-write"          # KICS: public bucket
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false       # KICS: public access not blocked
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Security group open to the world
resource "aws_security_group" "open" {
  name = "wide-open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]         # KICS: all ports open to internet
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]         # KICS: SSH open to world
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS: public, unencrypted, weak creds
resource "aws_db_instance" "db" {
  identifier          = "prod-db"
  engine              = "mysql"
  instance_class      = "db.t2.micro"
  username            = "admin"
  password            = "admin123"        # weak/hardcoded password
  publicly_accessible = true              # KICS: DB public
  storage_encrypted   = false             # KICS: no encryption at rest
  skip_final_snapshot = true
}

# Unencrypted, non-versioned EBS
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false               # KICS: unencrypted volume
}

# IAM policy allowing everything
resource "aws_iam_policy" "admin" {
  name = "allow-all"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"                      # KICS: wildcard action
      Resource = "*"                      # KICS: wildcard resource
    }]
  })
}
