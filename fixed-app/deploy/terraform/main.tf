# Hardened Terraform. No hardcoded creds, private + encrypted resources, least privilege.

provider "aws" {
  region = "us-east-1"
  # Credentials come from the environment / instance role, never hardcoded.
}

variable "db_password" {
  type      = string
  sensitive = true # supplied via TF_VAR_db_password from a secret manager
}

resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

# Security group scoped to the VPC and a single port.
resource "aws_security_group" "app" {
  name = "app-scoped"
  ingress {
    description = "app port from within VPC"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  identifier                  = "prod-db"
  engine                      = "mysql"
  instance_class              = "db.t3.micro"
  username                    = "admin"
  password                    = var.db_password
  publicly_accessible         = false
  storage_encrypted           = true
  iam_database_authentication_enabled = true
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "prod-db-final"
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

# Scoped IAM policy — specific actions on specific resources only.
resource "aws_iam_policy" "app" {
  name = "app-read-bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.data.arn}/*"
    }]
  })
}
