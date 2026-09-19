resource "aws_security_group_rule" "open" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}

resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}
