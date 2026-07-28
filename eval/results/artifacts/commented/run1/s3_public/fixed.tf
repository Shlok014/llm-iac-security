resource "aws_s3_bucket" "example" {
  bucket = "mybucket"
  acl    = "private"
}