
resource "null_resource" "create-endpoint" {
  provisioner "local-exec" {
    command = "aws2 --version"
  }
}