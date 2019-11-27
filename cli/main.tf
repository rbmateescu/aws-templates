
resource "null_resource" "create-endpoint" {
  provisioner "local-exec" {
    command = "source /home/terraform/.bashrc && aws --version "
  }
}