output "cascon_ubuntu_ip" {
  value = "${aws_instance.ubuntu_cascon.address}"
}