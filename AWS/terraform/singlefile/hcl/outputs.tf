output "public_ipv4" {
  value = "${aws_instance.ubuntu_cascon.*.public_ip}"
}