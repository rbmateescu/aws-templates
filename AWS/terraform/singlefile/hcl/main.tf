provider "aws" {
}

data "aws_vpc" "selected" {
  state = "available"
  filter {
    name = "tag:Name"
    values = ["${var.vpc_name_tag}"]
  }
}

data "aws_subnet" "selected" {
  state        = "available"
  vpc_id       = "${data.aws_vpc.selected.id}"
  cidr_block   = "${var.subnet_cidr}"

}

data "aws_security_group" "selected" {
  id = "${var.security_group_id}"
}

# Ubuntu 14.04.01 as documented at https://cloud-images.ubuntu.com/releases/14.04/14.04.1/
variable "aws_amis" {
  default = {
    us-west-1 = "ami-0db4b748"
    us-east-1 = "ami-b227efda"
  }
}

resource "aws_key_pair" "orpheus_public_key" {
    key_name = "${var.public_ssh_key_name}"
    public_key = "${var.public_ssh_key}"
}

resource "aws_instance" "ubuntu_micro" {
  instance_type = "t2.micro"
  ami = "${lookup(var.aws_amis, var.aws_region)}"
  subnet_id = "${data.aws_subnet.selected.id}"
  key_name = "${aws_key_pair.orpheus_public_key.id}"
  vpc_security_group_ids = ["${data.aws_security_group.selected.id}"]
}
