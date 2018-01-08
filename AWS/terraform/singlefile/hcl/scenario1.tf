provider "aws" {
 region = "${var.aws_region}"
 token  = "${var.aws_token}"
 access_key = "${var.aws_access_key}"
 secret_key = "${var.aws_secret_key}"
}

variable "aws_region" {
  description = "AWS region to launch servers."
  default     = "us-east-1"
}

variable "aws_token" {
  description = "AWS STS security token."
}

variable "aws_access_key" {
  description = "AWS STS access key."
}

variable "aws_secret_key" {
  description = "AWS STS secret key."
}

variable "vpc_name_tag" {
  description = "Name of the Virtual Private Cloud (VPC) this resource is going to be deployed into"
}

variable "subnet_cidr" {
  description = "Subnet cidr"
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

variable "public_ssh_key_name" {
  description = "Name of the public SSH key used to connect to the virtual guest"
}

variable "public_ssh_key" {
  description = "Public SSH key used to connect to the virtual guest"
}

variable "security_group_id" {
  description = "security_group"
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

resource "aws_instance" "orpheus_ubuntu_micro" {
  instance_type = "t2.micro"
  ami = "${lookup(var.aws_amis, var.aws_region)}"
  subnet_id = "${data.aws_subnet.selected.id}"
  key_name = "${aws_key_pair.orpheus_public_key.id}"
  vpc_security_group_ids = "${data.aws_security_group.selected.id}"
}
