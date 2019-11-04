variable "aws_region" {
  description = "AWS region to launch servers."
  default     = "us-east-1"
}

variable "flavor" {
  description = "VM flavor."
  default     = "t2.nano"
}

variable "vpc_name_tag" {
  description = "Name of the Virtual Private Cloud (VPC) this resource is going to be deployed into"
  default = "CAMVPC"
}

variable "subnet_cidr" {
  description = "Subnet cidr"
  default = "10.0.0.0/24"
}

variable "public_ssh_key_name" {
  description = "Name of the public SSH key used to connect to the virtual guest"
  default = "radu_test_key"
}

variable "public_ssh_key" {
  description = "Public SSH key used to connect to the virtual guest"
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHZ4niF/AJ/9y+/NCqXAnr+rWYEg9kv1/4uOc0PEQU+HBelUNM7RxthH5VGYPPEm9KuVBhwlO7VQ1Kpo2SrkdjX16YtM1Ozao4DyU7jJNh3PpvzjzPhqWf6lKo1AQ5EX4HBkIGe+G9zc17p6op8ZUniWNMux9zv3jf2F1zuMt/gbLGUmzUOUWU5lIwqEZPfToeJJhdQgpqFTYqfxhvKSkj0HTGOz8UbEkP37TIqx0pjohZjoIgbZDIz1YkfX52MaSEiHg7WdBAZiaJxFa1mAAwL5vZNg80/lSsKa96ga+INw1b0NHeEVVVWWBxy4Vo9n/1NPaYu1A/dYFoF5huEKep developer@radu-cascon"
}

variable "security_group_id" {
  description = "security_group"
  default = "sg-3cbeec40"
}
