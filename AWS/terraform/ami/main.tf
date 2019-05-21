##############################################################
# input variables ...
##############################################################

## removing aws api keys, as now on will use cloud connections in cam,
## and switch role/assume role functionality: 
## https://github.ibm.com/CMS/cms-opaas-api/issues/3712

#variable "aws_access_key" { 
#  type = "string"
#  description = "AWS access key"
#}

#variable "aws_secret_key" {
#  type = "string"  
#  description = "AWS secret key"
#}

#variable "aws_session_token" {
#  type = "string"  
#  description = "AWS session token"
#  default = ""
#}

#variable "aws_region" {
#  type = "string"  
#  description = "AWS Region Name"
#  default = "us-east-1"
#}

variable "aws_ami_owner_id" {
    type = "string"  
    description = "AWS AMI Owner ID"
    default = "309956199498"
}

variable "aws_vpc_name" {
    type = "string"
    description = "AWS VPC Name/id"
}

# multiple Security Groups can be added with space delimited string
variable "aws_sg_name" {
    description = "AWS Security Group Name"
    type = "map"
}

variable "instance_domain" {
    description = "customer's domain name or dns suffix"
    default = "cam.ibm.com"
}

variable "ibm_dns_suffix" {
    description = "ibm's domain name for managed apps"
    default = "imzcloud.ibmammsap.local"
}

variable "aws_ami_filter_name" {
    type = "string"
    description = "Operating system image id / template that should be used when creating the virtual image"
}

variable "aws_ami_virtualization_type" {
    type = "string"
    description = "aws virtulization type  hvm or paravirtual"
    default = "hvm"
}

variable "hostname" {
    type = "string"
    description = "Short hostname of virtual machine"
}

variable "aws_instance_type" {
    type = "string"
    description = "AWS EC2 Instance type"
    default = "t2.micro"
}

variable "sshKey" {
    type = "string"
    description = "public key for ssh auth"
}

variable "aws_subnet_name" {
    type = "map"  
    description = "AWS Subnet Name/id"
}

variable "root_block_device_volume_type" {
    type = "string"
    description = "AWS Root Block Device Volume Type"
    default = "gp2"
}

variable "root_block_device_volume_size" {
    type = "string"
    description = "AWS Root Block Device Volume Size"
    default = "10"
}

variable "root_block_device_delete_on_termination" {
    type = "string"
    description = "AWS Root Block Device Delete on Termination"
    default = "true"
}

variable "network_name" {
    type = "map"  
    description = "network internface name/ID"
}

variable "admin_user" {
    description = "admin user name"
}

variable "admin_password" {
    description = "password for admin user"
}

variable "imz_ssh_key" {
	description = "Public key for cam "
	default = "somefakekey"
}

variable "accessKeyFile" {
    description = "Private key file for cam"
    default="/home/terraform/.ssh/camaccess_rsa"
}

variable "dns_ips" {
	description = "space delimited IPs to use as dns/nameservers"
	default = "172.30.0.156 172.30.0.146"
}

variable "aws_iam_role" {
	description = "AWS IAM Role"
	default = "IBM_Instance_GenericRole"
}

variable "workloadType" {
	default = "AWS-BASE-OS"
}

variable "swap_volume_size" {
    description = "size of swap volume"
    default = "2"
}

variable "swap_device_path" {
    description = "device path for swap i.e. /dev/xvdb"
    default = "/dev/xvdb"
}

variable "swap_device_type" {
    description = "ebs volume type for swap disk"
    default = "gp2"
}

variable "swap_device_encrypted" {
    description = "Enable encryption on swap device (true / false)"
    default = "false"
}

variable "role_arn" {
    description = "Amazone Resource Number of the role to assume"
}

variable "autorecovery" {
    description = "enables autorecovery action using cloudwatch for aws instance, 1=enable ; 0=disable "
    default = "1"
}

variable "monitoring" {
    description = "If true, the launched EC2 instance will have detailed monitoring enabled."
    default = false
}

variable "ibm_network_index" {
	description = "Index number for admin network using which to connection for further config."
}

variable "customer_network_index" {
	description = "Index number for customer network, this network will get default gateway."
}

variable "static_routes" {
	description = "static routes for connecting back to ibm admin network, comma seperated"
}

##############################################################
# Define the aws provider
##############################################################

## removing access, secret keys and region as now on will use cloud connections in cam,
## and switch role/assume role functionality: 
## https://github.ibm.com/CMS/cms-opaas-api/issues/3712

provider "aws" {
#   region = "${var.aws_region}"
#   token  = "${var.aws_session_token}"
#   access_key = "${var.aws_access_key}"
#   secret_key = "${var.aws_secret_key}"
    assume_role {
        role_arn = "${var.role_arn}"
    }
    version = "2.10"
}

provider "template" {
    version = "2.1"
}

provider "null" {
    version = "2.0"
}


##############################################################
# data
##############################################################
data "aws_vpc" "selected_vpc" {
    id = "${var.aws_vpc_name}"
}

# grab aws region from provider to use for cloudWatch resource.
data "aws_region" "current" {}

data "aws_ami" "instance_ami" {
    most_recent = true
    filter {
        name = "name"
        values = ["${var.aws_ami_filter_name}*"]
    }
    filter {
        name   = "virtualization-type"
        values = ["${var.aws_ami_virtualization_type}"]
    }
    owners = ["${var.aws_ami_owner_id}"]
}

data "aws_subnet" "instance_selected_subnet" {
    count = "${length(var.aws_subnet_name)}"
    id = "${lookup(var.aws_subnet_name, count.index)}"
}

#using data.aws_network_interface to get mac address of eni
data "aws_network_interface" "eni" {
    count = "${length(var.aws_subnet_name)}"
    id = "${aws_network_interface.eni.*.id[count.index]}"
}

data "template_cloudinit_config" "instance_init"  {
    part {
        content_type = "text/cloud-config"
        content = <<EOF
#setting hostname to shortname as 3x is doing for consistency  
hostname: ${var.hostname}
fqdn: ${var.hostname}.${var.instance_domain}
manage_etc_hosts: false
ssh_authorized_keys:
  - ${var.imz_ssh_key}
  - ${var.sshKey}

# enable root: https://github.ibm.com/CMS/cms-opaas-api/issues/3586
disable_root: false

## if we uncomment above two lines with right cam pubic key, all below lines can be removed.
## as then will not need password based auth for cam to connect to instance.
ssh_pwauth: True
chpasswd:
  list:  |
    ${var.admin_user}:${var.admin_password}
  expire: False

## install lvm if not installed, as we need it for swap creation.
## nfs-utils for chef installation
packages:
 - lvm2
 - nfs-utils
## to avoid unplanned upgrades during first boot.
## and also avoids longer running cloud-init jobs. 
package_upgrade: false
EOF
    }

    part {
        content_type = "text/x-shellscript"
        content = <<EOF
#!/bin/bash
# log everything to log file
set -x
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>/var/log/userdata-staticroute-log.out 2>&1

#set dns in  resolve.conf
echo search ${var.instance_domain} > /etc/resolv.conf
for dns in $(echo ${var.dns_ips})
do
    echo nameserver $dns >> /etc/resolv.conf
done

# map to hold mac to eth device names
declare -A MAC_MAP

#map to hold eth device name to mac
declare -A ETH_MAP

for NET_DEV in "/sys/class/net/"*
do
    if [ -f "$NET_DEV" ] || [ "$${NET_DEV##*/}" != "lo" ]
    then
        NETDEV=$${NET_DEV##*/}
        MAC=$(cat $${NET_DEV}/address)
        MAC_MAP[$MAC]="$NETDEV"
        ETH_MAP[$NETDEV]="$MAC"
    fi
done

## function to convert cidr to mask
cdr2mask (){
   # Number of args to shift, 255..255, first non-255 byte, zeroes
   set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 << (8 - ($1 % 8))) & 255 )) 0 0 0
   [ $1 -gt 1 ] && shift $1 || shift
   echo $${1-0}.$${2-0}.$${3-0}.$${4-0}
}

## function to get gateway for network
get_gateway_ip () {
    local DEV=$1
    local SUBNET=$2
    local ADMIN_GATEWAY=""
    ADM_NETWORK=$${SUBNET%/*}
    ADM_CIDR=$${SUBNET##*/}
    IP_1=$(echo $ADM_NETWORK | cut -f1 -d".")
    IP_2=$(echo $ADM_NETWORK | cut -f2 -d".")
    IP_3=$(echo $ADM_NETWORK | cut -f3 -d".")

    if [ "$ADM_CIDR" -ge "24" ]
    then
        NET_MATCH=$IP_1.$IP_2.$IP_3.
    elif [ "$ADM_CIDR" -ge "16" ]
    then
        NET_MATCH=$IP_1.$IP_2.
    elif [ "$ADM_CIDR" -ge "8" ]
    then
        NET_MATCH=$IP_1.
    fi

    ADMIN_GATEWAY="$(ip route | grep -F $NET_MATCH | grep $DEV | grep default | awk '{print $3}')"
    if [[ ! $ADMIN_GATEWAY =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
    then
        # if didn't got admin gateway with dhcp, then add 1 to network address and assume it's gateway.
        NET_P1=$${ADM_NETWORK%.*}
        NET_P2=$(($${ADM_NETWORK#*.*.*.} + 1 ))
        ADMIN_GATEWAY=$NET_P1.$NET_P2
    fi
    echo $ADMIN_GATEWAY
}

ALL_MAC="${jsonencode(data.aws_network_interface.eni.*.mac_address)}"

declare -a MAC_ARR=($(echo $ALL_MAC | tr -d [ | tr -d ] | tr , ' '))
NET_COUNT=${length(var.aws_subnet_name) - 1}

#if only one NIC then nothing much to do with static routes 
if [ "$NET_COUNT" -eq "0" ]
then
	echo only one network interface found .. skipping static route config.
	exit 0
fi

# disable cloud-init for network to keep cloud-init from alterning static config.
for f in /etc/cloud/cloud.cfg.d/*disable*network*cfg
do
	 if [ -e "$f" ]
	 then
		echo $f already exists to disable cloud-init for network.
		break
	 else
		echo "network:" > /etc/cloud/cloud.cfg.d/99-disable-network.cfg
		echo "  config: disabled" >> /etc/cloud/cloud.cfg.d/99-disable-network.cfg
	 fi
done

i=0
while [ "$i" -le "$NET_COUNT" ]
do
    IF_DEV=eth$i
    IPADDR=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$${MAC_ARR[$i]}/local-ipv4s)
    #validate and wait if ip not valid so os can settledown 
    while [[ ! $IPADDR =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
    do
        # got bad ip  
        sleep 2
        IPADDR=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$${MAC_ARR[$i]}/local-ipv4s)
    done

    SUBNET=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$${MAC_ARR[$i]}/subnet-ipv4-cidr-block)
    NET_GATEWAY="" 
	
    ##  lets check if device names are as expected or not
    MAC=$${MAC_ARR[$i]}
    if [ "$MAC" != "$${ETH_MAP[$IF_DEV]}" ]
    then
		CURRENT_DEV_NAME=$${MAC_MAP[$MAC]}
		NEW_DEV_NAME=$IF_DEV
		if [ -e /sys/class/net/$NEW_DEV_NAME ]
		then
			# rename existing target to temp name
			ip link set $NEW_DEV_NAME down
			ip link set $NEW_DEV_NAME name DUP-$NEW_DEV_NAME
			ip link set DUP-$NEW_DEV_NAME  up
			TEMP_MAC=$${ETH_MAP[$NEW_DEV_NAME]}
			MAC_MAP[$TEMP_MAC]=DUP-$NEW_DEV_NAME
			sleep 1
		fi

		# rename net device name to match index
		ip link set $CURRENT_DEV_NAME  down
		ip link set $CURRENT_DEV_NAME name $NEW_DEV_NAME
		ip link set $NEW_DEV_NAME  up
		sleep 1

		# make change permanent via udev if os still using it
		if [ -f /etc/udev/rules.d/70-persistent-net.rules ]
		then
			sed -i -E "/==\"$MAC\"/s/(.*\sNAME=\")(eth[0-9]\")/\1$NEW_DEV_NAME\"/g" /etc/udev/rules.d/70-persistent-net.rules
		fi
    fi          
 
    ## if redhat/centos/oracle
    if [ -f /etc/sysconfig/network-scripts/ifcfg-eth0 ]
    then
		# set dhcp first to capture gateway ip 
		 dd of=/etc/sysconfig/network-scripts/ifcfg-$IF_DEV << EOT
BOOTPROTO=dhcp
DEVICE=$IF_DEV
HWADDR=$${MAC_ARR[$i]}
TYPE=Ethernet
EOT
		ifdown $IF_DEV
		ifup $IF_DEV
		sleep 1
		#now capture gateway for this network
		NET_GATEWAY=$(get_gateway_ip $IF_DEV $SUBNET)
		
		#create static ifcfg file for networks
		dd of=/etc/sysconfig/network-scripts/ifcfg-$IF_DEV << EOT
BOOTPROTO=none
DEVICE=$IF_DEV
HWADDR=$${MAC_ARR[$i]}
ONBOOT=yes
TYPE=Ethernet
USERCTL=no
NM_CONTROLLED=no
MTU=1500
IPADDR=$IPADDR
PREFIX=$${SUBNET#*/}
EOT
		
        if [ "$i" -eq "${var.customer_network_index}" ]
        then
            #set default gateway to Customer nic device
			echo DEFROUTE=yes >> /etc/sysconfig/network-scripts/ifcfg-$IF_DEV
			if [ -f /etc/sysconfig/network ]
			then
				echo GATEWAYDEV=$IF_DEV >> /etc/sysconfig/network
			fi 
			
			if [ -s /etc/sysconfig/network-scripts/route-$IF_DEV ]
			then
				# default route needs to be first in route file, so using sed
				sed -i "1s/^/default via $NET_GATEWAY dev $IF_DEV \n/" etc/sysconfig/network-scripts/route-$IF_DEV
			else
				#file do not exists or is empty
				echo default via $NET_GATEWAY dev $IF_DEV >> etc/sysconfig/network-scripts/route-$IF_DEV
			fi

			
            #set mtu to 1500 
            sed -i -e 's/^MTU=/#&/' -e '$aMTU=1500' /etc/sysconfig/network-scripts/ifcfg-$IF_DEV
        elif [ "$i" -eq "${var.ibm_network_index}" ]
		then
            ## this is ibm network.
            ADM_INT=$IF_DEV
			IBM_GATEWAY=$NET_GATEWAY
			echo DEFROUTE=no >> /etc/sysconfig/network-scripts/ifcfg-$IF_DEV
		else
			echo DEFROUTE=no >> /etc/sysconfig/network-scripts/ifcfg-$IF_DEV
        fi    
		              
    ## if SUSE    
    elif [ -f /etc/sysconfig/network/ifcfg-eth0 ]
    then
		# create dhcp file to capture gateway
		dd of=/etc/sysconfig/network/ifcfg-$IF_DEV << EOT
STARTMODE="hotplug"
BOOTPROTO="dhcp"
LLADDR="$${MAC_ARR[$i]}"
PERSISTENT_DHCLIENT="1"
EOT
		ifdown $IF_DEV
		ifup $IF_DEV
	    sleep 1
		#now capture gateway for this network
		NET_GATEWAY=$(get_gateway_ip $IF_DEV $SUBNET)
		
		#create static ip ifcfg config.
		NETMASK=$(cdr2mask $${SUBNET#*/})
		dd of=/etc/sysconfig/network/ifcfg-$IF_DEV << EOT
DEVICE=$IF_DEV
LLADDR=$${MAC_ARR[$i]}
BOOTPROTO='static'
IPADDR='$IPADDR'
STARTMODE='auto'
LINK_REQUIRED=no
LNIK_READY_WAIT=5
MTU=1500
NETMASK='$NETMASK'
EOT
                   
		
        if [ "$i" -eq "${var.customer_network_index}" ]
        then
			#set default gateway to Customer nic device
			echo -e "\ndefault    $NET_GATEWAY    -    $IF_DEV" >> /etc/sysconfig/network/routes
            #set mtu to 1500 
            sed -i -e 's/^MTU=/#&/' -e '$aMTU=1500' /etc/sysconfig/network/ifcfg-$IF_DEV
			
        elif [ "$i" -eq "${var.ibm_network_index}" ]
		then
			# this is ibm network.
			IBM_GATEWAY=$NET_GATEWAY
			ADM_INT=$IF_DEV
		fi
            
    # if ubuntu 16  
    elif [ -d /etc/network/interfaces.d ]
    then
         if (( $i == 0 ))
        then
            #set mtu to 1500 
            sed -i '/request /i \default interface-mtu 1500;' /etc/dhcp/dhclient.conf
            sed -i '/request /i \supercede interface-mtu 1500;' /etc/dhcp/dhclient.conf
        else
            dd of=/etc/network/interfaces.d/60-$IF_DEV.cfg << EOT
auto $IF_DEV
iface $IF_DEV inet dhcp
mtu 1500
    hwaddress ether $${MAC_ARR[$i]}
EOT
            ifup $IF_DEV
        fi
    
    # if ubuntu 18
    elif [ -d /etc/netplan ]
    then
        if (( $i == 0 ))
        then
            #set mtu to 1500 
            sed -i '/request /i \default interface-mtu 1500;' /etc/dhcp/dhclient.conf
            sed -i '/request /i \supercede interface-mtu 1500;' /etc/dhcp/dhclient.conf
        else
            dd of=/etc/netplan/60-$IF_DEV.yaml << EOT
network:
    version: 2
    ethernets:
        $IF_DEV:
            dhcp4: true
            match:
                macaddress: $${MAC_ARR[$i]}
            set-name: $IF_DEV
            mtu: 1500
EOT
            netplan apply
        fi
    else
        echo "ERROR : untested OS found !"
        exit 1
    fi
    let i=i+1
done

#set mtu to 1500 using ip cmd , permanent change will be done in above block
ip link list | awk -F: '/eth[0-9]/ {print $2}' | xargs -r -n 1 ip link set mtu 1500 dev

#now set static routes for IBM network.
for ROUTE in ${var.static_routes}
do
    if [ -f /etc/sysconfig/network/ifcfg-eth0 ]
    then
        # S U S E
        echo "$ROUTE    $IBM_GATEWAY   -    $ADM_INT" >> /etc/sysconfig/network/routes
    elif [ -f /etc/sysconfig/network-scripts/ifcfg-eth0 ]
    then
        # RedHat / CentOS / OracleLinux / Fedora
        echo "$ROUTE    via    $IBM_GATEWAY   dev    $ADM_INT" >> /etc/sysconfig/network-scripts/route-$ADM_INT
    else
        echo "ERROR : untested OS found !"
        exit 1
    fi  
done
systemctl stop NetworkManager
systemctl disable NetworkManager
systemctl restart network
EOF
    }

    #script to create swap with lvm
    part {
        content_type = "text/x-shellscript"
        content = <<EOF
#!/bin/bash
if [ -b "/dev/xvdb" ]
then
    DEVICE=/dev/xvdb
else
    if [ -b "/dev/sdb" ]
    then
        DEVICE=/dev/sdb
    else
        if [ -b "/dev/nvme1n1" ]
        then
            DEVICE=/dev/nvme1n1
        else
            DEVICE=NONE
        fi
    fi
fi

if [ "$DEVICE" != "NONE" ]
then
    if type pvcreate 2>/dev/null
    then
        echo "LVM exists so will use lvm for swap"
        pvcreate $DEVICE
        vgcreate system $DEVICE
        lvcreate -n swap -l 100%FREE system
        SWAP_DEVICE=/dev/system/swap
    else
        echo "LVM not found, swap will be on disk"
        SWAP_DEVICE=$DEVICE
    fi

    mkswap $SWAP_DEVICE
    swapon -v $SWAP_DEVICE
    FSUUID=$(blkid -o value -s UUID $SWAP_DEVICE)
    echo "UUID=$FSUUID swap swap defaults 0 0" >> /etc/fstab
    echo "SUCCESS: swap is on"

else
    echo "ERROR: no block device found for swap"
fi

EOF
    }

    #script to fix zypper repos if not initialized.
    part {
        content_type = "text/x-shellscript"
        content = <<EOF
#!/bin/bash
if hash zypper 2>/dev/null
then
    zypper repos -E | grep -e "Warning:\sNo\srepositories\sdefined"
    RESP=$?
    if [ "$RESP" -eq 0 ]
    then
        echo repos not configured ...
        /usr/sbin/registercloudguest --force-new
    fi
fi
EOF
    }   
}


locals {
    #adm_index = "${element(keys(var.aws_subnet_name), index(values(var.aws_subnet_name), var.admin_network))}"
    private_ips = "${flatten(aws_network_interface.eni.*.private_ips)}"
	private_subnets = "${flatten(data.aws_subnet.instance_selected_subnet.*.cidr_block)}"
}

data "null_data_source" "adm_net" {
    inputs = {
		ibm_ip = "${element(local.private_ips, var.ibm_network_index)}"
        customer_ip = "${element(local.private_ips, var.customer_network_index)}"
		ibm_subnet = "${element(local.private_subnets, var.ibm_network_index)}"
        # " this extra doubloe quote is only to keep syntax hylighter work properly on VS code
    }
}


#########################################################
##### Resource 
#########################################################

resource "aws_key_pair" "instance_ssh_key" {
    key_name_prefix = "${var.hostname}"
    public_key = "${var.sshKey}"
}

resource "aws_network_interface" "eni" {
    count = "${length(var.aws_subnet_name)}" 
    subnet_id = "${data.aws_subnet.instance_selected_subnet.*.id[count.index]}"
    security_groups = ["${split(" ", lookup(var.aws_sg_name, count.index))}"]
    # https://github.ibm.com/CMS/cms-opaas-api/issues/4551
    source_dest_check = false
    tags {
        Name = "${var.hostname}-${lookup(var.network_name, count.index)}"
    }
}

resource "aws_instance" "instance" {
    ami = "${data.aws_ami.instance_ami.id}"
    instance_type = "${var.aws_instance_type}"
    iam_instance_profile = "${var.aws_iam_role}"
    key_name = "${aws_key_pair.instance_ssh_key.key_name}"
    monitoring = "${var.monitoring}"
    network_interface {
        network_interface_id = "${aws_network_interface.eni.*.id[0]}"
        device_index = 0
    }

    volume_tags {
        Name = "${var.hostname}-volume"
    }

    tags {
        Name = "${var.hostname}"
    }
    root_block_device {
        volume_type = "${var.root_block_device_volume_type}"
        volume_size = "${var.root_block_device_volume_size}"
        #iops = "${var.instance_root_block_device_iops}"
        delete_on_termination = "${var.root_block_device_delete_on_termination}"
    }

    #swap disk  :: https://github.ibm.com/CMS/cms-opaas-api/issues/2880
    ebs_block_device {
        device_name = "${var.swap_device_path}"
        volume_type = "${var.swap_device_type}"
        volume_size = "${var.swap_volume_size}"
        encrypted = "${var.swap_device_encrypted}"
        delete_on_termination = "true"
    }

    user_data = "${data.template_cloudinit_config.instance_init.rendered}"
}

resource "aws_network_interface_attachment" "instance_eni" {
    count = "${length(var.aws_subnet_name) - 1}" 
    instance_id = "${aws_instance.instance.id}"
    network_interface_id = "${aws_network_interface.eni.*.id[count.index + 1]}"
    device_index = "${count.index +1}"
}  

# autorecovery  :: https://github.ibm.com/CMS/cms-opaas-api/issues/4237
# build the CloudWatch auto-recovery alarm and recovery action
resource "aws_cloudwatch_metric_alarm" "auto_recovery" {
    count = "${var.autorecovery}"
    alarm_name         = "${var.hostname}-instance-autorecovery"
    namespace          = "AWS/EC2"
    evaluation_periods = "3"
    period             = "60"
    alarm_description  = "This metric auto recovers EC2 instances"
    alarm_actions = ["arn:aws:automate:${data.aws_region.current.name}:ec2:recover"]
    statistic           = "Minimum"
    comparison_operator = "GreaterThanThreshold"
    threshold           = "0.0"
    metric_name         = "StatusCheckFailed_System"
    dimensions {
        InstanceId = "${aws_instance.instance.id}"
    }
} 



#########################################################
##### Output
#########################################################
output "instance_public_ip" {
    description = "Public IP address"
    value = "${aws_instance.instance.public_ip}"
}

output "private_ips" {
    description = "Private IPs of instance"
    value = "${data.aws_network_interface.eni.*.private_ips}"
}

output "ibm_ip" {
    value = "${data.null_data_source.adm_net.outputs["ibm_ip"]}"
}

output "ibm_subnet" {
    value = "${data.null_data_source.adm_net.outputs["ibm_subnet"]}"
}

output "customer_ip" {
    value = "${data.null_data_source.adm_net.outputs["customer_ip"]}"
}

output "instance_id" {
    description = "AWS EC2 instance id"
    value = "${aws_instance.instance.id}"
}

output "availability_zone" {
    description = "availability zone"
    value = "${aws_instance.instance.availability_zone}"
}

output "eni_mac_addresses" {
	description = "mac address "
	value = "${data.aws_network_interface.eni.*.mac_address}"
}

output "network_interface_ids" {
	description = "AWS Network Interface ID"
	value = "${data.aws_network_interface.eni.*.id}"
}

#########################################################
#  Wait for cloud-init to finish ..
#  This should keep CAM in loop till cloud-init finishes
#########################################################

resource "null_resource" "wait_for_cloud-init" {
    depends_on = ["aws_network_interface_attachment.instance_eni"]
    connection {
        type       = "ssh"
        user       = "${var.admin_user}"
        private_key  = "${file("${var.accessKeyFile}")}"
        host       = "${data.null_data_source.adm_net.outputs["ibm_ip"]}"
    } 
    
    provisioner "file" {
        content = <<EOF
#!/bin/bash
# log everything to log file
set -x
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>/var/log/wait_for_cloud-init.log 2>&1
echo "$(date): checking if cloud init finished if not will wait .."
cloud-init status --wait >/dev/null
# this while loop not needed,  but just paranoid thinking what is cloud-init wait do not work :)
while ! test -e '/var/lib/cloud/instance/boot-finished'
do
        echo "$(date): still waiting .."
        sleep 3
done
echo "$(date): cloud-init finished ..."
EOF
    destination = "/tmp/waitForCloudInit.sh"
    }
    # Execute the script remotely
    provisioner "remote-exec" {
        inline = [
        "chmod +x /tmp/waitForCloudInit.sh; bash /tmp/waitForCloudInit.sh "
        
        ]
    }    
}


#########################################################
# Start baseos cofiguration. 
# This configures /etc/hosts file.
#########################################################
resource "null_resource" "baseos_config" {
    depends_on = ["null_resource.wait_for_cloud-init"]
    connection {
        type       = "ssh"
        user       = "${var.admin_user}"
        private_key  = "${file("${var.accessKeyFile}")}"
        #password   = "${var.admin_password}" 
        host       = "${data.null_data_source.adm_net.outputs["ibm_ip"]}"
    } 

    
    provisioner "file" {
        content = <<EOF
#!/bin/bash

LOGFILE="/var/log/etchostsupdate.log"
etcHostsFile="/etc/hosts"
etcHostnameFile="/etc/hostname"

echo "Now updating the $etcHostsFile"

ALL_TAGS="${jsonencode(data.aws_network_interface.eni.*.tags)}"
declare -a NET_NAME=($(echo $ALL_TAGS | tr -d [ | tr -d ] | tr -d { | tr -d } | tr , ' '))
ALL_IPS="${jsonencode(data.aws_network_interface.eni.*.private_ips)}"
declare -a IPS=($(echo $ALL_IPS | tr -d [ | tr -d ] | tr , ' '))
NET_COUNT=${length(var.aws_subnet_name) - 1}
i=0
echo "# Added by oPAAS Automation do not remove, retain comment as well"  >> $etcHostsFile 2>&1 || { echo "--- Failed to update the $etcHostsFile file --" | tee -a $LOGFILE; exit 1; }
while [ "$$i" -le "$NET_COUNT" ]
do
    if [[ "$${NET_NAME[$i]}" =~ (ifn|imz) ]]
    then
        echo "$${IPS[$$i]} ${var.hostname}.${var.ibm_dns_suffix}" >> $etcHostsFile 2>&1 || { echo "--- Failed to update the $etcHostsFile file --" | tee -a $LOGFILE; exit 1; }
    else
        echo "$${IPS[$$i]} ${var.hostname}.${var.instance_domain} ${var.hostname}" >> $etcHostsFile 2>&1 || { echo "--- Failed to update the $etcHostsFile file --" | tee -a $LOGFILE; exit 1; }
    fi
    let i=i+1
done

echo "Now updating the /etc/hostname file "
rm /etc/hostname
echo "Recreating the /etc/hostname file"
touch /etc/hostname
echo "${var.hostname}.${var.ibm_dns_suffix}" >> $etcHostnameFile 2>&1 || { echo "--- Failed to update the $etcHostnameFile  --" | tee -a $LOGFILE; exit 1; }

EOF
    destination = "/tmp/etchostsUpdate.sh"
    }
    # Execute the script remotely
    provisioner "remote-exec" {
        inline = [
        "chmod +x /tmp/etchostsUpdate.sh; bash /tmp/etchostsUpdate.sh "
        
        ]
    }    
}

#########################################################
# End baseos configuration
#########################################################


#########################################################
# Start grub configuration for HANA
#########################################################
resource "null_resource" "grub_config" {

    # only run this grub_config if workloadType=SAPHANA_AWS_INSTANCE
    count = "${var.workloadType == "SAPHANA_AWS_INSTANCE" ? 1 : 0 }"
    depends_on = ["null_resource.wait_for_cloud-init"]
    # Specify the ssh connection
    connection {
    type        = "ssh"
    user        = "${var.admin_user}"
    private_key  = "${file("${var.accessKeyFile}")}"  
    #password    = "${var.admin_password}" 
    host        = "${data.null_data_source.adm_net.outputs["ibm_ip"]}"
    }   

    provisioner "file" {
    content = <<EOF
#!/bin/bash

LOGFILE="/etc/default/grub.new"

cp /etc/default/grub /etc/default/grub.backup

echo " # If you change this file, run 'grub2-mkconfig -o /boot/grub2/grub.cfg' afterwards to update /boot/grub2/grub.cfg." >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# Uncomment to set your own custom distributor. If you leave it unset or empty, the default# policy is to determine the value from /etc/os-release " >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_DISTRIBUTOR=" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_DEFAULT=saved" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_HIDDEN_TIMEOUT=0" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_HIDDEN_TIMEOUT_QUIET=true" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_TIMEOUT=8" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"resume=/dev/system/swap splash=silent quiet showopts  numa_balancing=disable intel_idle.max_cstate=1 processor.max_cstate=1 elevator=noop transparent_hugepage=never\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_CMDLINE_LINUX=\"\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# Uncomment to automatically save last booted menu entry in GRUB2 environment" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# variable \`saved_entry\'" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# GRUB_SAVEDEFAULT=\"true\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "#Uncomment to enable BadRAM filtering, modify to suit your needs" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# This works with Linux (no patch required) and with any kernel that obtains" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# the memory map information from GRUB (GNU Mach, kernel of FreeBSD ...)" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# GRUB_BADRAM=\"0x01234567,0xfefefefe,0x89abcdef,0xefefefef\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "#Uncomment to disable graphical terminal (grub-pc only)" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "GRUB_TERMINAL=\"gfxterm\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# The resolution used on graphical terminal" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "#note that you can use only modes which your graphic card supports via VBE" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# you can see them in real GRUB with the command \`vbeinfo\'" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_GFXMODE=\"auto\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# Uncomment if you don't want GRUB to pass \"root=UUID=xxx\" parameter to Linux" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "# GRUB_DISABLE_LINUX_UUID=true" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "#Uncomment to disable generation of recovery mode menu entries" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# GRUB_DISABLE_LINUX_RECOVERY=\"true\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "#Uncomment to get a beep at grub start" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

echo "# GRUB_INIT_TUNE=\"480 440 1\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_BACKGROUND=/boot/grub2/themes/SLE/background.png" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_THEME=/boot/grub2/themes/SLE/theme.txt" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "SUSE_BTRFS_SNAPSHOT_BOOTING=\"true\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_DISABLE_OS_PROBER=\"true\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }
echo "GRUB_ENABLE_CRYPTODISK=\"n\"" >> $LOGFILE 2>&1 || { echo "---Failed to create the grub config file---" | tee -a $LOGFILE; exit 1; }

cp /etc/default/grub.new /etc/default/grub

EOF
	destination = "/tmp/updategrub.sh"

    }

    # Execute the script remotely
    provisioner "remote-exec" {
        inline = [
        "chmod +x /tmp/updategrub.sh; bash /tmp/updategrub.sh"
        
        ]
    }
}
#########################################################
# End grub configuration for HANA.
#########################################################
