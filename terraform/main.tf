# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get subnets in the default VPC
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Jenkins Server
resource "aws_instance" "jenkins" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = tolist(data.aws_subnets.default.ids)[0]   # first subnet
  vpc_security_group_ids = [var.sg_id]

  tags = {
    Name = "prince-${var.project}-jenkins"
  }
}

# Monitoring Server (Prometheus + Grafana)
resource "aws_instance" "monitoring" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = tolist(data.aws_subnets.default.ids)[0]   # first subnet
  vpc_security_group_ids = [var.sg_id]

  tags = {
    Name = "prince-${var.project}-monitoring"
  }
}

# Generate dynamic Ansible inventory
resource "local_file" "ansible_inventory" {
  content = <<EOT
[jenkins]
${aws_instance.jenkins.public_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/${var.key_name}.pem

[monitoring]
${aws_instance.monitoring.public_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/${var.key_name}.pem
EOT

  filename = "${path.module}/../ansible/inventory/hosts.ini"
}
