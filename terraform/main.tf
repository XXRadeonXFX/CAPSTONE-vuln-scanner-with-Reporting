# Keep your existing VPC and Subnet data blocks
data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_subnet" "selected" {
  id = var.subnet_id
}

# Jenkins Server
resource "aws_instance" "jenkins" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = data.aws_subnet.selected.id
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
  subnet_id              = data.aws_subnet.selected.id
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
