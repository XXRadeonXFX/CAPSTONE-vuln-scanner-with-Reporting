output "jenkins_public_ip" {
  description = "Public IP of Jenkins server"
  value       = aws_instance.jenkins.public_ip
}

output "monitoring_public_ip" {
  description = "Public IP of Monitoring server"
  value       = aws_instance.monitoring.public_ip
}
