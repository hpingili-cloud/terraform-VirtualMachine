output "os_type" {
  description = "The operating system type of the virtual machine"
  value       = var.os_type
}

output "name" {
  description = "The name of the virtual machine"
  value       = var.os_type == "windows" ? azurerm_windows_virtual_machine.this[0].name : azurerm_linux_virtual_machine.this[0].name
}

output "id" {
  description = "The resource ID of the virtual machine"
  value       = var.os_type == "windows" ? azurerm_windows_virtual_machine.this[0].id : azurerm_linux_virtual_machine.this[0].id
}

output "admin_username" {
  description = "The admin username for the virtual machine"
  value       = var.admin_username
}

output "admin_password" {
  description = "The admin password for the virtual machine"
  value = (
    var.os_type == "linux" && var.disable_password_authentication == true
    ? "Password authentication is disabled for this Linux VM."
    : resource.random_password.this.result
  )
  sensitive = true
}

output "private_key_pem" {
  description = "value of the private key PEM for the virtual machine"
  value       = var.os_type == "linux" && local.linux_vm_uses_password == false ? tls_private_key.this[0].private_key_pem : null
  sensitive   = true
}

output "network_interfaces" {
  description = "The full ARM object map associated with the deployed NIC(s)."
  value       = azurerm_network_interface.this
}

output "public_ips" {
  description = "The full ARM object map associated with any deployed Public IP(s)."
  value       = azurerm_public_ip.this
}

output "vm_backup_id" {
  description = "The ID of the Azure VM Backup Protected VM resource, if backup is enabled."
  value       = length(azurerm_backup_protected_vm.this) > 0 ? azurerm_backup_protected_vm.this[0].id : null
}
