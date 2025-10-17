# A few caveats to note about Azure VM network interfaces (NICs)
# Every NIC must be associated to a subnet (even if the intent is only to have a public IP)
# Every IP configuration gets a private IP (even when not specified, Azure creates it)
# A subnet association is required in every IP configuration block, despite the fact that NIC may only associate to one subnet

locals {
  tags = merge(var.tags, local.module_tags)
  module_tags = {
    tfc-module = "virtual_machine"
  }

  # azurerm vm resources implement network interfaces based on order of input.
  # order the inputs so the nic tagged as primary is first.
  # this affects default routing within the OS
  ordered_network_interface_keys = concat(
    [for nic, value in var.network_interfaces : nic if value.is_primary],
    [for nic, value in var.network_interfaces : nic if !value.is_primary]
  )

  # flatten ip_configs for the nics
  nics_ip_configs = { for ip_config in flatten([
    for nk, nv in var.network_interfaces : [
      for ipck, ipcv in nv.ip_configurations : merge(
        {
          nic_key      = nk
          ipconfig_key = ipck
        },
        ipcv
      )
    ]
  ]) : "${ip_config.nic_key}-${ip_config.ipconfig_key}" => ip_config }

  linux_vm_uses_password = var.os_type == "linux" && var.disable_password_authentication == false

  use_availability_set = var.availability_set_id != null || var.create_availability_set

  extension_protected_settings_map = {
    for ps in var.extension_protected_settings : ps.extension_name => ps.value
  }

  # Merge extension_protected_settings into each corresponding extensions 'protected_settings' block
  extensions = {
    for extension in var.extensions : extension.name => merge(
      extension,
      {
        protected_settings = lookup(local.extension_protected_settings_map, extension.name, null)
      }
    )
  }

  default_sql_disk_parameters = {
    caching                           = "None"
    create_option                     = null
    source_resource_id                = null
    disk_attachment_create_option     = null
    disk_access_id                    = null
    disk_encryption_set_id            = null
    disk_iops_read_only               = null
    disk_iops_read_write              = null
    disk_mbps_read_only               = null
    disk_mbps_read_write              = null
    gallery_image_reference_id        = null
    hyper_v_generation                = null
    image_reference_id                = null
    logical_sector_size               = null
    max_shares                        = null
    network_access_policy             = null
    on_demand_bursting_enabled        = null
    optimized_frequent_attach_enabled = false
    os_type                           = null
    performance_plus_enabled          = false
    public_network_access_enabled     = true
    secure_vm_disk_encryption_set_id  = null
    security_type                     = null
    source_uri                        = null
    storage_account_id                = null
    tier                              = null
    trusted_launch_enabled            = null
    upload_size_bytes                 = null
  }

  sql_default_data_disks = [
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-Software-D"
      lun                  = 0
      storage_account_type = "Standard_LRS"
      disk_size_gb         = 64
    }),
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-Logs-E"
      lun                  = 1
      storage_account_type = "Standard_LRS"
      disk_size_gb         = 128
    }),
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-SysData-F"
      lun                  = 2
      storage_account_type = "Standard_LRS"
      disk_size_gb         = 64
    }),
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-Data-H"
      lun                  = 3
      storage_account_type = "Standard_LRS"
      disk_size_gb         = 256
    }),
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-DBAdmin-L"
      lun                  = 4
      storage_account_type = "Standard_LRS"
      disk_size_gb         = 32
    }),
    merge(local.default_sql_disk_parameters, {
      name                 = "${var.name}-TempDB-T"
      lun                  = 5
      storage_account_type = "Premium_LRS"
      disk_size_gb         = 128
    }),
  ]

  final_data_disks = length(var.data_disks) > 0 ? var.data_disks : (var.sql_vm ? local.sql_default_data_disks : [])
}

resource "tls_private_key" "this" {
  count     = var.os_type == "linux" && local.linux_vm_uses_password == false ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096

  lifecycle {
    create_before_destroy = true
  }
}

# create public ip(s) - Assumes each ip configuration has a unique name
resource "azurerm_public_ip" "this" {
  for_each = { for key, values in local.nics_ip_configs : key => values if values.public_ip != null && try(values.public_ip.name, null) != null }

  name                    = each.value.public_ip.name
  location                = var.location
  resource_group_name     = var.resource_group_name
  tags                    = local.tags
  edge_zone               = var.edge_zone
  allocation_method       = try(each.value.public_ip.allocation_method, "Static")
  ddos_protection_mode    = try(each.value.public_ip.ddos_protection_mode, "VirtualNetworkInherited")
  ddos_protection_plan_id = try(each.value.public_ip.ddos_protection_plan_id, null)
  domain_name_label       = try(each.value.public_ip.domain_name_label, null)
  idle_timeout_in_minutes = try(each.value.public_ip.idle_timeout_in_minutes, 30)
  ip_version              = try(each.value.public_ip.ip_version, "IPv4")
  sku                     = try(each.value.public_ip.sku, "Standard")
  sku_tier                = try(each.value.public_ip.sku_tier, "Regional")
  zones                   = try(each.value.public_ip.zones, ["1", "2", "3"])
}

resource "azurerm_network_interface" "this" {
  for_each = { for idx, nic in var.network_interfaces : idx => nic }

  name                           = each.value.name != null ? each.value.name : lower("${var.name}-nic${each.key + 1}")
  location                       = var.location
  resource_group_name            = var.resource_group_name
  tags                           = local.tags
  edge_zone                      = var.edge_zone
  accelerated_networking_enabled = each.value.enable_accelerated_networking
  dns_servers                    = each.value.dns_servers
  internal_dns_name_label        = each.value.internal_dns_name_label
  ip_forwarding_enabled          = each.value.enable_ip_forwarding

  dynamic "ip_configuration" {
    for_each = { for idx, ip_config in each.value.ip_configurations : idx => ip_config }

    content {
      name                                               = ip_configuration.value.name != null ? ip_configuration.value.name : lower("${var.name}-nic${each.key + 1}-ip${ip_configuration.key + 1}")
      primary                                            = ip_configuration.value.is_primary_ipconfiguration
      subnet_id                                          = try(ip_configuration.value.subnet_resource_id, null)
      gateway_load_balancer_frontend_ip_configuration_id = try(ip_configuration.value.gateway_load_balancer_frontend_ip_configuration_resource_id, null)
      private_ip_address_allocation                      = try(ip_configuration.value.private_ip.ip_address_allocation, "Dynamic")
      private_ip_address                                 = try(ip_configuration.value.private_ip.ip_address, null)
      private_ip_address_version                         = try(ip_configuration.value.private_ip.ip_address_version, "IPv4")

      # Use created public IP if name is supplied, or existing_resource_id if supplied, else null
      public_ip_address_id = (
        try(ip_configuration.value.public_ip.name, null) != null && contains(keys(azurerm_public_ip.this), "${each.key}-${ip_configuration.key}") ?
        azurerm_public_ip.this["${each.key}-${ip_configuration.key}"].id :
        try(ip_configuration.value.public_ip.existing_resource_id, null)
      )
    }
  }
}

resource "random_password" "this" {
  length           = 16
  special          = true
  override_special = "!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
}

resource "azurerm_availability_set" "this" {
  count                        = local.use_availability_set && var.create_availability_set ? 1 : 0
  name                         = "${var.name}-avset"
  location                     = var.location
  resource_group_name          = var.resource_group_name
  platform_fault_domain_count  = var.availability_set_config.platform_fault_domain_count
  platform_update_domain_count = var.availability_set_config.platform_update_domain_count
  managed                      = var.availability_set_config.managed
  tags                         = local.tags
}

resource "azurerm_windows_virtual_machine" "this" {
  count = var.os_type == "windows" ? 1 : 0

  name                       = var.name
  computer_name              = var.name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  zone                       = var.zone
  edge_zone                  = var.edge_zone
  size                       = var.sku_size
  network_interface_ids      = [for interface in local.ordered_network_interface_keys : azurerm_network_interface.this[interface].id]
  admin_username             = var.admin_username
  admin_password             = resource.random_password.this.result
  encryption_at_host_enabled = var.encryption_at_host_enabled
  license_type               = var.license_type
  tags                       = local.tags
  timezone                   = var.timezone

  custom_data = var.custom_data != null ? base64encode(var.custom_data) : null

  availability_set_id = local.use_availability_set ? (var.availability_set_id != null ? var.availability_set_id : azurerm_availability_set.this[0].id) : null

  dedicated_host_group_id = var.dedicated_host_group_id # supported when azurerm_dedicated_host_group.automatic_placement_enabled = true
  dedicated_host_id       = var.dedicated_host_id       # required when azurerm_dedicated_host_group.automatic_placement_enabled = false

  os_disk {
    caching              = var.os_disk.caching
    storage_account_type = var.os_disk.storage_account_type
    disk_size_gb         = var.os_disk.disk_size_gb
    name                 = var.os_disk.name != null ? var.os_disk.name : lower("${var.name}-os")
  }

  source_image_reference {
    publisher = var.source_image.publisher
    offer     = var.source_image.offer
    sku       = var.source_image.sku
    version   = var.source_image.version
  }

  boot_diagnostics {
    storage_account_uri = var.boot_diagnostics.storage_account_uri
  }

  dynamic "plan" {
    for_each = var.plan != null ? [1] : []
    content {
      name      = var.plan.name
      product   = var.plan.product
      publisher = var.plan.publisher
    }
  }

  dynamic "identity" {
    for_each = var.identity != null ? [var.identity] : []

    content {
      type         = identity.value.type
      identity_ids = identity.value.identity_ids
    }
  }
  lifecycle {
    ignore_changes = [gallery_application, ] #Managed outside terraform
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  count = var.os_type == "linux" ? 1 : 0

  name                       = var.name
  computer_name              = var.name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  license_type               = var.license_type
  zone                       = var.zone
  edge_zone                  = var.edge_zone
  size                       = var.sku_size
  network_interface_ids      = [for interface in local.ordered_network_interface_keys : azurerm_network_interface.this[interface].id]
  encryption_at_host_enabled = var.encryption_at_host_enabled
  tags                       = local.tags

  custom_data = var.custom_data != null ? base64encode(var.custom_data) : null

  availability_set_id = local.use_availability_set ? (var.availability_set_id != null ? var.availability_set_id : azurerm_availability_set.this[0].id) : null

  dedicated_host_group_id = var.dedicated_host_group_id # supported when azurerm_dedicated_host_group.automatic_placement_enabled = true
  dedicated_host_id       = var.dedicated_host_id       # required when azurerm_dedicated_host_group.automatic_placement_enabled = false

  os_disk {
    caching              = var.os_disk.caching
    storage_account_type = var.os_disk.storage_account_type
    disk_size_gb         = var.os_disk.disk_size_gb
    name                 = var.os_disk.name != null ? var.os_disk.name : lower("${var.name}-os")
  }

  source_image_reference {
    publisher = var.source_image.publisher
    offer     = var.source_image.offer
    sku       = var.source_image.sku
    version   = var.source_image.version
  }

  boot_diagnostics {
    storage_account_uri = var.boot_diagnostics.storage_account_uri
  }

  admin_username                  = var.admin_username
  admin_password                  = var.disable_password_authentication == true ? null : resource.random_password.this.result
  disable_password_authentication = var.disable_password_authentication

  dynamic "admin_ssh_key" {
    for_each = local.linux_vm_uses_password == false ? [1] : []
    content {
      username   = var.admin_username
      public_key = tls_private_key.this[0].public_key_openssh
    }
  }

  dynamic "plan" {
    for_each = var.plan != null ? [1] : []
    content {
      name      = var.plan.name
      product   = var.plan.product
      publisher = var.plan.publisher
    }
  }

  dynamic "identity" {
    for_each = var.identity != null ? [var.identity] : []

    content {
      type         = identity.value.type
      identity_ids = lookup(identity.value, "identity_ids", null)
    }
  }
  lifecycle {
    ignore_changes = [gallery_application, ] #Managed outside terraform
  }
}

resource "azurerm_managed_disk" "this" {
  for_each = { for disk in local.final_data_disks : disk.name => disk }

  name                              = each.value.name
  location                          = var.location
  resource_group_name               = var.resource_group_name
  storage_account_type              = each.value.storage_account_type
  create_option                     = each.value.create_option != null ? each.value.create_option : "Empty"
  disk_size_gb                      = each.value.disk_size_gb
  zone                              = local.use_availability_set ? null : var.zone
  source_resource_id                = each.value.create_option == "Restore" || each.value.create_option == "Copy" ? each.value.source_resource_id : null
  edge_zone                         = var.edge_zone
  tags                              = local.tags
  disk_access_id                    = each.value.disk_access_id
  disk_encryption_set_id            = each.value.disk_encryption_set_id
  disk_iops_read_only               = each.value.disk_iops_read_only
  disk_iops_read_write              = each.value.disk_iops_read_write
  disk_mbps_read_only               = each.value.disk_mbps_read_only
  disk_mbps_read_write              = each.value.disk_mbps_read_write
  gallery_image_reference_id        = each.value.gallery_image_reference_id
  hyper_v_generation                = each.value.hyper_v_generation
  image_reference_id                = each.value.image_reference_id
  logical_sector_size               = each.value.logical_sector_size
  max_shares                        = each.value.max_shares
  network_access_policy             = each.value.network_access_policy
  on_demand_bursting_enabled        = each.value.on_demand_bursting_enabled
  optimized_frequent_attach_enabled = each.value.optimized_frequent_attach_enabled
  os_type                           = each.value.os_type
  performance_plus_enabled          = each.value.performance_plus_enabled
  public_network_access_enabled     = each.value.public_network_access_enabled
  secure_vm_disk_encryption_set_id  = each.value.secure_vm_disk_encryption_set_id
  security_type                     = each.value.security_type
  source_uri                        = each.value.source_uri
  storage_account_id                = each.value.storage_account_id
  tier                              = each.value.tier
  trusted_launch_enabled            = each.value.trusted_launch_enabled
  upload_size_bytes                 = each.value.upload_size_bytes
}

resource "azurerm_virtual_machine_data_disk_attachment" "this" {
  for_each = { for disk in local.final_data_disks : disk.name => disk if disk.create_option != "FromImage" }

  managed_disk_id    = azurerm_managed_disk.this[each.value.name].id
  virtual_machine_id = var.os_type == "windows" ? azurerm_windows_virtual_machine.this[0].id : azurerm_linux_virtual_machine.this[0].id
  caching            = each.value.caching
  lun                = each.value.lun
  create_option      = try(each.value.disk_attachment_create_option, null)
}

resource "azurerm_virtual_machine_extension" "this" {
  for_each = local.extensions

  virtual_machine_id         = var.os_type == "linux" ? azurerm_linux_virtual_machine.this[0].id : azurerm_windows_virtual_machine.this[0].id
  tags                       = var.tags
  name                       = each.value.name
  publisher                  = each.value.publisher
  type                       = each.value.type
  type_handler_version       = each.value.type_handler_version
  auto_upgrade_minor_version = each.value.auto_upgrade_minor_version
  automatic_upgrade_enabled  = each.value.automatic_upgrade_enabled
  provision_after_extensions = each.value.provision_after_extensions
  settings                   = each.value.settings

  # protected_settings is mutually exclusive with protected_settings_from_key_vault
  # only one may be used at a time
  protected_settings = each.value.protected_settings_from_key_vault == null ? each.value.protected_settings : null

  dynamic "protected_settings_from_key_vault" {
    for_each = each.value.protected_settings_from_key_vault != null ? [each.value.protected_settings_from_key_vault] : []

    content {
      secret_url      = each.value.protected_settings_from_key_vault.secret_url
      source_vault_id = each.value.protected_settings_from_key_vault.source_vault_id
    }
  }

  lifecycle {
    ignore_changes = [tags]
  }

  depends_on = [
    azurerm_windows_virtual_machine.this,
    azurerm_linux_virtual_machine.this,
    azurerm_managed_disk.this,
    azurerm_virtual_machine_data_disk_attachment.this
  ]
}

# create NIC-to-NSG association if network_security_group_id is supplied
resource "azurerm_network_interface_security_group_association" "this" {
  for_each = { for idx, nic in var.network_interfaces : idx => nic if contains(keys(nic), "network_security_group_id") && nic.network_security_group_id != null }

  network_interface_id      = azurerm_network_interface.this[each.key].id
  network_security_group_id = each.value.network_security_group_id
}

data "azurerm_recovery_services_vault" "this" {
  count = var.backup_configuration != null ? 1 : 0

  name                = var.backup_configuration.recovery_vault_name
  resource_group_name = var.backup_configuration.recovery_vault_resource_group_name
}

data "azurerm_backup_policy_vm" "this" {
  count = var.backup_configuration != null ? 1 : 0

  name                = var.backup_configuration.policy_name
  recovery_vault_name = data.azurerm_recovery_services_vault.this[0].name
  resource_group_name = data.azurerm_recovery_services_vault.this[0].resource_group_name
}

resource "azurerm_backup_protected_vm" "this" {
  count = var.backup_configuration != null ? 1 : 0

  resource_group_name = data.azurerm_recovery_services_vault.this[0].resource_group_name
  recovery_vault_name = data.azurerm_recovery_services_vault.this[0].name

  source_vm_id = var.os_type == "windows" ? (length(azurerm_windows_virtual_machine.this) > 0 ? azurerm_windows_virtual_machine.this[0].id : null) : (
  length(azurerm_linux_virtual_machine.this) > 0 ? azurerm_linux_virtual_machine.this[0].id : null)

  backup_policy_id  = data.azurerm_backup_policy_vm.this[0].id
  include_disk_luns = var.backup_configuration.included_disk_luns
  exclude_disk_luns = var.backup_configuration == null ? [] : coalesce(var.backup_configuration.excluded_disk_luns, var.sql_vm ? [1, 3, 5] : [], [])

  depends_on = [
    azurerm_windows_virtual_machine.this,
    azurerm_linux_virtual_machine.this,
  ]
}
