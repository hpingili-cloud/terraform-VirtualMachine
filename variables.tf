variable "resource_group_name" {
  type        = string
  description = "(Required) The name of the resource group. Changing this forces a new resource to be created. Resource group names must be between 1 and 90 characters in length and use alphanumeric characters, underscores, parentheses, hyphens, and periods only."
}

variable "name" {
  type        = string
  description = "(Required) The name to use when creating the virtual machine. Must be unique within the Azure Region. Changing this forces a new resource to be created. Virtual machine names for linux must be between 1 and 64 characters in length. Virtual machine name for windows must be between 1 and 20 characters in length."

  validation {
    condition     = can(regex("^.{1,64}$", var.name))
    error_message = "virtual machine names for linux must be between 1 and 64 characters in length. Virtual machine name for windows must be between 1 and 20 characters in length."
  }
}

variable "source_image" {
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
  default = {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }
  description = <<-EOT
    (Optional) The source image reference for the virtual machine. 
      
    - `publisher` (Required) The publisher of the image reference. Changing this forces a new resource to be created. Defaults to MicrosoftWindowsServer.
    - `offer` (Required) The offer of the image reference. Changing this forces a new resource to be created. Defaults to WindowsServer.
    - `sku` (Required) The SKU of the image reference. Changing this forces a new resource to be created. Defaults to 2022-Datacenter.
    - `version` (Required) The version of the image reference. Changing this forces a new resource to be created. Defaults to latest.
    EOT
}

variable "location" {
  type        = string
  default     = "canadacentral"
  description = "(Optional) The Azure region where this and supporting resources should be deployed. Changing this forces a new resource to be created. Defaults to canadacentral."
}

variable "os_type" {
  type        = string
  default     = "windows"
  description = "(Optional) Operating system for the Azure Virtual Machine. Possible values are 'windows' or 'linux'."

  validation {
    condition     = contains(["windows", "linux"], var.os_type)
    error_message = "Invalid value for os_type. Valid options are 'windows' or 'linux'"
  }
}

variable "sku_size" {
  type        = string
  default     = "Standard_D2as_v5"
  description = "(Optional) sku size for the virtual machine. Defaults to `Standard_D2as_v5` (AMD processor)."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "(Optional) Map of tags to assign to the storage account resource"
  validation {
    condition = alltrue([
      for k in keys(var.tags) : lower(k) != "tfc-module"
    ])
    error_message = "'tfc-module' is a reserved tag and must not be set by module consumers."
  }
}

variable "network_interfaces" {
  type = list(object({
    name                          = optional(string, null)
    is_primary                    = optional(bool, true)
    dns_servers                   = optional(set(string), [])
    enable_accelerated_networking = optional(bool, false)
    enable_ip_forwarding          = optional(bool, false)
    internal_dns_name_label       = optional(string)
    network_security_group_id     = optional(string)
    ip_configurations = list(object({
      name                                                        = optional(string, null)
      is_primary_ipconfiguration                                  = optional(bool, true)
      subnet_resource_id                                          = optional(string)
      gateway_load_balancer_frontend_ip_configuration_resource_id = optional(string)
      private_ip = optional(object({
        ip_address            = optional(string)
        ip_address_allocation = optional(string, "Dynamic")
        ip_address_version    = optional(string, "IPv4")
      }), null)
      public_ip = optional(object({
        name                    = optional(string)
        existing_resource_id    = optional(string)
        allocation_method       = optional(string, "Static")
        ddos_protection_mode    = optional(string, "VirtualNetworkInherited")
        ddos_protection_plan_id = optional(string)
        domain_name_label       = optional(string)
        idle_timeout_in_minutes = optional(number, 30)
        ip_version              = optional(string, "IPv4")
        sku                     = optional(string, "Standard")
        sku_tier                = optional(string, "Regional")
        zones                   = optional(set(string), ["1", "2", "3"])
      }), null)
    }))
  }))
  description = <<-EOT
    (Required) A list of network interfaces to configure on the VM

    - `name` (Optional) Name of this Network Interface. Name is generated if not specified (example: 'vmname-nic1').
    - `is_primary` (Optional) Is it the Primary Network Interface? Possible values are `true` or `false`. Defaults to `true` (as most VMs have only one NIC).
    - `dns_servers` (Optional) A set of DNS Server IP Addresses assigned to the NIC.
    - `enable_accelerated_networking` (Optional) Should the NIC support Accelerated Networking? Possible values are `true` or `false`. Defaults to `false`.
    - `enable_ip_forwarding` (Optional) Should the NIC support IP Forwarding? Possible values are `true` or `false`. Defaults to `false`.
    - `internal_dns_name_label` (Optional) The relative DNS Name for internal communications between Virtual Machines in the same Virtual Network.
    - `network_security_group_id` (Optional) The ID of a Network Security Group to be assigned to this NIC.
    - `ip_configurations` (Required) A list of ip configurations on this NIC. One must be marked `is_primary_ipconfiguration` for each NIC.
      - `name` (Optional) The Name of this IP Configuration. Name is generated if not specified (example: 'vmname-nic1-ip1').
      - `is_primary_ipconfiguration` (Optional) Is it the Primary IP Configuration for this NIC? Possible values are `true` and `false`. Defaults to `true` (as VMs typically have one IP configuration per NIC).
      - `subnet_resource_id` (Optional) The Azure subnet ID where this NIC is attached. Required for ALL IPv4 configurations - whether private OR public IP address (Azure requirement).
      - `gateway_load_balancer_frontend_ip_configuration_resource_id` (Optional) The Frontend IP Configuration resource ID of a Gateway SKU Load Balancer.
      - `private_ip` (Optional) A Private IP block as follows. Every IP configuration gets a private IP, whether this block is included or omitted (Azure behavior).
          - `ip_address` (Optional) The Static IP of this IP configuration, required if `ip_address_allocation` is `Static`.
          - `ip_address_allocation` (Optional) The allocation method for the Private IP. Possible values are `Dynamic` and `Static`. Defaults to `Dynamic`.
          - `ip_address_version` (Optional) The IP Version to use. Possible values are `IPv4` or `IPv6`. Defaults to `IPv4`.
      - `public_ip` (Optional) A Public IP block as follows:
          - `name` (Optional) The Name of the Public IP Address to be created. Required when creating a Public IP. Cannot be used with `existing_resource_id`.
          - `existing_resource_id` (Optional) Azure Resource ID of a Public IP Address to be associated with this NIC. Required when using an existing Public IP. Cannot be used with `name`.
          - `allocation_method` (Optional) Allocation method for this IP address. Possible values are `Static` or `Dynamic`. Defaults to `Static`.
          - `ddos_protection_mode` (Optional) DDoS protection mode of the public IP. Possible values are `Disabled`, `Enabled`, and `VirtualNetworkInherited`. Defaults to `VirtualNetworkInherited`.
          - `ddos_protection_plan_id` (Optional) The ID of DDoS protection plan associated with the public IP. ddos_protection_plan_id can only be set when ddos_protection_mode is Enabled
          - `domain_name_label` (Optional) Label for the Domain Name. Will be used to make up the FQDN.
          - `idle_timeout_in_minutes` (Optional) Timeout for the TCP idle connection can be set from `4` to `30` minutes. Default is `30`.
          - `ip_version` (Optional) Use `IPv4` or `IPv6`. Defaults to `IPv4`. Only static IP allocation is supported for `IPv6`.
          - `sku` (Optional) The Public IP SKU. Accepted values are `Basic` or `Standard`. Defaults to `Standard` to support zones by default. When sku_tier is set to `Global`, sku must be set to `Standard`. Changing this forces a new resource to be created.
          - `sku_tier` (Optional) The Public IP SKU tier. Accepted values are `Global` and `Regional`. Defaults to `Regional`.
          - `zones` (Optional) A set of availability zones to assign the public IP to. Configured to use all zones by default. Not all regions support zones. Change this if fewer than 3 zones are available in the target region. Changing this forces a new resource to be created.
    EOT
  # Only one NIC can be primary
  validation {
    condition = (
      length([
        for nic in var.network_interfaces : nic.is_primary if nic.is_primary == true
      ]) == 1
    )
    error_message = "Only one network interface can have is_primary = true."
  }

  # Only one IP configuration per NIC can be is_primary_ipconfiguration
  validation {
    condition = alltrue([
      for nic in var.network_interfaces : (
        length([
          for ipconf in nic.ip_configurations : ipconf.is_primary_ipconfiguration if ipconf.is_primary_ipconfiguration == true
        ]) == 1
      )
    ])
    error_message = "A network interface must have only one ip_configuration with is_primary_ipconfiguration = true."
  }
  # Create a Public IP or reuse an existing one (not both)
  validation {
    condition = alltrue([
      for nic in var.network_interfaces : alltrue([
        for ipconf in nic.ip_configurations : (
          ipconf.public_ip == null ||
          (
            !(
              try(ipconf.public_ip.name, null) != null &&
              try(ipconf.public_ip.existing_resource_id, null) != null
            )
          )
        )
      ])
    ])
    error_message = "Only one of public_ip.name or public_ip.existing_resource_id may be set (not both)."
  }
}

variable "os_disk" {
  type = object({
    name                 = optional(string, null)
    caching              = optional(string, "ReadWrite")
    storage_account_type = optional(string, "Premium_LRS")
    disk_size_gb         = optional(number, 127)
  })
  default = {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = 127
  }
  description = <<-EOT
    (Optional) OS disk configuration:

    - `name` (Optional) Name of the OS disk. Changing this forces a new resource to be created. Defaults to `<vm_name>-os`.
    - `caching` (Optional) Caching mode for the OS disk. Possible values are `None`, `ReadOnly`, and `ReadWrite`. Defaults to `ReadWrite`.
    - `storage_account_type` (Optional) Storage type for the OS Disk. Possible values are `Standard_LRS`, `Premium_LRS`, `StandardSSD_ZRS` and `Premium_ZRS`. Defaults to `Premium_LRS`. Changing this forces a new resource to be created.
    - `disk_size_gb` (Optional) OS disk size in gigabytes. Defaults to `127` GB. Changing this forces a new resource to be created.
    EOT
}

variable "data_disks" {
  type = list(object({
    name                              = string
    lun                               = number
    caching                           = optional(string, "None")
    storage_account_type              = optional(string, "Standard_LRS")
    disk_size_gb                      = optional(number, 256)
    create_option                     = optional(string, null)
    source_resource_id                = optional(string, null)
    disk_attachment_create_option     = optional(string, null)
    disk_access_id                    = optional(string, null)
    disk_encryption_set_id            = optional(string, null)
    disk_iops_read_only               = optional(number, null)
    disk_iops_read_write              = optional(number, null)
    disk_mbps_read_only               = optional(number, null)
    disk_mbps_read_write              = optional(number, null)
    gallery_image_reference_id        = optional(string, null)
    hyper_v_generation                = optional(string, null)
    image_reference_id                = optional(string, null)
    logical_sector_size               = optional(number, null)
    max_shares                        = optional(number, null)
    network_access_policy             = optional(string, null)
    on_demand_bursting_enabled        = optional(bool, null)
    optimized_frequent_attach_enabled = optional(bool, false)
    os_type                           = optional(string, null)
    performance_plus_enabled          = optional(bool, false)
    public_network_access_enabled     = optional(bool, true)
    secure_vm_disk_encryption_set_id  = optional(string, null)
    security_type                     = optional(string, null)
    source_uri                        = optional(string, null)
    storage_account_id                = optional(string, null)
    tier                              = optional(string, null)
    trusted_launch_enabled            = optional(bool, null)
    upload_size_bytes                 = optional(number, null)
  }))
  default     = []
  description = <<-EOT
    (Optional) List of `data_disks` as follows:

    - `name` (Required) Name of the data disk. Changing this forces a new resource to be created.
    - `lun` (Required) Logical Unit Number of the data disk, must be unique in the Virtual Machine. Changing this forces a new resource to be created.
    - `caching` (Optional) Caching mode for the data disk. Possible values are `None`, `ReadOnly`, and `ReadWrite`. Defaults to `None`.
    - `storage_account_type` (Optional) Storage type - possible values are `Standard_LRS`, `StandardSSD_ZRS`, `Premium_LRS`, `PremiumV2_LRS`, `Premium_ZRS`, `StandardSSD_LRS` or `UltraSSD_LRS`. Defaults to `Standard_LRS`.
    - `disk_size_gb` (Optional) Data disk size in gigabytes. Defaults to a `256` GB data disk if not specified.
    - `create_option` (Optional) The method to use when creating a managed disk. Possible values include: 1. `Empty` Create an empty managed disk. 2. `Copy` Copy an existing managed disk or snapshot (specified with source_resource_id). 3. `FromImage` Copy a Platform Image (specified with image_reference_id) 4. `Restore` Set by Azure Backup or Site Recovery on a restored disk (specified with source_resource_id). Defaults to `Empty` when null. Changing this forces a new resource to be created.
    - `source_resource_id` (Optional) The Azure resource ID of the source snapshot or disk. Required when `create_option` is `Restore` or `Copy`.
    - `disk_attachment_create_option` (Optional) - Create Option of a data disk attachment - either `Empty` or `Attach`. Defaults to `Attach` if null. Changing this forces a new resource to be created.
    - `disk_access_id` (Optional) The ID of the disk access resource for using private endpoints on disks.
    - `disk_encryption_set_id` (Optional) The ID of the disk encryption set.
    - `disk_iops_read_only` (Optional) The number of IOPS allowed across all VMs mounting the shared disk as read-only; only settable for UltraSSD disks and PremiumV2 disks with shared disk enabled.
    - `disk_iops_read_write` (Optional) The number of IOPS allowed for this disk; only settable for UltraSSD disks and PremiumV2 disks.
    - `disk_mbps_read_only` (Optional) The bandwidth allowed across all VMs mounting the shared disk as read-only; only settable for UltraSSD disks and PremiumV2 disks with shared disk enabled.
    - `disk_mbps_read_write` (Optional) The bandwidth in MBps allowed for read/write operations.
    - `gallery_image_reference_id` (Optional) ID of a Gallery Image Version to copy when create_option is FromImage.
    - `hyper_v_generation` (Optional) The HyperV Generation of the Disk when the source of an Import or Copy operation targets a source that contains an operating system. Possible values are V1 and V2.
    - `image_reference_id` (Optional) ID of an existing platform/marketplace disk image to copy when create_option is FromImage. This field cannot be specified if gallery_image_reference_id is specified.
    - `logical_sector_size` (Optional) Logical Sector Size. Possible values are: 512 and 4096. Defaults to 4096.
    - `max_shares` (Optional) The maximum number of VMs that can attach to the disk at the same time. Value greater than one indicates a disk that can be mounted on multiple VMs at the same time.
    - `network_access_policy` (Optional) The network access policy for the disk. Possible values are `AllowAll`, `AllowPrivate`, or `DenyAll`.
    - `on_demand_bursting_enabled` (Optional) Whether on-demand bursting is enabled for the disk.
    - `optimized_frequent_attach_enabled` (Optional) Whether optimized frequent attach is enabled for the disk. Defaults to `false`.
    - `os_type` (Optional) The operating system type of the disk. Possible values are `Windows` or `Linux`.
    - `performance_plus_enabled` (Optional) Whether performance plus is enabled for the disk. Defaults to `false`.
    - `public_network_access_enabled` (Optional) Whether public network access is enabled for the disk. Defaults to `true`.
    - `secure_vm_disk_encryption_set_id` (Optional) The ID of the secure VM disk encryption set.
    - `security_type` (Optional) The security type of the disk.
    - `source_uri` (Optional) The URI of the source VHD or image.
    - `storage_account_id` (Optional) The ID of the Storage Account where the source_uri is located. Required when create_option is set to Import or ImportSecure. Changing this forces a new resource to be created.
    - `tier` (Optional) The disk performance tier to use.This feature is currently supported only for premium SSDs.
    - `trusted_launch_enabled` (Optional) Whether trusted launch is enabled for the disk.
    - `upload_size_bytes` (Optional) The size in bytes for upload operations.
    EOT

  validation {
    condition = alltrue([
      for disk in var.data_disks : (
        !(disk.create_option == "Copy" || disk.create_option == "Restore") || (disk.source_resource_id != null && disk.source_resource_id != "")
      )
    ])
    error_message = "If create_option is 'Copy' or 'Restore', then 'source_resource_id' must also be set."
  }

  validation {
    condition = alltrue([
      for disk in var.data_disks : (
        disk.create_option != "FromImage" || (disk.image_reference_id != null && disk.image_reference_id != "")
      )
    ])
    error_message = "If create_option is 'FromImage', then 'image_reference_id' must also be set."
  }

  validation {
    condition = alltrue([
      for disk in var.data_disks : (
        disk.disk_attachment_create_option == null ||
        disk.disk_attachment_create_option == "Empty" ||
        disk.disk_attachment_create_option == "Attach"
      )
    ])
    error_message = "disk_attachment_create_option must be 'Empty', 'Attach', or null. If null, the provider defaults to 'Attach'."
    # https://github.com/hashicorp/terraform-provider-azurerm/issues/12032
    # azurerm_virtual_machine_data_disk_attachment.create_option does not support Copy or FromImage 
  }
}

variable "zone" {
  type        = string
  default     = null
  description = "(Optional) The Availability Zone which the Virtual Machine should be allocated in, only one zone would be accepted. If set then this module won't create azurerm_availability_set resource. Changing this forces a new resource to be created. If deploying to a region without zones, this must be null."
}

variable "admin_username" {
  type        = string
  default     = "azadmin"
  description = "(Optional) The administrator username for the virtual machine."
}

variable "disable_password_authentication" {
  type        = bool
  default     = false
  description = "(Optional) Disable password authentication for the Linux virtual machine. Defaults to false."
}

variable "plan" {
  type = object({
    name      = string
    product   = string
    publisher = string
  })
  default     = null
  description = <<-EOT
  (Optional) Specifies the plan for the gallery application.

  - `name` (Required) The name of the plan for the gallery application.
  - `product` (Required) The product of the plan for the gallery application.
  - `publisher` (Required) The publisher of the plan for the gallery application.
  EOT
}

variable "custom_data" {
  type        = string
  default     = null
  description = "(Optional) User-provided data that can be used for VM customization (e.g., cloud-init)."
}

variable "availability_set_id" {
  type        = string
  default     = null
  description = "(Optional) The ID of an existing availability set to use for the virtual machine."
}

variable "create_availability_set" {
  type        = bool
  default     = false
  description = "(Optional) Whether to create a new availability set for the virtual machine."
}

variable "availability_set_config" {
  type = object({
    platform_fault_domain_count  = number
    platform_update_domain_count = number
    managed                      = bool
  })
  default = {
    platform_fault_domain_count  = 2
    platform_update_domain_count = 5
    managed                      = true
  }
  description = <<-EOT
    (Optional) Configuration settings for the availability set (if one is created).

    - `platform_fault_domain_count` (Required) The number of fault domains that the availability set should span.  Must be between 1 and 3 (inclusive).
    - `platform_update_domain_count` (Required) The number of update domains that the availability set should span. Must be between 1 and 20 (inclusive).
    - `managed` (Required) Whether the availability set is managed or unmanaged.  Must be `true` for availability sets used with managed disks.
    EOT
}

variable "extensions" {
  type = list(object({
    name                       = string
    publisher                  = string
    type                       = string
    type_handler_version       = string
    auto_upgrade_minor_version = optional(bool, true)
    automatic_upgrade_enabled  = optional(bool, null)
    settings                   = optional(string, "{}")
    provision_after_extensions = optional(list(string), null)
    protected_settings_from_key_vault = optional(object({
      secret_url      = string
      source_vault_id = string
    }), null)
  }))
  default     = []
  description = <<-EOT
    (Optional) A list of extensions

    - `name` (Required) The name of the virtual machine extension peering. Changing this forces a new resource to be created.
    - `publisher` (Required) The publisher of the extension, available publishers can be found by using the Azure CLI. Changing this forces a new resource to be created.
    - `type` (Required) The type of extension, available types for a publisher can be found using the Azure CLI.
    - `type_handler_version` (Required) Specifies the version of the extension to use, available versions can be found using the Azure CLI.
    - `auto_upgrade_minor_version` (Optional) Should the latest version of the Extension be used at Deployment Time, if one is available? This won't auto-update the extension on existing installation. Defaults to `true`.
    - `automatic_upgrade_enabled` (Optional) Should the Extension be automatically updated whenever the Publisher releases a new version of this VM Extension?
    - `settings` (Optional) A map of settings passed to be passed into the extension. (This map is converted to JSON string in the module).
    - `provision_after_extensions` (Optional) Specifies the collection of extension names after which this extension needs to be provisioned.
    - `protected_settings_from_key_vault` (Optional) A protected_settings_from_key_vault block. Note: cannot be used with `extension_protected_settings` variable (they're mutually exclusive).
      - `secret_url` (Required) The Secret Identifier (URL) to a Key Vault secret which stores the protected settings as a JSON-encoded string. (e.g. `{"password": "myS3cReT"}`)
      - `source_vault_id` (Required) The ID of the source Key Vault.
    EOT
}

variable "extension_protected_settings" {
  type = list(object({
    extension_name = string
    value          = string
  }))
  sensitive   = true
  default     = []
  description = <<-EOT
    (Optional) Any protected settings to apply to an extension

    **Note:**
    Keys in the `value` map are notoriously case-sensitive. Required casing depends on the Extension being used (e.g. TitleCase vs snakeCase).
    Refer to the documentation for the specific VM Extension for more information.

      - `extension_name` (Required) The name of the extension to apply the protected settings to.
      - `value` (Required) A jsonencode()'d string of protected settings for the extension.
  EOT
}

variable "encryption_at_host_enabled" {
  type        = bool
  default     = true
  description = "(Optional) Should disks attached to this Virtual Machine Scale Set be encrypted by enabling Encryption at Host?."
}

variable "edge_zone" {
  type        = string
  default     = null
  description = "(Optional) Specifies the Edge Zone within the Azure Region where this Virtual Machine should exist. Changing this forces a new Virtual Machine to be created."
}

variable "boot_diagnostics" {
  type = object({
    enabled             = bool
    storage_account_uri = optional(string)
  })
  default = {
    enabled = true
  }
  description = <<-EOT
    (Optional) Boot diagnostic settings for the VM

    - `enabled` (Required) Should boot diagnostics be enabled? Possible values are `true` or `false`.
    - `storage_account_uri` (Optional) The URI of the storage account to use for boot diagnostics. If not provided, a managed storage account will be used.
    EOT
}

variable "license_type" {
  type        = string
  default     = "Windows_Server"
  description = <<-EOT
    (Optional) Specifies the type license to be used for the virtual machine.
    - For Windows: 'Windows_Client', 'Windows_Server', or null.
    - For Linux: 'RHEL_BYOS', 'RHEL_BASE', 'RHEL_EUS', 'RHEL_SAPAPPS', 'RHEL_SAPHA', 'RHEL_BASESAPAPPS', 'RHEL_BASESAPHA', 'SLES_BYOS', 'SLES_SAP', 'SLES_HPC', 'UBUNTU_PRO', or null.
  EOT

  validation {
    condition = (
      (var.os_type == "windows" && (var.license_type == "Windows_Client" || var.license_type == "Windows_Server" || var.license_type == null)) ||
      (var.os_type == "linux" && (var.license_type == "RHEL_BYOS" || var.license_type == "RHEL_BASE" || var.license_type == "RHEL_EUS" || var.license_type == "RHEL_SAPAPPS" || var.license_type == "RHEL_SAPHA" || var.license_type == "RHEL_BASESAPAPPS" ||
    var.license_type == "RHEL_BASESAPHA" || var.license_type == "SLES_BYOS" || var.license_type == "SLES_SAP" || var.license_type == "SLES_HPC" || var.license_type == "UBUNTU_PRO" || var.license_type == null)))
    error_message = "For Windows VMs, license_type must be 'Windows_Client', 'Windows_Server' or null. For Linux VMs, license_type must be one of: 'RHEL_BYOS', 'RHEL_BASE', 'RHEL_EUS', 'RHEL_SAPAPPS', 'RHEL_SAPHA', 'RHEL_BASESAPAPPS', 'RHEL_BASESAPHA', 'SLES_BYOS', 'SLES_SAP', 'SLES_HPC', 'UBUNTU_PRO', or null."
  }
}

variable "identity" {
  type = object({
    type         = string
    identity_ids = optional(list(string), [])
  })
  default = {
    type         = "SystemAssigned"
    identity_ids = []
  }
  description = <<-EOT
  (Optional) Specifies the type of Managed Service Identity (MSI) to be assigned to the virtual machine. 

  - `type` (Required) The type of Managed Service Identity to assign to the virtual machine. Possible values are 'SystemAssigned', 'UserAssigned', or 'SystemAssigned, UserAssigned'.
  - `identity_ids` (Optional) A list of User Assigned Managed Identity IDs to be assigned to the virtual machine. Required if `type` includes 'UserAssigned'.
  EOT
}

variable "timezone" {
  type        = string
  default     = "Pacific Standard Time"
  description = "(Optional) Windows Only. Specifies the Time Zone which should be used by the Virtual Machine, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Changing this forces a new resource to be created."
}

variable "backup_configuration" {
  type = object({
    recovery_vault_name                = string
    recovery_vault_resource_group_name = string
    policy_name                        = string
    included_disk_luns                 = optional(list(number))
    excluded_disk_luns                 = optional(list(number))
  })
  description = <<EOT
  (Optional) Configuration for Azure VM backup. 
  If this block is provided, VM backup will be enabled using the specified settings.
  - `recovery_vault_name`: (Required) Name of the existing Azure Recovery Services Vault.
  - `recovery_vault_resource_group_name`: (Required) Resource group name of the existing Azure Recovery Services Vault.
  - `policy_name`: (Required) Name of the existing VM Backup Policy.
  - `included_disk_luns`: (Optional) A list of LUNs of data disks to be included in the backup. Defaults to an empty list, meaning all data disks are candidates for backup (unless excluded).
  - `excluded_disk_luns`: (Optional) A list of LUNs of data disks to be excluded from the backup. Defaults to an empty list (no exclusions by default).
  EOT
  default     = null
}

variable "sql_vm" {
  type        = bool
  description = "(Optional) If set to true, applies a default data disks and exclusion list for common SQL Server. Defaults to false."
  default     = false
}

variable "dedicated_host_group_id" {
  type        = string
  default     = null
  description = "(Optional) The ID of a Dedicated Host where this machine should be run on. Conflicts with dedicated_host_group_id"
}

variable "dedicated_host_id" {
  type        = string
  default     = null
  description = "(Optional) The ID of a Dedicated Host Group that this Windows Virtual Machine should be run within. Conflicts with dedicated_host_id"
}
