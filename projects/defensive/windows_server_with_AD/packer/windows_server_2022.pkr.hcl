# Builds a reusable Windows Server 2022 Vagrant box with WinRM pre-enabled.
# Packer is optional — the Vagrantfile defaults to a public box. Use this template
# when you want a clean, locally-vetted base image with only the trust you audited.
#
# Usage:
#   packer init windows_server_2022.pkr.hcl
#   packer build -var 'iso_url=./iso/en-us_windows_server_2022.iso' \
#                -var 'iso_checksum=sha256:...' \
#                windows_server_2022.pkr.hcl

packer {
  required_plugins {
    vmware = {
      version = ">= 1.0.11"
      source  = "github.com/hashicorp/vmware"
    }
    virtualbox = {
      version = ">= 1.0.5"
      source  = "github.com/hashicorp/virtualbox"
    }
    vagrant = {
      version = ">= 1.1.3"
      source  = "github.com/hashicorp/vagrant"
    }
  }
}

variable "iso_url"        { type = string }
variable "iso_checksum"   { type = string }
variable "winrm_user"     { type = string  default = "vagrant" }
variable "winrm_password" { type = string  default = "vagrant" sensitive = true }
variable "disk_size_mb"   { type = number  default = 61440 }
variable "memory_mb"      { type = number  default = 4096 }
variable "cpus"           { type = number  default = 2 }

source "vmware-iso" "ws2022" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  guest_os_type    = "windows9srv-64"
  vm_name          = "ws2022-homelab"
  disk_size        = var.disk_size_mb
  memory           = var.memory_mb
  cpus             = var.cpus
  communicator     = "winrm"
  winrm_username   = var.winrm_user
  winrm_password   = var.winrm_password
  winrm_timeout    = "6h"
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer shutdown\""
  floppy_files = [
    "./autounattend.xml",
    "./scripts/enable-winrm.ps1",
    "./scripts/install-updates.ps1",
  ]
}

source "virtualbox-iso" "ws2022" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  guest_os_type    = "Windows2022_64"
  vm_name          = "ws2022-homelab"
  disk_size        = var.disk_size_mb
  memory           = var.memory_mb
  cpus             = var.cpus
  communicator     = "winrm"
  winrm_username   = var.winrm_user
  winrm_password   = var.winrm_password
  winrm_timeout    = "6h"
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer shutdown\""
  floppy_files = [
    "./autounattend.xml",
    "./scripts/enable-winrm.ps1",
    "./scripts/install-updates.ps1",
  ]
  guest_additions_mode = "disable"
}

build {
  name    = "ws2022-homelab"
  sources = [
    "source.vmware-iso.ws2022",
    "source.virtualbox-iso.ws2022",
  ]

  provisioner "powershell" {
    scripts = [
      "./scripts/enable-winrm.ps1",
      "./scripts/install-updates.ps1",
    ]
  }

  post-processor "vagrant" {
    keep_input_artifact = false
    output              = "ws2022-homelab-{{.Provider}}.box"
  }
}
