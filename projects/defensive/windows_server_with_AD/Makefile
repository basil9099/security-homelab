# Homelab AD Makefile — thin convenience wrapper around Vagrant + Ansible.
# All config is declarative; these targets are just shortcuts.

PROJECT_DIR := $(abspath $(CURDIR))
VAGRANT_DIR := $(PROJECT_DIR)/vagrant
ANSIBLE_DIR := $(PROJECT_DIR)/ansible
PACKER_DIR  := $(PROJECT_DIR)/packer

# Default provider. Override with: make up PROVIDER=virtualbox
PROVIDER ?= vmware_desktop

.PHONY: help
help:
	@echo "Targets:"
	@echo "  collections   Install Ansible collections (microsoft.ad, ansible.windows, community.windows)"
	@echo "  up            Boot DC01 + WKSTN01 via Vagrant (runs provisioners)"
	@echo "  provision     Re-run all playbooks against the booted VMs"
	@echo "  users         Re-apply AD baseline (OUs, groups, users, GPOs) only"
	@echo "  smoke         Read-only smoke test of the AD baseline"
	@echo "  halt          Graceful shutdown"
	@echo "  destroy       Destroy all VMs (asks for confirmation)"
	@echo "  packer-build  Build the WS2022 base box from ISO (needs iso_url + iso_checksum)"
	@echo ""
	@echo "Override provider with PROVIDER=virtualbox (default: vmware_desktop)"

.PHONY: collections
collections:
	cd $(ANSIBLE_DIR) && ansible-galaxy collection install -r requirements.yml -p ./.collections

.PHONY: up
up: collections
	cd $(VAGRANT_DIR) && VAGRANT_DEFAULT_PROVIDER=$(PROVIDER) vagrant up

.PHONY: provision
provision:
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/site.yml

.PHONY: users
users:
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/ad_baseline.yml

.PHONY: smoke
smoke:
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/smoke.yml

.PHONY: halt
halt:
	cd $(VAGRANT_DIR) && vagrant halt

.PHONY: destroy
destroy:
	cd $(VAGRANT_DIR) && vagrant destroy

.PHONY: packer-build
packer-build:
	@test -n "$$iso_url" || (echo "Set iso_url=... and iso_checksum=sha256:..."; exit 1)
	cd $(PACKER_DIR) && packer init windows_server_2022.pkr.hcl && \
		packer build -var "iso_url=$$iso_url" -var "iso_checksum=$$iso_checksum" windows_server_2022.pkr.hcl

.PHONY: lint
lint:
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/site.yml --syntax-check && \
		ansible-playbook playbooks/smoke.yml --syntax-check
	cd $(PACKER_DIR) && packer validate windows_server_2022.pkr.hcl || true
