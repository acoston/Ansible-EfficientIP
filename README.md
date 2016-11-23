# EfficientIP Ansible module
An EfficientIP Solidserver module for Ansible

## Disclaimer

This module is still in heavy developpment.
DO NOT USE IT (yet) in production environnement 

## Install

- put it in your Ansible module directory 
- you also need to install the "requests" py module

## Usage
### Task listing...
- ip_space_list
- ip_space_info
- ip_address_add [hostname, IPv4, Space ]
- ip_address_delete [IPv4, Space]

### via Playbooks 
```
  tasks:
  - name: list space
    eip:
     ipm_server=10.0.0.4
     ipm_username=ipmadmin
     ipm_password=admin
     ipm_action=ip_space_list
  - name: add IP on space
    eip:
     ipm_server=10.0.0.4
     ipm_username=ipmadmin
     ipm_password=admin
     ipm_action=ip_address_add
     ipm_space=NY_space
     ipm_ip_name=ansible999
     ipm_hostaddr='192.168.1.103'
  - name: properties of a space
    eip:
     ipm_server=10.0.0.4
     ipm_username=ipmadmin
     ipm_password=admin
     ipm_action=ip_space_info
     ipm_space_id=5
  - name: delete IP address
    eip:
     ipm_server=10.0.0.4
     ipm_username=ipmadmin
     ipm_password=admin
     ipm_action=ip_address_delete
     ipm_space=NY_space
     ipm_hostaddr='192.168.1.103'
```
