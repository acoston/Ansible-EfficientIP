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
- ip_subnet_list [space] 
- ip_address_find_free [subnet_id]
- ip_address_add [hostname, ipv4, space ]
- ip_address_delete [ipv4, space]

### via Playbooks 
```
  tasks:
  - name: list space
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_space_list

  - name: list usable subnet from a space
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_subnet_list
     ipm_space=NY_space

  - name: find one free IP address on a subnet
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_find_free
     ipm_subnet_id=4

  - name: add IP on space
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_add
     ipm_space=NY_space
     ipm_hostname=hello-ansible
     ipm_hostaddr='192.168.1.103'

  - name: delete IP address
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_delete
     ipm_space=NY_space
     ipm_hostaddr='192.168.1.103'
```
