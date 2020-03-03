[![Build status](https://travis-ci.org/acoston/Ansible-EfficientIP.svg)](https://travis-ci.org/acoston/Ansible-EfficientIP)

# EfficientIP Ansible module
An EfficientIP Solidserver module for Ansible

## Disclaimer

This module is still in heavy developpment.

## Install

- put it in your Ansible module directory 
- you also need to install the "requests" py module

## Usage
### Task listing...
- ip_space_list
- ip_subnet_list space [ one_class_parameter | class_name ]  
- ip_address_find_free subnet_id, begin_addr
- ip_address_add hostname, ipv4, space [ mac_addr, class_name, class_parameters ]
- ip_address_delete ipv4, space
- dns_cname_add alias_fqdn, hostname, ttl
- dns_cname_delete alias_fqdn


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
     ipm_classparam='metadata1=somedata'
     -or- 
     ipm_classname=myclass
    register: eip

  - name: find one free IP address on a subnet
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_find_free
     ipm_subnet_id=4
     ipm_begin_addr=192.168.15.20
    register: eip

  - name: add IP on space
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_add
     ipm_space=NY_space
     ipm_hostname=hello.mydomain.net
     ipm_classparam='metadata1=somedata&metadata2=somedata&[...]'
     ipm_classname=myclass
     ipm_hostaddr='{{ eip.result.output }}'

  - name: delete IP address
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_admin_user_here>
     ipm_password=<your_ipm_admin_password_here>
     ipm_action=ip_address_delete
     ipm_space=NY_space
     ipm_hostaddr=192.168.1.103

  - name: add CNAME
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_user_here>
     ipm_password=<your_ipm_pwd_here>
     ipm_action=dns_cname_add
     ipm_alias_fqdn=alias.mydomain.net
     ipm_alias_value=hostname.mydomain.net
     ipm_alias_ttl=600

  - name: delete CNAME
    eip:
     ipm_server=<your_ipm_ipaddress_or_hostname_here>
     ipm_username=<your_ipm_user_here>
     ipm_password=<your_ipm_pwd_here>
     ipm_action=dns_cname_delete
     ipm_alias_fqdn=alias.mydomain.net
```
