
#
# Copyright: Ansible Project
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: efficientip
version_added: "2.9"
short_description: Interface with EfficientIP
description:
   - "Manages domains and records via the EfficientIP Rest API
options:
  eip_server:
    description:
      - EfficientIP server URL
    required: true
    type: str
  eip_username:
    description:
      - EfficientIP user account
    required: true
    type: str
  eip_password:
    description:
      - EfficientIP user password
    required: true
    type: str
  record:
    description:
      - The full DNS record to create or delete
    type: str
  space:
    description:
      - EfficientIP space name or ID
      - If input "LIST" a list of spaces will be returned.
    type: str
  space_id:
    description:
      - EfficientIP space ID
    type: str
  subnet:
    description:
      - Subnet name
      - If input "LIST" a list of subnets will be returned.
    required: true
    type: str
  subnet_id:
    description:
      - Subnet ID
    type: str
  type:
    description:
      - The type of DNS record to create.
    choices: [ 'A', 'CNAME' ]
    type: str
    required: true
  hostaddr:
    description:
      - Record value (IP Address)
      - If input "FIND_FREE" one free IP address will be returned
    type: str
  macaddr:
    description:
      - MAC address
    type: str
  alias_fqdn:
    description:
      - reference for CNAME
    type: str
  alias_value:
    description:
      - Value for CNAME
    type: str
  alias_ttl:
    description:
      - TTL for CNAME
    type: str
  classparam:
    description:
      - Classparameter for entry
    type: str
  classname:
    description:
      - Classname for entry
    type: str
  state:
    description:
      -  whether the record should exist or not.
    choices: [ 'present', 'absent' ]
    default: present
    type: str
'''

EXAMPLES = '''
- name: list space
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    space: LIST

- name: list usable subnet from a space
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    subnet: LIST
    space: NY_space
    classparam: 'metadata1=somedata'
    -or-
    classname: myclass

- name: find one free IP address on a subnet
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    hostaddr: FIND_FREE
    subnet_id: 4

- name: add IP on space
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    type: A
    state: present
    space: NY_space
    record: test.mydomain.com
    hostaddr: 127.0.0.1

- name: delete IP on space
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    type: A
    state: absent
    space: NY_space
    hostaddr: 127.0.0.1

- name: add CNAME
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    type: CNAME
    state: present
    alias_fqdn: alias.mydomain.net
    alias_value: hostname.mydomain.net
    alias_ttl: 600

- name: delete CNAME
  efficientip:
    eip_server: server.mydomain.com
    eip_username: dummyusername
    eip_password: dummypassword
    type: CNAME
    state: absent
    alias_fqdn: alias.mydomain.net
    alias_value: hostname.mydomain.net
    alias_ttl: 600
'''

RETURN = r"""# """

import base64
import requests

from ansible.module_utils.basic import AnsibleModule

def req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring):

    try:
        session = requests.request(method, base_url + ipm_cmd, params=querystring, headers=ipm_auth_hdr, verify=False, timeout=10)
    except:
        try:
            if session:
                req_status_code = session.status_code
                req_output = {"error" : "EfficientIP Server unreachable"}
        except:
             req_output = {"error" : "EfficientIP Server unreachable"}

    req_status_code = session.status_code

    if req_status_code == 204:
        req_output = {"output" : "no data" }

    if req_status_code == 401:
        req_output = {"error" : "check EfficientIP Server credential" }

    if req_status_code == 400:
        req_output = {"error" : "check EfficientIP Server or parameter format" }

    if req_status_code == 500:
        req_output = {"error" : "something went wrong" }

    # status code handling: from there data are expected
    req_output = session.json()

    if req_status_code == 201:
        ipm_check=True
        ipm_changed=True

    elif req_status_code == 200:
        if ipm_cmd == 'rest/ip_delete' or ipm_cmd == 'rest/dns_rr_delete' :
            ipm_check=True
            ipm_changed=True
        else:
            ipm_check=True
            ipm_changed=False

    else:
        ipm_check=False
        ipm_changed=False

    return (req_output, ipm_check, ipm_changed)


def ip_space_list(base_url, ipm_auth_hdr):
    method = 'get'
    ipm_cmd = 'rest/ip_site_list'
    querystring = ''
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def ip_subnet_list(base_url, ipm_auth_hdr, space, classparam, classname):
    method = 'get'
    ipm_cmd = 'rest/ip_block_subnet_list'
    if classparam is not None:
        obj1, param1 = classparam.split('=')
        querystring = {'TAGS' : 'network.'+ obj1 +'' , 'WHERE' : 'site_name = \''+ space +'\' AND is_terminal = \'1\' AND tag_network_'+ obj1 +' = \''+ param1 +'\''}
    elif classname is not None:
        querystring = {'WHERE' : 'site_name = \''+ space +'\' AND is_terminal = \'1\' AND subnet_class_name = \''+ classname +'\''}
    else:
        querystring = {'WHERE' : 'site_name = \''+ space +'\' AND is_terminal = \'1\''}
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def ip_address_add(base_url, ipm_auth_hdr, space, record, hostaddr, macaddr, classparam, classname):
    method = 'post'
    ipm_cmd = 'rest/ip_add'
    querystring = {'site_name': space,'name': record,'hostaddr': hostaddr, 'mac_addr' : macaddr, 'ip_class_parameters' : classparam, 'ip_class_name': classname}
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def ip_address_delete(base_url, ipm_auth_hdr, space, hostaddr):
    method = 'delete'
    ipm_cmd = 'rest/ip_delete'
    querystring = {'site_name': space,'hostaddr': hostaddr}
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def ip_address_find_free(base_url, ipm_auth_hdr, subnet_id):
    method = 'get'
    ipm_cmd = 'rpc/ip_find_free_address'
    querystring =  {'subnet_id' : subnet_id, 'max_find' : '1'}
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def dns_cname_add(base_url, ipm_auth_hdr, alias_fqdn, alias_value, alias_ttl):
    method = 'post'
    ipm_cmd = 'rest/dns_rr_add'
    querystring = {'rr_type': 'cname','rr_name': alias_fqdn, 'value1' : alias_value, 'rr_ttl' : alias_ttl }
    return req(base_url, ipm_auth_hdr, method, ipm_cmd, querystring)

def dns_cname_delete(base_url, ipm_auth_hdr, alias_fqdn, alias_value):
    method = 'delete'
    ipm_cmd = 'rest/dns_rr_delete'
    querystring = {'rr_name': alias_fqdn, 'value1' : alias_value}
    return req(base_url, ipm_auth_hdr, method, ipm_cmd ,querystring)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            eip_server=dict(type='str', required=True),
            eip_username=dict(type='str', required=True),
            eip_password=dict(type='str',required=True, no_log=True),
            record=dict(type='str'),
            space=dict(type='str'),
            space_id=dict(type='str'),
            subnet=dict(type='str'),
            subnet_id=dict(type='str'),
            type=dict(type='str', choices=['A', 'CNAME'], required=True),
            hostaddr=dict(type='str'),
            macaddr=dict(type='str'),
            alias_fqdn=dict(type='str'),
            alias_value=dict(type='str'),
            alias_ttl=dict(type='str'),
            classparam=dict(type='str'),
            classname=dict(type='str'),
            state=dict(type='str', choices=['present', 'absent'], default='present')
        )
    )

    eip_server = module.params.get('eip_server')
    eip_username = module.params.get('eip_username')
    eip_password = module.params.get('eip_password')
    record = module.params.get('record')
    space = module.params.get('space')
    space_id = module.params.get('space_id')
    subnet = module.params.get('subnet')
    subnet_id = module.params.get('subnet_id')
    type=module.params.get('type')
    hostaddr = module.params.get('hostaddr')
    macaddr = module.params.get('macaddr')
    alias_fqdn = module.params.get('alias_fqdn')
    alias_value = module.params.get('alias_value')
    alias_ttl = module.params.get('alias_ttl')
    classparam = module.params.get('classparam')
    classname = module.params.get('classname')
    state = module.params.get('state')

    ipm_auth_hdr = {
    'X-IPM-Username': base64.b64encode(eip_username),
    'X-IPM-Password': base64.b64encode(eip_password)
    }

    base_url = "https://{host}/".format(host=eip_server)


    try:

        if space == 'LIST':
            result = ip_space_list(base_url, ipm_auth_hdr)
            if result[1] == True:
                data = []
                for rows in result[0]:
                    data.append({ 'space_id': rows['site_id'], 'space' :  rows['site_name'] })
                req_output = { 'output' : data }
                module.exit_json(changed=result[2], result=req_output)
            else:
                raise Exception()

        if subnet == 'LIST':
            result = ip_subnet_list(base_url, ipm_auth_hdr, space, classparam, classname)
            if result[1] == True:
                data = []
                for rows in result[0]:
                     raw_network = int(rows['start_ip_addr'],16)
                     network = '.'.join( [ str((raw_network >> 8*i) % 256)  for i in [3,2,1,0] ])
                     data.append({ 'ipm_subnet_size' : rows['subnet_size'], 'ipm_subnet_addr' : network, 'ipm_subnet_id' : rows['subnet_id'], 'ipm_subnet' :  rows['subnet_name'] })
                req_output = { 'output' : data }
                module.exit_json(changed=result[2], result=req_output)
            else:
                raise Exception()

        if type == 'A' and state == 'present':
            result = ip_address_add(base_url, ipm_auth_hdr, space, record, hostaddr, macaddr, classparam, classname)
            if result[1] == True:
                req_output = {"output" : "entry added" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False:
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()

        if type == 'A' and state == 'absent':
            result = ip_address_delete(base_url, ipm_auth_hdr, space, hostaddr)
            if result[1] == True:
                req_output = {"output" : "entry deleted" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False:
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()

        if hostaddr == 'FIND_FREE':
            result = ip_address_find_free(base_url, ipm_auth_hdr, subnet_id)
            if result[1] == True:
                req_output = { 'output' : result[0][0]["hostaddr"]}
                module.exit_json(changed=result[2], result=req_output)
            else:
                raise Exception()

        if type == 'CNAME' and state == 'present' :
            result = dns_cname_add(base_url, ipm_auth_hdr, alias_fqdn, alias_value ,alias_ttl)
            if result[1] == True:
                req_output = {"output" : "entry added" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False:
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()

        if type == 'CNAME' and state == 'absent':
            result = dns_cname_delete(base_url, ipm_auth_hdr, alias_fqdn, alias_value)
            if result[1] == True:
                req_output = {"output" : "entry deleted" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False:
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()

    except Exception as kaboom:
                module.fail_json(msg=str(kaboom))


if __name__ == '__main__':
        main()

