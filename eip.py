#!/usr/bin/python

# ==============================================================

#   WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP
#   WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP

# ==============================================================

DOCUMENTATION = '''
---
module: EfficientIP 
version_added: "0.8"
short_description: Ansible interface to the REST/RPC EfficientIP SOLIDServer API
description:
  - works with SOLIDserver 6.0.x (don't even try on earlier version, please upgrade)
  - works with Ansible 2.4 and Ansible 2.5 (python2.7)
  - supports simple action to make ansible/efficientip working together (update IPAM/update cname in DNS)
  - supports EIP class parameters when adding an IP or searching a Subnet (only one class parameter supported for searching)
'''

import base64
import requests


# ==============================================================
# EfficientIP solidserver init...

class Eip(object):
    def __init__(self,module,ipm_server,ipm_username, ipm_password):
        self.module = module
        self.ipm_auth_hdr = {
            'X-IPM-Username': base64.b64encode(ipm_username),
            'X-IPM-Password': base64.b64encode(ipm_password)
        }
        self.base_url = "https://{host}/".format(host=ipm_server)


# ==============================================================
# connexion and request

    def req(self,method,ipm_cmd,querystring):

        # secure/unsecure ssl switch to come...
        requests.packages.urllib3.disable_warnings()

        try:
            session = requests.request(method, self.base_url + ipm_cmd, params=querystring, headers=self.ipm_auth_hdr, verify=False, timeout=10)
        except:
            try:
                if session:
                    req_status_code = session.status_code
                    req_output = {"error" : "SOLIDServer unreachable"}
                    self.module.exit_json( unreachable=True, result=req_output)
            except:
                req_output = {"error" : "SOLIDServer unreachable"}
                self.module.exit_json(changed=False, unreachable=True, result=req_output)

        req_status_code = session.status_code

# ==============================================================
# IPAM API json output control

        # Basic status code handling without data to ouput
        if req_status_code == 204:
            req_output = {"output" : "no data" }
            self.module.exit_json(result=req_output)

        if req_status_code == 401:
            req_output = {"error" : "check SOLIDServer credential" }
            self.module.exit_json( failed=True, result=req_output )

        if req_status_code == 400:
            req_output = {"error" : "check SOLIDServer or parameter format" }
            self.module.exit_json( failed=True, result=req_output )

        if req_status_code == 500:
            req_output = {"error" : "something went wrong" }
            self.module.exit_json( failed=True, result=req_output )

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
        
        return (req_output,ipm_check,ipm_changed)


# ==============================================================
# ansible ipm_action/IPAM API translation and control

    def ip_space_list(self):
       method = 'get'
       ipm_cmd = 'rest/ip_site_list'
       querystring = ''
       return self.req(method,ipm_cmd,querystring)

    def ip_subnet_list(self,ipm_space,ipm_classparam,ipm_classname):
       method = 'get'
       ipm_cmd = 'rest/ip_block_subnet_list'
       if ipm_classparam is not None:
        obj1, param1 = ipm_classparam.split('=')
        querystring = {'TAGS' : 'network.'+ obj1 +'' , 'WHERE' : 'site_name = \''+ ipm_space +'\' AND is_terminal = \'1\' AND tag_network_'+ obj1 +' = \''+ param1 +'\''}
       elif ipm_classname is not None:
        querystring = {'WHERE' : 'site_name = \''+ ipm_space +'\' AND is_terminal = \'1\' AND subnet_class_name = \''+ ipm_classname +'\''}
       else:
        querystring = {'WHERE' : 'site_name = \''+ ipm_space +'\' AND is_terminal = \'1\''}
       return self.req(method,ipm_cmd,querystring)

    def ip_address_add(self,ipm_space,ipm_hostname,ipm_hostaddr,ipm_macaddr,ipm_classparam,ipm_classname):
       method = 'post'
       ipm_cmd = 'rest/ip_add'
       querystring = {'site_name': ipm_space,'name': ipm_hostname,'hostaddr': ipm_hostaddr, 'mac_addr' : ipm_macaddr, 'ip_class_parameters' : ipm_classparam, 'ip_class_name': ipm_classname}
       return self.req(method,ipm_cmd,querystring)

    def ip_address_delete(self,ipm_space,ipm_hostaddr):
       method = 'delete'
       ipm_cmd = 'rest/ip_delete'
       querystring = {'site_name': ipm_space,'hostaddr': ipm_hostaddr}
       return self.req(method,ipm_cmd,querystring)

    def ip_address_find_free(self,ipm_subnet_id):
       method = 'get'
       ipm_cmd = 'rpc/ip_find_free_address'
       querystring =  {'subnet_id' : ipm_subnet_id, 'max_find' : '1'} 
       return self.req(method,ipm_cmd,querystring)

    def dns_cname_add(self,ipm_alias_fqdn,ipm_alias_value,ipm_alias_ttl):
       method = 'post'
       ipm_cmd = 'rest/dns_rr_add'
       querystring = {'rr_type': 'cname','rr_name': ipm_alias_fqdn, 'value1' : ipm_alias_value, 'rr_ttl' : ipm_alias_ttl }
       return self.req(method,ipm_cmd,querystring)

    def dns_cname_delete(self,ipm_alias_fqdn,ipm_alias_value):
       method = 'delete'
       ipm_cmd = 'rest/dns_rr_delete'
       querystring = {'rr_name': ipm_alias_fqdn, 'value1' : ipm_alias_value}
       return self.req(method,ipm_cmd,querystring)


# ==============================================================
# main

# check mode untested
# ssl secure mode not tested and switch not implemented


def main():
    module = AnsibleModule(
        argument_spec = dict(
            insecure         = dict(required=False),
            ipm_server       = dict(required=True),
            ipm_username     = dict(required=True),
            ipm_password     = dict(required=True),
            ipm_space        = dict(required=False),
            ipm_space_id     = dict(required=False),
            ipm_subnet       = dict(required=False),
            ipm_subnet_id    = dict(required=False),
            ipm_hostname     = dict(required=False),
            ipm_hostaddr     = dict(required=False),
            ipm_macaddr      = dict(required=False),
    	    ipm_alias_fqdn   = dict(required=False),
            ipm_alias_value  = dict(required=False),
            ipm_alias_ttl    = dict(required=False),
            ipm_classparam   = dict(required=False),
            ipm_classname    = dict(required=False),
            ipm_action       = dict(required=True, choices=['ip_space_list',
                                                            'ip_subnet_list',
                                                            'ip_address_add',
                                                            'ip_address_delete',
                                                            'ip_address_find_free',
                                                            'dns_cname_delete',
							    'dns_cname_add'])
        ), supports_check_mode=False
    )   

    insecure        = module.params["insecure"]
    ipm_server      = module.params["ipm_server"]
    ipm_username    = module.params["ipm_username"]
    ipm_password    = module.params["ipm_password"]
    ipm_space       = module.params["ipm_space"]
    ipm_space_id    = module.params["ipm_space_id"]
    ipm_subnet      = module.params["ipm_subnet"]
    ipm_subnet_id   = module.params["ipm_subnet_id"]
    ipm_hostname    = module.params["ipm_hostname"]
    ipm_hostaddr    = module.params["ipm_hostaddr"]
    ipm_macaddr     = module.params["ipm_macaddr"]   
    ipm_alias_fqdn  = module.params["ipm_alias_fqdn"]
    ipm_alias_value = module.params["ipm_alias_value"]
    ipm_alias_ttl   = module.params["ipm_alias_ttl"]
    ipm_classparam  = module.params["ipm_classparam"]
    ipm_classname   = module.params["ipm_classname"]   
    ipm_action = module.params["ipm_action"]   

    try:
        eip = Eip(module, ipm_server, ipm_username, ipm_password)

        if ipm_action == 'ip_space_list':
            result = eip.ip_space_list()
            if result[1] == True:
                data = []
                for rows in result[0]:
                    data.append({ 'ipm_space_id': rows['site_id'], 'ipm_space' :  rows['site_name'] })
                req_output = { 'output' : data } 
                module.exit_json(changed=result[2], result=req_output)
            else:
                raise Exception()

        if ipm_action == 'ip_subnet_list':
            result = eip.ip_subnet_list(ipm_space,ipm_classparam,ipm_classname)
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

        if ipm_action == 'ip_address_add':
            result = eip.ip_address_add(ipm_space,ipm_hostname,ipm_hostaddr,ipm_macaddr,ipm_classparam,ipm_classname)
            if result[1] == True:
                req_output = {"output" : "entry added" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False: 
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()
    
        if ipm_action == 'ip_address_delete':
            result = eip.ip_address_delete(ipm_space,ipm_hostaddr)
            if result[1] == True:
                req_output = {"output" : "entry deleted" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False: 
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()

        if ipm_action == 'ip_address_find_free':
            result = eip.ip_address_find_free(ipm_subnet_id)
            if result[1] == True:
                req_output = { 'output' : result[0][0]["hostaddr"]}
                module.exit_json(changed=result[2], result=req_output)
            else:
                raise Exception()

        if ipm_action == 'dns_cname_add':
            result = eip.dns_cname_add(ipm_alias_fqdn,ipm_alias_value,ipm_alias_ttl)
            if result[1] == True:
                req_output = {"output" : "entry added" }
                module.exit_json(changed=result[2], result=req_output)
            elif result[1] == False: 
                req_output = {"output" : result[0] }
                module.exit_json(changed=result[2], result=req_output, failed=True)
            else:
                raise Exception()
    
        if ipm_action == 'dns_cname_delete':
            result = eip.dns_cname_delete(ipm_alias_fqdn,ipm_alias_value)
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


# ==============================================================
# import module snippets
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
        main()

