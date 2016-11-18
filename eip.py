#!/usr/bin/python

# ==============================================================

#   WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP WIP

#   FOR TESTING ONLY DO NOT USE IN PRODUCTION ENVIRONNEMENT

#    ansible-playbook test.yml -M path_to_eip_module/ -vvv

# ==============================================================

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
        self.rest_url = "https://{host}/rest/".format(host=ipm_server)


# ==============================================================
# connexion and request

    def req(self,method,ipm_cmd,querystring):

        # secure/unsecure ssl switch to come...
        requests.packages.urllib3.disable_warnings()

        try:
            session = requests.request(method, self.rest_url + ipm_cmd, params=querystring, headers=self.ipm_auth_hdr, verify=False, timeout=1)
            req_status_code = session.status_code
            req_output = session.json()
        except:
            req_status_code = session.status_code
            if req_status_code != 204:
                req_error = {"solidserver" : "unreachable"}
                self.module.exit_json(changed=False, unreachable=True, Failed=True, result=req_error)
            else:
                req_output = {"entry deleted" : "true" }

# ==============================================================
# IPAM API json output control

# http code 201 created on add /204 no content on del/ 400 on rep del
# errno 1/errno 0/errno XXXX/category/errmesg/severity/ret_oid, etc....
# first try, still not working on ip_space_list/ip_space_info
# with delete no content...= exception.
# changed = True/False
# unreachable = True/False
# failed = True/False

        if req_status_code == 204:
            ipm_check=True
            ipm_changed=True

        elif req_status_code == 200:
            ipm_errno = req_output[0]['errno']
            if ipm_errno == '0': #voodoo here
                ipm_check=True
                ipm_changed=False
            else:
                ipm_check=False
                ipm_changed=False
        
        elif req_status_code == 201:
            ipm_errno = req_output[0]['errno']
            if ipm_errno == 1:  #voodoo here 
                ipm_check=True
                ipm_changed=True
            else:
                ipm_check=False
                ipm_changed=False
        
        else:
            ipm_check=False
            ipm_changed=False
        
        return (req_output,ipm_check,ipm_changed)


# ==============================================================
# ansible ipm_action/IPAM API translation and control

# not yet very usefull need -vvv with ansible-playbook to show the info
    def ip_space_list(self):
       method = 'get'
       ipm_cmd = 'ip_site_list'
       querystring = ''
       return self.req(method,ipm_cmd,querystring)

# not yet very usefull need -vvv with ansible-playbook to show the info
    def ip_space_info(self, ipm_space_id):
       method = 'get'
       ipm_cmd = 'ip_site_info'
       querystring = {'site_id': ipm_space_id}
       return self.req(method,ipm_cmd,querystring)

    def ip_address_add(self,ipm_space,ipm_ip_name,ipm_hostaddr):
       method = 'post'
       ipm_cmd = 'ip_add'
       querystring = {'site_name': ipm_space,'ip_name': ipm_ip_name,'hostaddr': ipm_hostaddr}
       return self.req(method,ipm_cmd,querystring)

    def ip_address_delete(self,ipm_space,ipm_hostaddr):
       method = 'delete'
       ipm_cmd = 'ip_delete'
       querystring = {'site_name': ipm_space,'hostaddr': ipm_hostaddr}
       return self.req(method,ipm_cmd,querystring)



# ==============================================================
# main

# check mode untested
# ssl secure mode not tested and switch not implemented
# ip_address_find_free and lot of others not implemented


def main():
    module = AnsibleModule(
        argument_spec = dict(
            insecure         = dict(required=False),
            ipm_server       = dict(required=True),
            ipm_username     = dict(required=True),
            ipm_password     = dict(required=True),
            ipm_space        = dict(required=False),
            ipm_subnet       = dict(required=False),
            ipm_ip_name      = dict(required=False),
            ipm_hostaddr     = dict(required=False),
            ipm_space_id     = dict(required=False),
            ipm_action       = dict(required=True, choices=['ip_space_list',
                                                            'ip_space_info',
                                                            'ip_address_add',
                                                            'ip_address_delete',
                                                            'ip_address_find_free'])
        ), supports_check_mode=False
    )   

    insecure        = module.params["insecure"]
    ipm_server      = module.params["ipm_server"]
    ipm_username    = module.params["ipm_username"]
    ipm_password    = module.params["ipm_password"]
    ipm_space       = module.params["ipm_space"]
    ipm_subnet      = module.params["ipm_subnet"]
    ipm_ip_name     = module.params["ipm_ip_name"]
    ipm_hostaddr    = module.params["ipm_hostaddr"]
    ipm_space_id    = module.params["ipm_space_id"]
    ipm_action      = module.params["ipm_action"]

    try:
        eip = Eip(module, ipm_server, ipm_username, ipm_password)

        if ipm_action == 'ip_space_list':
            result = eip.ip_space_list()
            if result[1] == True:
                module.exit_json(changed=result[2], result=result[0])
            else:
                raise Exception()

        if ipm_action == 'ip_space_info':
            result = eip.ip_space_info(ipm_space_id)
            if result[1] == True:
                module.exit_json(changed=result[2], result=result[0])
            else:
                raise Exception()

        if ipm_action == 'ip_address_add':
            result = eip.ip_address_add(ipm_space,ipm_ip_name,ipm_hostaddr)
            if result[1] == True:
                module.exit_json(changed=result[2], result=result[0])
            elif result[1] == False: 
                module.exit_json(changed=result[2], result=result[0], failed=True)
            else:
                raise Exception()
    
        if ipm_action == 'ip_address_delete':
            result = eip.ip_address_delete(ipm_space,ipm_hostaddr)
            if result[1] == True:
                module.exit_json(changed=result[2], result=result[0])
            elif result[1] == False: 
                module.exit_json(changed=result[2], result=result[0], failed=True)
            else:
                raise Exception()

    except Exception as kaboom:
                module.fail_json(msg=str(kaboom))


# ==============================================================
# import module snippets
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
        main()

