#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage elasticsearch shield role
(c) 2016, Thierno IB. BARRY @barryib
Sponsored by Polyconseil http://polyconseil.fr.

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

import urlparse
try:
    import json
except ImportError:
    import simplejson as json

DOCUMENTATION = '''
---
module: elasticsearch_shield_role
short_description: Manage Elasticsearch Shield role in an esnative Realm
description:
    - Manages Elasticsearch Shield role.
version_added: "2.2"
author: Thierno IB. BARRY (@barryib)
options:
    name:
        description:
            - Name of the role to add or remove
        required: True
    cluster:
        description:
            - The cluster privileges. (Required when adding a user)
        required: False
        default: None
    indices:
        description:
            - Indices privileges. (Required when adding a user)
        required: False
        default: None
    run_as:
        description:
            - Run AS privileges.
        required: False
        default: []
    state:
        description:
          - Whether the user should exist.  When C(absent), removes the user
        required: false
        default: present
        choices: [ "present", "absent" ]
    elasticsearch_api:
        description:
            - The Elasticsearch api endpoint. Used in an C(esnative) realm
        required: False
        default: http://localhost:9200
    shield_realm:
        description:
            - The shield realm to manage the user on. Refer to the shield documentation for details
        required: false
        default: esnative
        choices: [ "esnative", "esusers" ]
'''

EXAMPLES = '''
# Adds a role to your cluster
- elasticsearch_shield_role:
    name: my_kibana_user
    cluster: ['monitor']
    indices:
      - { 'names': '*', 'privileges': ['view_index_metadata', 'read'] }
      - { 'names': '.kibana*', 'privileges': ['all'] }
    state: present

# Delete a role from your cluster
- elasticsearch_shield_role:
    name: my_kibana_user
    state: absent
'''

RETURN = '''
name:
    description: the role name to manage
    returned: success
    type: string
cluster:
    description: cluster privileges
    returned: success
    type: list
indices:
    description: indices privileges
    returned: success
    type: list
run_as:
    description: run_as privileges
    returned: success
    type: list
state:
    description: the state for the managed user
    returned: success
    type: string
'''

class ShieldRoleBase(object):
    def __init__(self, module, shield_realm):
        self.module = module
        self.shield_realm = shield_realm

    def get_role(self):
        raise NotImplementedError('Must be implemented by a sub-class')

    def role_del(self):
        raise NotImplementedError('Must be implemented by a sub-class')

    def role_add(self):
        raise NotImplementedError('Must be implemented by a sub-class')

class ShieldNativeRole(ShieldRoleBase):
    def __init__(self, module, elasticsearch_api, socket_timeout=30):
        ShieldRoleBase.__init__(self, module, 'esnative')
        self.elasticsearch_api = elasticsearch_api
        self.body_format = 'json'
        self.headers = { 'Content-Type': 'application/json' }
        self.socket_timeout = socket_timeout

    def _do_request(self, url, method, body=None):
        if body:
            body = json.dumps(body, sort_keys=True)

        resp, info = fetch_url(self.module, url, data=body, method=method, headers=self.headers, timeout=self.socket_timeout)  
        return resp, info

    def get_role(self, name):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/role/%s' % name)
        resp, info = self._do_request(url, 'GET')
        if int(info['status']) == 200:
            try:
                content = json.loads(resp.read())
            except AttributeError:
                # there was no content, but the error read()
                # may have been stored in the info as 'body'
                content = json.loads(info.pop('body', ''))

            return True, content[name]
        # role doesn't exist
        elif int(info['status']) == 404:
            return False, None
        
        self.module.fail_json(msg=info)


    def role_del(self, name):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/role/%s' % name)
        resp, info = self._do_request(url, 'DELETE')
        if int(info['status']) == 200:
            return True
        
        self.module.fail_json(msg=info)

    def role_add(self, name, cluster, indices, run_as):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/role/%s' % name)
        body = {}
        
        body['cluster'] = cluster
        body['indices'] = indices
        if run_as:
            body['run_as'] = run_as
        
        resp, info = self._do_request(url, 'POST', body)

        if int(info['status']) == 200:
            return True
        
        self.module.fail_json(msg=info)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            cluster=dict(required=False, type='list'),
            indices=dict(required=False, type='list'),
            run_as=dict(required=False, default=[], type='list'),
            url_username = dict(required=False, default=None, aliases=['admin_user']),
            url_password = dict(required=False, default=None, no_log=True, aliases=['admin_password']),
            state=dict(default='present', choices=['present', 'absent']),
            elasticsearch_api=dict(default='http://localhost:9200')
        )
    )

    name                = module.params['name']
    cluster             = module.params['cluster']
    indices             = module.params['indices']
    run_as              = module.params['run_as']
    state               = module.params['state']
    elasticsearch_api   = module.params['elasticsearch_api']

    shield_role = ShieldNativeRole(module, elasticsearch_api)

    present, role = shield_role.get_role(name)

    if state == 'present':
        if not cluster or not indices:
            module.fail_json(msg="cluster and indices are required to add role")

        if present:
            dict_cmp = cmp(role, {'cluster': cluster, 'indices': indices, 'run_as': run_as})
            if dict_cmp == 0:
                changed = False
            else:
                changed = shield_role.role_add(name, cluster, indices, run_as)
        else:
            changed = shield_role.role_add(name, cluster, indices, run_as)
    elif state == 'absent':
        if present:
            changed = shield_role.role_del(name)
        else:
            changed = False

    module.exit_json(changed=changed, name=name, cluster=cluster, indices=indices, state=state)

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
