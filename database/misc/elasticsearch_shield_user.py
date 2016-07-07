#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage elasticsearch shield users
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

import os
import urlparse
try:
    import json
except ImportError:
    import simplejson as json

DOCUMENTATION = '''
---
module: elasticsearch_shield_user
short_description: Manage Elasticsearch users in an esusers or esnative Realm
description:
    - Manages Elasticsearch users.
version_added: "2.2"
author: Thierno IB. BARRY (@barryib)
options:
    username:
        description:
            - Name of the user to add or remove
        required: True
    password:
        description:
            - Set the user's password. (Required when adding a user)
        required: False
        default: None
    admin_user:
        description:
            - Name of the admin user to authenticate with to add user
        required: False
    admin_password:
        description:
            - The admin user's password
        required: False
    roles:
        description:
            - Roles to be associated to the user. These are list of role
        required: True
        default: None
    state:
        description:
          - Whether the user should exist.  When C(absent), removes the user
        required: false
        default: present
        choices: [ "present", "absent" ]
    esusers_bin:
        description:
            - Location of the esusers binary. Used in an C(esusers) realm
        required: False
        default: /usr/share/elasticsearch/bin/shield/esusers
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
    update_password:
        description:
          - C(always) update user password and roles.  C(on_create) will only set the password for newly created users
        required: false
        default: always
        choices: [ "always", "on_create" ]
    extra_attr:
        description:
          - Dict to refer to the user extra attibute like C(full_name), C(email) and C(metadata). Refer to the shield documentation for detail
        required: false
        default: {}
    force:
        description:
          - Deletes and recreates the user. If set to C(yes) the C(update_password) will be skipped
        required: false
        default: no
        choices: [ "yes", "no" ]
'''

EXAMPLES = '''
# Adds a user to your cluster
- elasticsearch_esusers: state=present username="bob" password="123456"

# Add a user to your cluster and associate him with roles
- elasticsearch_esusers: state=present username="bob" password="123456" roles=["admin", "marvel"]

# Delete a user to your cluster
- elasticsearch_esusers: state=absent username="bob"
'''

RETURN = '''
username:
    description: the username to be managed
    returned: success
    type: string
roles:
    description: roles to be addedd or removed
    returned: success
    type: string
extra_attr:
    description: extra_attr to be addedd or removed
    returned: success
    type: string
state:
    description: the state for the managed user
    returned: success
    type: string
'''

class ShieldUserBase(object):
    def __init__(self, module, shield_realm):
        self.module = module
        self.shield_realm = shield_realm

    def _compare_user_roles(self, owned_roles, needed_roles):
        roles_to_rem = []
        roles_to_add = []
        
        for role in owned_roles:
            if role not in needed_roles:
                roles_to_rem.append(role)
        
        for role in needed_roles:
            if role not in owned_roles:
                roles_to_add.append(role)
    
        return roles_to_add, roles_to_rem

    def get_user(self):
        raise NotImplementedError('Must be implemented by a sub-class')

    def user_del(self):
        raise NotImplementedError('Must be implemented by a sub-class')

    def user_add(self):
        raise NotImplementedError('Must be implemented by a sub-class')

    def user_mod(self):
        raise NotImplementedError('Must be implemented by a sub-class')

class ShieldESUsers(ShieldUserBase):
    def __init__(self, module, shield_realm, esusers_bin):
        ShieldUserBase.__init__(self, module, shield_realm)
        self.esusers_bin = esusers_bin
        if not self.is_esusers_bin_exists():
            module.fail_json(msg='esusers binary doesn\'t exist. Check if shield is installed')

    def _parse_user_roles(self, string):
        roles = string.replace('\n', ':').replace('*', '').replace(' ','').split(':')
        roles = roles[1]
        return sorted(roles.split(','))

    def is_esusers_bin_exists(self):
        return os.path.exists(self.esusers_bin)
    
    def get_user(self, username):
        cmd_args = [self.esusers_bin, "list", username]
        cmd = " ".join(cmd_args)
        rc, out, err = self.module.run_command(cmd)
        # User exist
        if rc == 0:
            return True, self._parse_user_roles(out)
        # User doesn't exist
        elif rc == 67:
            return False, None
        # Otherwise throw an error
        self.module.fail_json(msg=out)

    def user_del(self, username):
        cmd_args = [self.esusers_bin, "userdel", username]
        cmd = " ".join(cmd_args)
        rc, out, err = self.module.run_command(cmd)
        if rc == 0:
            return True

        self.module.fail_json(msg=out)

    def user_add(self, username, password, roles, extra_attr):
        cmd_args = [self.esusers_bin, "useradd", username]
        if password:
            cmd_args.append("-p %s" % password)
        if roles:
            cmd_args.append("-r '%s'" % roles)

        cmd = " ".join(cmd_args)
        rc, out, err = self.module.run_command(cmd)
        if rc == 0:
            return True

        self.module.fail_json(msg=out)

    def user_mod(self, username, password, owned_roles, needed_roles, extra_attr):
        roles_to_add, roles_to_rem = self._compare_user_roles(owned_roles, needed_roles)
        
        # Update password
        if password:
            cmd_args = [self.esusers_bin, "passwd", username]
            cmd_args.append("-p %s" % password)
            cmd = " ".join(cmd_args)
            rc, out, err = self.module.run_command(cmd)
            if rc != 0:
                self.module.fail_json(msg=out)
        
        # Add roles
        if roles_to_add:
            cmd_args = [self.esusers_bin, "roles", username]
            cmd_args.append("-a '%s'" % ",".join(roles_to_add))
            cmd = " ".join(cmd_args)
            rc, out, err = self.module.run_command(cmd)
            if rc != 0:
                self.module.fail_json(msg=out)

        # Remove roles
        if roles_to_rem:
            cmd_args = [self.esusers_bin, "roles", username]
            cmd_args.append("-r '%s'" % ",".join(roles_to_rem))
            cmd = " ".join(cmd_args)
            rc, out, err = self.module.run_command(cmd)
            if rc != 0:
                self.module.fail_json(msg=out)

        return True

class ShieldNativeUser(ShieldUserBase):
    def __init__(self, module, shield_realm, elasticsearch_api, socket_timeout=30):
        ShieldUserBase.__init__(self, module, shield_realm)
        self.elasticsearch_api = elasticsearch_api
        self.body_format = 'json'
        self.headers = { 'Content-Type': 'application/json' }
        self.socket_timeout = socket_timeout

    def _do_request(self, url, method, body=None):
        if body:
            body = json.dumps(body)

        resp, info = fetch_url(self.module, url, data=body, method=method, headers=self.headers, timeout=self.socket_timeout)  
        return resp, info

    def get_user(self, username):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/user/%s' % username)
        resp, info = self._do_request(url, 'GET')
        if int(info['status']) == 200:
            try:
                content = json.loads(resp.read())
            except AttributeError:
                # there was no content, but the error read()
                # may have been stored in the info as 'body'
                content = json.loads(info.pop('body', ''))

            return True, content[username]['roles']
        
        # User doesn't exist
        elif int(info['status']) == 404:
            return False, None
        
        self.module.fail_json(msg=info)


    def user_del(self, username):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/user/%s' % username)
        resp, info = self._do_request(url, 'DELETE')
        if int(info['status']) == 200:
            return True
        
        self.module.fail_json(msg=info)

    def user_add(self, username, password, roles, extra_attr):
        url = urlparse.urljoin(self.elasticsearch_api, '/_shield/user/%s' % username)
        body = {}
        
        body['password'] = password
        body['roles'] = roles
        if extra_attr:
            body.update(extra_attr)
        
        resp, info = self._do_request(url, 'POST', body)

        if int(info['status']) == 200:
            return True
        
        self.module.fail_json(msg=info)

    def user_mod(self, username, password, owned_roles, needed_roles, extra_attr):
        return self.user_add(username, password, needed_roles, extra_attr)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(required=True),
            password=dict(required=False, no_log=True),
            url_username = dict(required=False, default=None, aliases=['admin_user']),
            url_password = dict(required=False, default=None, no_log=True, aliases=['admin_password']),
            roles=dict(required=True, type='list'),
            state=dict(default='present', choices=['present', 'absent']),
            esusers_bin=dict(default='/usr/share/elasticsearch/bin/shield/esusers'),
            elasticsearch_api=dict(default='http://localhost:9200'),
            shield_realm=dict(default='esnative', choices=['esnative', 'esusers']),
            update_password=dict(default='always', choices=['always', 'on_create']),
            extra_attr = dict(required=False, type='dict', default={}),
            force=dict(default='no', type='bool')
        )
    )

    username            = module.params['username']
    password            = module.params['password']
    roles               = module.params['roles']
    state               = module.params['state']
    esusers_bin         = module.params['esusers_bin']
    elasticsearch_api   = module.params['elasticsearch_api']
    shield_realm        = module.params['shield_realm']
    update_password     = module.params['update_password']
    extra_attr          = module.params['extra_attr']
    force               = module.params['force']

    if shield_realm == 'esnative':
        shield_user = ShieldNativeUser(module, shield_realm, elasticsearch_api)
    elif shield_realm == 'esusers':
        shield_user = ShieldESUsers(module, shield_realm, esusers_bin)

    present, owned_roles = shield_user.get_user(username)

    if state == 'present':
        if present:
            if password is None and (update_password == "always" or force):
                module.fail_json(msg="password parameter required when adding a user")

            if update_password == 'always' and not force:
                changed = shield_user.user_mod(username, password, owned_roles, roles, extra_attr)
            elif force:
                changed = shield_user.user_del(username)
                changed = shield_user.user_add(username, password, roles, extra_attr)
            else:
                changed = False
        else:
            changed = shield_user.user_add(username, password, roles, extra_attr)
    elif state == 'absent':
        if present:
            changed = shield_user.user_del(username)
        else:
            changed = False

    module.exit_json(changed=changed, user=username, roles=roles, extra_attr=extra_attr, state=state)

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
