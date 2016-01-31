#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

"""
Ansible module to manage elasticsearch shield users
(c) 2016, Thierno IB. BARRY <ibrahima.br@gmail.com>
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

DOCUMENTATION = '''
---
module: elasticsearch_esusers
short_description: Manage Elasticsearch users in an esusers Realm
description:
    - Manages Elasticsearch users.
version_added: "2.1"
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
    roles:
        description:
            - Roles to be associated to the user. These are comma separated list of role
        required: False
        default: None
    state:
        description:
          - Whether the user should exist.  When C(absent), removes the user
        required: false
        default: present
        choices: [ "present", "absent" ]
    esusers_bin:
        description:
            - Location of the esusers binary
        required: False
        default: /usr/share/elasticsearch/bin/shield/esusers
    update_password:
        description:
          - C(always) update user password and roles.  C(on_create) will only set the password for newly created users
        required: false
        default: always
        choices: [ "always", "on_create" ]
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
- elasticsearch_esusers: state=present username="bob" password="123456" roles="admin, marvel"

# Delete a user to your cluster
- elasticsearch_esusers: state=absent username="bob"
'''

RETURN = '''
changed:
    description: whatever something changed by the module
    returned: success
    type: string
username:
    description: the username to be managed
    returned: success
    type: string
roles:
    description: roles to be addedd or removed
    returned: success
    type: string
state:
    description: the state for the managed user
    returned: success
    type: string
'''

class ESUsers(object):
    def __init__(self, module, esusers_bin):
        self.module = module
        self.esusers_bin = esusers_bin

    def _parse_user_roles(self, string):
        roles = string.replace('\n', ':').replace('*', '').replace(' ','').split(':')
        roles = roles[1]
        return sorted(roles.split(','))

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

    def user_add(self, username, password, roles):
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

    def user_mod(self, username, password, owned_roles, needed_roles):
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

def main():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(required=True),
            password=dict(default=None, no_log=True),
            roles=dict(required=True),
            state=dict(default="present", choices=["present", "absent"]),
            esusers_bin=dict(default="/usr/share/elasticsearch/bin/shield/esusers"),
            update_password=dict(default="always", choices=["always", "on_create"]),
            force=dict(default='no', type='bool')
        )
    )

    username = module.params["username"]
    password = module.params["password"]
    roles = module.params["roles"].replace(' ','')
    state = module.params["state"]
    esusers_bin = module.params["esusers_bin"]
    update_password = module.params["update_password"]
    force = module.params["force"]

    esusers = ESUsers(module, esusers_bin)

    if not esusers.is_esusers_bin_exists():
        module.fail_json(msg="esusers binary doesn't exist. Check if shield is installed")

    present, owned_roles = esusers.get_user(username)
    
    if state == "present":
        if password is None and (update_password == "always" or force):
            module.fail_json(msg="password parameter required when adding a user")

        if present:
            if update_password == "always" and not force:
                changed = esusers.user_mod(username, password, owned_roles, roles.split(','))
            elif force:
                changed = esusers.user_del(username)
                changed = esusers.user_add(username, password, roles)
            else:
                changed = False
        else:
            changed = esusers.user_add(username, password, roles)
    elif state == "absent":
        if present:
            changed = esusers.user_del(username)
        else:
            changed = False

    module.exit_json(changed=changed, username=username, roles=roles, state=state)

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()