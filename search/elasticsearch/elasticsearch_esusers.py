#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

"""
Ansible module to manage elasticsearch shield users
(c) 2016, Thierno IB. BARRY <ibrahima.br@gmail.com>
# Sponsored by Polyconseil http://polyconseil.fr.

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
          - Whether the user should exist.  When C(absent), removes the user.
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
          - C(always) will delete user and recreate it.  C(on_create) will only set the password for newly created users.
        required: false
        default: always
        choices: ['always', 'on_create']
'''

EXAMPLES = '''
# Adds a user to your cluster
- elasticsearch_esusers: state=present username="bob" password="123456"

# Add a user to your cluster and associate him with roles
- elasticsearch_esusers: state=present username="bob" password="123456" roles="admin, marvel"

# Delete a user to your cluster
- elasticsearch_esusers: state=absent username="bob"
'''


def is_esusers_bin_exists(esusers_bin_path):
    return os.path.exists(esusers_bin_path)

def main():

    package_state_map = dict(
        present="useradd",
        absent="userdel"
    )

    module = AnsibleModule(
        argument_spec=dict(
            username=dict(required=True),
            password=dict(default=None, no_log=True),
            roles=dict(required=True),
            state=dict(default="present", choices=package_state_map.keys()),
            esusers_bin=dict(default="/usr/share/elasticsearch/bin/shield/esusers"),
            update_password=dict(default="always", choices=["always", "on_create"])
        )
    )

    username = module.params["username"]
    password = module.params["password"]
    roles = module.params["roles"]
    state = module.params["state"]
    esusers_bin = module.params["esusers_bin"]
    update_password = module.params["update_password"]

    if not is_esusers_bin_exists(esusers_bin):
        module.fail_json(msg="esusers binary doesn't exist. Check if shield is installed")

    rc, out, err = module.run_command(esusers_bin + " list " + username)
    if rc == 0:
        present = True
    else:
        present = False

    # skip if the state is correct
    if (present and state == "present" and update_password == "on_create") or (state == "absent" and not present):
        module.exit_json(changed=False, username=username)

    if (password is None and update_password == "always"):
        module.fail_json(msg="password parameter required when adding a user")
    
    if (present and update_password == "always"):
        cmd_args = [esusers_bin, package_state_map["absent"], username]
        cmd = " ".join(cmd_args)
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            module.fail_json(cmd=cmd, msg=out)

    cmd_args = [esusers_bin, package_state_map[state], username]

    if state == "present":
        if password:
            cmd_args.append("-p %s" % password)

        if roles:
            cmd_args.append("-r %s" % roles)

    cmd = " ".join(cmd_args)
    rc, out, err = module.run_command(cmd)
    if rc != 0:
        module.fail_json(cmd=cmd, msg=out)

    module.exit_json(changed=True, cmd=cmd, username=username, roles=roles, state=state, stdout=out, stderr=err)

from ansible.module_utils.basic import *

main()