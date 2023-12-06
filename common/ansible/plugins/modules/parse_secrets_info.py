# Copyright 2022,2023 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Ansible plugin module that loads secrets from a yaml file and pushes them
inside the HashiCorp Vault in an OCP cluster. The values-secrets.yaml file is
expected to be in the following format:
---
# version is optional. When not specified it is assumed it is 1.0
version: 1.0

# These secrets will be pushed in the vault at secret/hub/test The vault will
# have secret/hub/test with secret1 and secret2 as keys with their associated
# values (secrets)
secrets:
  test:
    secret1: foo
    secret2: bar

# This will create the vault key secret/hub/testfoo which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files:
  testfoo: ~/ca.crt

# These secrets will be pushed in the vault at secret/region1/test The vault will
# have secret/region1/test with secret1 and secret2 as keys with their associated
# values (secrets)
secrets.region1:
  test:
    secret1: foo1
    secret2: bar1

# This will create the vault key secret/region2/testbar which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files.region2:
  testbar: ~/ca.crt
"""

import os

import yaml
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.load_secrets_common import get_version
from ansible.module_utils.parse_secrets_v3 import ParseSecretsV3

ANSIBLE_METADATA = {
    "metadata_version": "1.2",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: parse_secrets_info
short_description: Parses a Validated Patterns Secrets file for later loading
version_added: "2.50"
author: "Martin Jackson"
description:
  - Takes a values-secret.yaml file, parses and returns values for secrets loading. The goal here is to do all the work of reading and interpreting the file and resolving the content pointers (that is, creating content where it is given) such that that content is then available for secrets vaults to load. It does not attempt to load the content or interpret the content beyond the conventions of the file format. (So, it knows how to retrieve ini-keys, about paths, and about base64 but leaves interaction with backends to backend-specific code.
options:
  values_secrets_plaintext:
    description:
      - The unencrypted content of the values-secrets file
    required: true
    type: str
"""

RETURN = """
"""

EXAMPLES = """
- name: Loads secrets file into the vault of a cluster
  parse_secrets_info:
    values_secrets_plaintext: '{{ <unencrypted content> }}'
"""

def run(module):
    """Main ansible module entry point"""
    results = dict(changed=False)

    args = module.params
    values_secrets_plaintext = args.get("values_secrets_plaintext", "")

    syaml = yaml.safe_load(values_secrets_plaintext)

    if syaml is None:
        syaml = {}

    parsed_secret_obj = ParseSecretsV3(module, syaml)
    parsed_secret_obj.parse()

    results["failed"] = False
    results["changed"] = False
#    results["syaml"] = syaml
#    results["values_secrets_plaintext"] = values_secrets_plaintext
    results["parsed_secrets"] = parsed_secret_obj.parsed_secrets
    results["kubernetes_secret_objects"] = parsed_secret_obj.kubernetes_secret_objects

    module.exit_json(**results)

def main():
    """Main entry point where the AnsibleModule class is instantiated"""
    module = AnsibleModule(
        argument_spec=yaml.safe_load(DOCUMENTATION)["options"],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
