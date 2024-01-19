# Copyright 2022 Red Hat, Inc.
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
import time

import yaml
from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: vault_load_parsed_secrets
short_description: Loads secrets into the HashiCorp Vault
version_added: "2.50"
author: "Martin Jackson"
description:
    - Takes parsed secrets objects and vault policies (as delivered by parse_secrets_info) and runs the commands to
      load them into a vault instance. The relevent metadata will exist in the parsed secrets object. Returns count
      of secrets injected.
options:
  parsed_secrets:
    description:
      - A structure containing the secrets, fields, and their metadata
    required: true
    type: dict
  vault_policies:
    description:
      - Vault policies to inject into the instance.
    required: true
    type: dict
  namespace:
    description:
      - Namespace where the vault is running
    required: false
    type: str
    default: vault
  pod:
    description:
      - Name of the vault pod to use to inject secrets
    required: false
    type: str
    default: vault-0
  check_missing_secrets:
    description:
      - Validate the ~/values-secret.yaml file against the top-level
        values-secret-template.yaml and error out if secrets are missing
    required: false
    type: bool
    default: False
"""

RETURN = """
"""

EXAMPLES = """
- name: Loads secrets file into the vault of a cluster
  vault_load_secrets:
    values_secrets: ~/values-secret.yaml
"""


class VaultSecretLoader:
    def __init__(
        self,
        module,
        parsed_secrets,
        vault_policies,
        namespace,
        pod,
        check_missing_secrets,
    ):
        self.module = module
        self.parsed_secrets = parsed_secrets
        self.vault_policies = vault_policies
        self.namespace = namespace
        self.pod = pod
        self.check_missing_secrets = check_missing_secrets

    def _run_command(self, command, attempts=1, sleep=3, checkrc=True):
        """
        Runs a command on the host ansible is running on. A failing command
        will raise an exception in this function directly (due to check=True)

        Parameters:
          command(str): The command to be run.
          attempts(int): Number of times to retry in case of Error (defaults to 1)
          sleep(int): Number of seconds to wait in between retry attempts (defaults to 3s)

        Returns:
          ret(subprocess.CompletedProcess): The return value from run()
        """
        for attempt in range(attempts):
            ret = self.module.run_command(
                command,
                check_rc=checkrc,
                use_unsafe_shell=True,
                environ_update=os.environ.copy(),
            )
            if ret[0] == 0:
                return ret
            if attempt >= attempts - 1:
                return ret
            time.sleep(sleep)

    def load_vault(self):
        injected_secret_count = 0

        self.inject_vault_policies()

        for secret_name, secret in self.parsed_secrets.items():
            pass

        return injected_secret_count

    def inject_secret(self, secret_name, secret):
        pass

    def inject_vault_policies(self):
        pass


def run(module):
    """Main ansible module entry point"""
    results = dict(changed=False)

    args = module.params

    vault_policies = args.get("vault_policies")
    parsed_secrets = args.get("parsed_secrets")
    namespace = args.get("namespace", "vault")
    pod = args.get("pod", "vault-0")
    check_missing_secrets = args.get("check_missing_secrets")

    loader = VaultSecretLoader(
        module, parsed_secrets, vault_policies, namespace, pod, check_missing_secrets
    )

    nr_secrets = loader.load_vault()

    results["failed"] = False
    results["changed"] = True
    results["msg"] = f"{nr_secrets} secrets injected"
    module.exit_json(**results)


def main():
    """Main entry point where the AnsibleModule class is instantiated"""
    module = AnsibleModule(
        argument_spec=yaml.safe_load(DOCUMENTATION)["options"],
        supports_check_mode=False,
    )
    run(module)


if __name__ == "__main__":
    main()
