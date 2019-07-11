# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import socket

from charmhelpers.core import hookenv

from charms.reactive import set_flag, clear_flag
from charms.reactive import Endpoint
from charms.reactive import when_not, when


class VaultKVRequires(Endpoint):

    @when('endpoint.{endpoint_name}.changed')
    def data_changed(self):
        if self.unit_role_id and self.unit_token and self.vault_url:
            set_flag(self.expand_name('{endpoint_name}.available'))
        else:
            clear_flag(self.expand_name('{endpoint_name}.available'))

    @when_not('endpoint.{endpoint_name}.joined')
    def broken(self):
        clear_flag(self.expand_name('{endpoint_name}.connected'))
        clear_flag(self.expand_name('{endpoint_name}.available'))

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        set_flag(self.expand_name('{endpoint_name}.connected'))

    @property
    def endpoint_address(self):
        """ Determine the local endpoint network address """
        try:
            return hookenv.network_get_primary_address(
                self.expand_name('{endpoint_name}')
            )
        except NotImplementedError:
            return hookenv.unit_private_ip()

    def request_secret_backend(self, name, isolated=True):
        """Request creation and access to a secret backend

        :param name: name of secret backend to create/access
        :type name: str
        :param isolated: enforce isolation in backend between units
        :type isolated: bool"""
        for relation in self.relations:
            relation.to_publish['secret_backend'] = name
            relation.to_publish['access_address'] = self.endpoint_address
            relation.to_publish['hostname'] = socket.gethostname()
            relation.to_publish['isolated'] = isolated
            relation.to_publish['unit_name'] = hookenv.local_unit()

    @property
    def unit_role_id(self):
        """Retrieve the AppRole ID for this application unit or None

        :returns role_id: AppRole ID for unit
        :rtype role_id: str"""
        role_key = '{}_role_id'.format(hookenv.local_unit())
        return self.all_joined_units.received.get(role_key)

    @property
    def unit_token(self):
        """Retrieve the one-shot token for secret_id retrieval for
        this application unit or None

        :returns token: Vault one-shot toekn for secret_id response
        :rtype token: str"""
        token_key = '{}_token'.format(hookenv.local_unit())
        return self.all_joined_units.received.get(token_key)

    @property
    def vault_url(self):
        """Retrieve the URL to access Vault

        :returns vault_url: URL to access vault
        :rtype vault_url: str"""
        return self.all_joined_units.received.get('vault_url')

    @property
    def vault_ca(self):
        """Retrieve the CA published by Vault

        :returns vault_ca: Vault CA Certificate data
        :rtype vault_ca: str"""
        encoded_ca = self.all_joined_units.received.get('vault_ca')
        if encoded_ca:
            return base64.b64decode(encoded_ca)
