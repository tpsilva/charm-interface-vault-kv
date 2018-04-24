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

from charms.reactive import set_flag, clear_flag
from charms.reactive import Endpoint
from charms.reactive import when_any, when_not, when


class VaultKVProvides(Endpoint):

    @when_any('endpoint.{endpoint_name}.changed.access_address',
              'endpoint.{endpoint_name}.changed.secret_backend',
              'endpoint.{endpoint_name}.changed.hostname',
              'endpoint.{endpoint_name}.changed.isolated')
    def new_secret_backend(self):
        # New backend request detected, set flags and clear changed flags
        set_flag(self.expand_name('endpoint.{endpoint_name}.new-request'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.changed.access_address'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.changed.secret_backend'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.changed.hostname'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.changed.isolated'))

    @when_not('endpoint.{endpoint_name}.joined')
    def broken(self):
        clear_flag(self.expand_name('endpoint.{endpoint_name}.new-request'))
        clear_flag(self.expand_name('{endpoint_name}.connected'))

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        set_flag(self.expand_name('{endpoint_name}.connected'))

    def publish_url(self, vault_url):
        """ Publish URL for Vault to all Relations """
        for relation in self.relations:
            relation.to_publish['vault_url'] = vault_url

    def publish_ca(self, vault_ca):
        """ Publish SSL CA for Vault to all Relations """
        for relation in self.relations:
            relation.to_publish['vault_ca'] = vault_ca

    def set_role_id(self, unit, role_id):
        """ Set the AppRole ID for a specific remote unit """
        unit.relation.to_publish['{}_role_id'.format(unit.unit_name)] = role_id

    def requests(self):
        """ Retrieve full set of setup requests from all remote units """
        requests = []
        for relation in self.relations:
            for unit in relation.units:
                access_address = unit.received['access_address']
                secret_backend = unit.received['secret_backend']
                hostname = unit.received['hostname']
                isolated = unit.received['isolated']
                if not (secret_backend and access_address
                        and hostname and isolated is not None):
                    continue
                requests.append({
                    'unit': unit,
                    'access_address': access_address,
                    'secret_backend': secret_backend,
                    'hostname': hostname,
                    'isolated': isolated,
                })
        return requests