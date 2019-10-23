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

from charmhelpers.contrib.network.ip import (
    is_address_in_network,
    resolve_network_cidr,
)
from charmhelpers.core.hookenv import (
    network_get_primary_address,
)


class VaultKVProvides(Endpoint):

    @when_any('endpoint.{endpoint_name}.changed.access_address',
              'endpoint.{endpoint_name}.changed.secret_backend',
              'endpoint.{endpoint_name}.changed.hostname',
              'endpoint.{endpoint_name}.changed.isolated')
    def new_secret_backend(self):
        # New backend request detected, set flags and clear changed flags
        set_flag(self.expand_name('endpoint.{endpoint_name}.new-request'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.access_address'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.secret_backend'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.hostname'))
        clear_flag(self.expand_name('endpoint.{endpoint_name}.'
                                    'changed.isolated'))

    @when_not('endpoint.{endpoint_name}.joined')
    def broken(self):
        clear_flag(self.expand_name('endpoint.{endpoint_name}.new-request'))
        clear_flag(self.expand_name('{endpoint_name}.connected'))

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        set_flag(self.expand_name('{endpoint_name}.connected'))

    def publish_url(self, vault_url, remote_binding=None):
        """ Publish URL for Vault to all Relations

        :param vault_url: api url used by remote client to speak to vault.
        :param remote_binding: if provided, remote units not using this
                               binding will be ignored.
        """
        for relation in self.relations:
            if remote_binding:
                units = relation.units
                if units:
                    addr = units[0].received['ingress-address'] or \
                        units[0].received['access_address']
                    bound_cidr = resolve_network_cidr(
                        network_get_primary_address(remote_binding)
                    )
                    if not (addr and is_address_in_network(bound_cidr, addr)):
                        continue

            relation.to_publish['vault_url'] = vault_url

    def publish_ca(self, vault_ca):
        """ Publish SSL CA for Vault to all Relations """
        for relation in self.relations:
            relation.to_publish['vault_ca'] = vault_ca

    @when_not('leadership.is_leader')
    def clear_role_id(self):
        for relation in self.relations:
            units = relation.units
            if units:
                for unit in units:
                    role_id_key = '{}_role_id'.format(unit.unit_name)
                    token_key = '{}_token'.format(unit.unit_name)
                    unit.relation.to_publish_raw[role_id_key] = None
                    unit.relation.to_publish_raw[token_key] = None

    def set_role_id(self, unit, role_id, token):
        """ Set the AppRole ID and token for out-of-band Secret ID retrieval
        for a specific remote unit """
        # for cmr we will need to the other end to provide their unit name
        # expicitly.
        unit_name = unit.received.get('unit_name') or unit.unit_name
        unit.relation.to_publish['{}_role_id'.format(unit_name)] = role_id
        unit.relation.to_publish['{}_token'.format(unit_name)] = token

    def requests(self):
        """ Retrieve full set of setup requests from all remote units """
        requests = []
        for relation in self.relations:
            for unit in relation.units:
                access_address = unit.received['access_address']
                ingress_address = unit.received['ingress-address']
                secret_backend = unit.received['secret_backend']
                hostname = unit.received['hostname']
                isolated = unit.received['isolated']
                if not (secret_backend and access_address and
                        hostname and isolated is not None):
                    continue
                requests.append({
                    'unit': unit,
                    'access_address': access_address,
                    'ingress_address': ingress_address,
                    'secret_backend': secret_backend,
                    'hostname': hostname,
                    'isolated': isolated,
                })
        return requests
