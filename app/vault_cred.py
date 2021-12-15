#
# IM - Infrastructure Manager Dashboard
# Copyright (C) 2020 - GRyCAP - Universitat Politecnica de Valencia
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Class to manage user credentials using a Vault backend."""
import hvac
import requests
from flask import json
from app.cred import Credentials


class VaultCredentials(Credentials):

    def __init__(self, vault_url, role=None, key=None):
        self.vault_path = "credentials/"
        self.role = role
        self.client = None
        super().__init__(vault_url, key)

    def _login(self, token):
        login_url = self.url + '/v1/auth/jwt/login'

        if self.role:
            data = '{ "jwt": "' + token + '", "role": "' + self.role + '" }'
        else:
            data = '{ "jwt": "' + token + '" }'

        response = requests.post(login_url, data=data, verify=False, timeout=5)

        if not response.ok:
            raise Exception("Error getting Vault token: {} - {}".format(response.status_code, response.text))

        deserialized_response = response.json()

        vault_auth_token = deserialized_response["auth"]["client_token"]
        vault_entity_id = deserialized_response["auth"]["entity_id"]

        self.client = hvac.Client(url=self.url, token=vault_auth_token)
        if not self.client.is_authenticated():
            raise Exception("Error authenticating against Vault with token: {}".format(vault_auth_token))

        return vault_entity_id

    def get_creds(self, token, enabled=None):
        vault_entity_id = self._login(token)
        data = []

        try:
            creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
            for cred_json in creds["data"].values():
                new_item = self._decrypt(json.loads(cred_json))
                if enabled is None or enabled == new_item['enabled']:
                    data.append(new_item)
        except Exception:
            pass

        return data

    def get_cred(self, serviceid, token):
        vault_entity_id = self._login(token)
        creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        if serviceid in creds["data"]:
            return json.loads(self._decrypt(creds["data"][serviceid]))
        else:
            return None

    def write_creds(self, serviceid, token, data, insert=False):
        vault_entity_id = self._login(token)

        try:
            creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        except Exception:
            creds = None

        if creds:
            old_data = creds["data"]
            if serviceid in creds["data"]:
                if insert:
                    raise Exception("Duplicated Credential ID!.")
                service_data = self._decrypt(json.loads(creds["data"][serviceid]))
                service_data.update(data)
                creds["data"][serviceid] = service_data
            else:
                old_data[serviceid] = data
                old_data[serviceid]['enabled'] = 1
        else:
            old_data = {serviceid: data}
            old_data[serviceid]['enabled'] = 1

        old_data[serviceid] = self._encrypt(json.dumps(old_data[serviceid]))
        response = self.client.secrets.kv.v1.create_or_update_secret(vault_entity_id,
                                                                     old_data,
                                                                     mount_point=self.vault_path)

        response.raise_for_status()

    def delete_cred(self, serviceid, token):
        vault_entity_id = self._login(token)
        creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        if serviceid in creds["data"]:
            del creds["data"][serviceid]
            if creds["data"]:
                response = self.client.secrets.kv.v1.create_or_update_secret(vault_entity_id,
                                                                            creds["data"],
                                                                            method="PUT",
                                                                            mount_point=self.vault_path)
            else:
                response = self.client.secrets.kv.v1.delete_secret(vault_entity_id,
                                                                   mount_point=self.vault_path)
            response.raise_for_status()

    def enable_cred(self, serviceid, token, enable=1):
        vault_entity_id = self._login(token)
        creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        if serviceid in creds["data"]:
            service_data = json.loads(self._decrypt(creds["data"][serviceid]))
            service_data["enabled"] = enable
            creds["data"][serviceid] = self._encrypt(json.dumps(service_data))
            response = self.client.secrets.kv.v1.create_or_update_secret(vault_entity_id,
                                                                         creds["data"],
                                                                         method="PUT",
                                                                         mount_point=self.vault_path)
            response.raise_for_status()
