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
"""Class to manage user credentials."""
from flask import json
import hvac
import requests

class VaultCredentials():

    def __init__(self, vault_url):
        self.vault_url = vault_url
        self.vault_path = "credentials/"
        self.role = None
        self.client = None

    def _login(self, token):
        login_url = self.vault_url + '/v1/auth/jwt/login'
        
        if self.role:
            data = '{ "jwt": "' + token +  '", "role": "' + self.role + '" }'
        else:
            data = '{ "jwt": "' + token +  '" }'
        
        response = requests.post(login_url, data=data, verify=False)
        
        if not response.ok:
            raise Exception("Error getting Vault token: {} - {}".format(response.status_code, response.text) )
        
        deserialized_response = json.loads(response.text)

        vault_auth_token = deserialized_response["auth"]["client_token"]
        vault_entity_id = deserialized_response["auth"]["entity_id"]
        
        self.client = hvac.Client(url=self.vault_url,token=vault_auth_token)
        if not self.client.is_authenticated():
            raise Exception("Error authenticating against Vault with token: {}".format(vault_auth_token))
        
        return vault_entity_id

    def get_creds(self, token, enabled=None):
        vault_entity_id = self._login(token)
        data = []

        creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        for cred_json in creds["data"].values():
            new_item = json.loads(cred_json)
            if enabled is None or enabled == new_item['enabled']:
                data.append(new_item)

        return data

    def get_cred(self, serviceid, token):
        vault_entity_id = self._login(token)
        creds = self.client.secrets.kv.v1.read_secret(path=vault_entity_id, mount_point=self.vault_path)
        if serviceid in creds["data"]:
            return json.loads(creds["data"][serviceid])
        else:
            return None