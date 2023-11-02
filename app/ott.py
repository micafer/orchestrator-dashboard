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
"""Class to manage data using One Time Tokens (OTT)."""
import hvac
from uuid import uuid4

class OneTimeTokenData():

    VAULT_LOCKER_MOUNT_POINT = "/cubbyhole/"

    def __init__(self, vault_url, role="", ttl=86400, num_uses=2):
        self.vault_url = vault_url
        self.role = role
        self.ttl = ttl
        self.num_uses = num_uses

    def _create(self, access_token):
        """
        Create a locker and return the locker token
        from fedcloudclient. Thanks ti @tdviet
        """
        client = hvac.Client(url=self.vault_url)
        client.auth.jwt.jwt_login(role=self.role, jwt=access_token)
        client.auth.token.renew_self(increment=self.ttl)
        locker_token = client.auth.token.create(
            policies=["default"], ttl=self.ttl, num_uses=self.num_uses, renewable=False
        )
        return locker_token["auth"]["client_token"]


    def locker_client(self, locker_token, command, path, data=None):
        """
        Manage locker data.
        from fedcloudclient. Thanks to @tdviet
        """
        client = hvac.Client(url=self.vault_url, token=locker_token)
        if command == "read_secret":
            resp = client.read(self.VAULT_LOCKER_MOUNT_POINT + path)
            return resp.get("data").get("data")
        elif command == "put":
            resp = client.write(self.VAULT_LOCKER_MOUNT_POINT + path, data=data)
            return None
        else:
            raise Exception(f"Invalid command {command}")
        

    def write_data(self, access_token, data):
        token = self._create(access_token)
        path = str(uuid4())
        self.locker_client(token, "put", path, data)
        return token, path

    def get_data(self, path, token):
        return self.locker_client(token, "read_secret", path)
