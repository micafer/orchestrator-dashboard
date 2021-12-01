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
"""
Class to manage user credentials.

Temporary will migrate DB creds to Vault.
"""

from app.db_cred import DBCredentials
from app.vault_cred import VaultCredentials


class Credentials:

    def __init__(self, vault_url, db_url, key=None, role=None):
        self.db_client = DBCredentials(db_url, key)
        self.vault_client = None
        if vault_url:
            self.vault_client = VaultCredentials(vault_url, role)

    def get_creds(self, userid, enabled=None):
        res = []
        (token, db_userid) = userid
        if self.vault_client:
            res = self.vault_client.get_creds(token, enabled)

        db_res = self.db_client.get_creds(db_userid, enabled)
        if db_res:
            res.extend(db_res)
            if self.vault_client:
                # Move the data to the Vault server
                for cred in db_res:
                    try:
                        self.vault_client.write_creds(cred["id"], token, cred)
                        self.db_client.delete_cred(cred["id"], db_userid)
                    except Exception:
                        pass

        return res

    def get_cred(self, serviceid, userid):
        res = None
        (token, db_userid) = userid
        if self.vault_client:
            res = self.vault_client.get_cred(serviceid, token)
        if res:
            return res
        else:
            return self.db_client.get_cred(serviceid, db_userid)

    def write_creds(self, serviceid, userid, data, insert=False):
        (token, db_userid) = userid
        if self.vault_client:
            self.vault_client.write_creds(serviceid, token, data)
        else:
            self.db_client.write_creds(serviceid, db_userid, data, insert)

    def delete_cred(self, serviceid, userid):
        (token, db_userid) = userid
        if self.vault_client:
            self.vault_client.delete_cred(serviceid, token)
        self.db_client.delete_cred(serviceid, db_userid)

    def enable_cred(self, serviceid, userid, enable=1):
        (token, db_userid) = userid
        if self.vault_client:
            self.vault_client.enable_cred(serviceid, token, int(enable))
        else:
            self.db_client.enable_cred(serviceid, db_userid, int(enable))

    def validate_cred(self, userid, new_cred):
        """ Validates the credential with the availabe ones.
        Returns: 0 if no problem, 1 if it is duplicated, or 2 if the site is the same
        """
        cred_id = None
        if isinstance(new_cred, str):
            cred_id = new_cred
            new_cred = self.get_cred(cred_id, userid)

        no_host_types = ["EC2", "GCE", "Azure", "linode", "Orange"]
        for cred in self.get_creds(userid):
            if cred["enabled"] and cred["type"] == new_cred["type"] and (not cred_id or cred_id != cred['id']):
                isequal = True
                for k in cred.keys():
                    if k not in ["id", "enabled"]:
                        if cred[k] != new_cred[k]:
                            isequal = False
                            break
                if isequal:
                    return 1, "Duplicated"

                if new_cred["type"] in no_host_types:
                    return 2, ("There is already a " + new_cred["type"] + " Credentials " +
                               " It may cause problems authenticating with the Provider." +
                               " Please disable/remove one of the Credentials.")
                else:
                    if new_cred["host"] and cred["host"] == new_cred["host"]:
                        return 2, ("This site has already a Credential with same site URL." +
                                   " It may cause problems authenticating with the Site." +
                                   " Please disable/remove one of the Credentials.")

        return 0, ""
