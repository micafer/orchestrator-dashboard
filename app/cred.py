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


class Credentials:

    def __init__(self, url):
        self.url = url

    def get_creds(self, userid, enabled=None):
        raise NotImplementedError("Should have implemented this")

    def get_cred(self, serviceid, userid):
        raise NotImplementedError("Should have implemented this")

    def write_creds(self, serviceid, userid, data, insert=False):
        raise NotImplementedError("Should have implemented this")

    def delete_cred(self, serviceid, userid):
        raise NotImplementedError("Should have implemented this")

    def enable_cred(self, serviceid, userid, enable=1):
        raise NotImplementedError("Should have implemented this")

    def validate_cred(self, userid, new_cred):
        """ Validates the credential with the availabe ones.
        Returns: 0 if no problem, 1 if it is duplicated, or 2 if the site is the same
        """
        cred_id = None
        if isinstance(new_cred, str):
            cred_id = new_cred
            new_cred = self.get_cred(cred_id, userid)

        no_host_types = ["EC2", "GCE", "Azure", "linode", "Orange"]
        for cred in self.get_creds(userid, 1):
            if cred["type"] == new_cred["type"] and (not cred_id or cred_id != cred['id']):
                isequal = True
                if new_cred["id"] == cred["id"]:
                    return 1, ("Duplicated ID.")
                for k in cred.keys():
                    if k not in ["id", "enabled"]:
                        if k not in new_cred or cred[k] != new_cred[k]:
                            isequal = False
                            break
                if isequal:
                    return 1, "Credentials already available."

                if new_cred["type"] in no_host_types:
                    return 2, ("There is already a " + new_cred["type"] + " Credentials " +
                               " It may cause problems authenticating with the Provider." +
                               " Please disable/remove one of the Credentials.")
                elif new_cred["type"] not in ['EGI', 'OpenStack', 'fedcloud']:  # these types has no problem
                    if new_cred["host"] and cred["host"] == new_cred["host"]:
                        return 2, ("This site has already a Credential with same site URL." +
                                   " It may cause problems authenticating with the Site." +
                                   " Please disable/remove one of the Credentials.")

        return 0, ""
