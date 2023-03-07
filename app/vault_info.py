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
"""Class to manage External Vault Info using a DB backend."""
from app.db import DataBase


class VaultInfo():

    def __init__(self, url):
        self.url = url

    def _get_db(self):
        db = DataBase(self.url)
        if db.connect():
            if not db.table_exists("vault_info"):
                db.execute("CREATE TABLE vault_info(userid VARCHAR(255) PRIMARY KEY, url VARCHAR(255), "
                            "mount_point VARCHAR(255), path VARCHAR(255), kv_ver INTEGER)")
        else:
            raise Exception("Error connecting DB: %s" % self.url)
        return db

    def get_vault_info(self, userid):
        db = self._get_db()
        res = db.select("select url, mount_point, path, kv_ver from vault_info where userid = %s", (userid,))
        db.close()

        if len(res) > 0:
            return res[0]
        else:
            return []

    def write_vault_info(self, userid, url, mount_point, path, kv_ver=1):
        db = self._get_ssh_db()

        db.execute("replace into vault_info (userid, url, mount_point, path, kv_ver) values (%s, %s, %s, %s, %s)",
                   (userid, url, mount_point, path, kv_ver))
        db.close()

    def delete_vault_info(self, userid):
        db = self._get_ssh_db()
        db.execute("delete from vault_info where userid = %s", (userid, ))
        db.close()
