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
"""Class to manage user credentials using a DB backend with encryption."""
from cryptography.fernet import Fernet
from app.cred import Credentials
from app.db import DataBase
from flask import json


class DBCredentials(Credentials):

    def __init__(self, cred_db_url, key=None):
        self.key = None
        if key:
            self.key = Fernet(key)
        super().__init__(cred_db_url)

    def _encrypt(self, message):
        if self.key:
            return self.key.encrypt(message.encode())
        else:
            return message

    def _decrypt(self, message):
        if self.key:
            return self.key.decrypt(message)
        else:
            return message

    def _get_creds_db(self):
        db = DataBase(self.url)
        if db.connect():
            if not db.table_exists("credentials"):
                db.execute("CREATE TABLE credentials(userid VARCHAR(255), serviceid VARCHAR(255),"
                           "enabled INTEGER ,data LONGBLOB, PRIMARY KEY (userid, serviceid))")
        else:
            raise Exception("Error connecting DB: %s" % self.url)
        return db

    def get_creds(self, userid, enabled=None, filter=None):
        db = self._get_creds_db()
        res = db.select("select serviceid, enabled, data from credentials where userid = %s", (userid,))
        db.close()

        data = []
        if len(res) > 0:
            for elem in res:
                new_item = json.loads(self._decrypt(elem[2]))
                new_item['enabled'] = elem[1]
                if enabled is None or enabled == new_item['enabled']:
                    if filter:
                        if all([elem in new_item and filter[elem] in new_item[elem] for elem in list(filter.keys())]):
                            data.append(new_item)
                    else:
                        data.append(new_item)

        return data

    def get_cred(self, serviceid, userid):
        db = self._get_creds_db()
        res = db.select("select data, enabled from credentials where userid = %s and serviceid = %s",
                        (userid, serviceid))
        db.close()

        data = {}
        if len(res) > 0:
            data = json.loads(self._decrypt(res[0][0]))
            data['enabled'] = res[0][1]

        return data

    def write_creds(self, serviceid, userid, data, insert=False):
        db = self._get_creds_db()
        op = "replace"
        if insert:
            op = "insert"
            old_data = data
        else:
            old_data = self.get_cred(serviceid, userid)
            old_data.update(data)

        if 'enabled' in old_data:
            enabled = old_data['enabled']
            del old_data['enabled']
        else:
            enabled = 1

        str_data = self._encrypt(json.dumps(old_data))
        db.execute(op + " into credentials (data, userid, serviceid, enabled) values (%s, %s, %s, %s)",
                   (str_data, userid, serviceid, enabled))
        db.close()

    def delete_cred(self, serviceid, userid):
        db = self._get_creds_db()
        db.execute("delete from credentials where userid = %s and serviceid = %s", (userid, serviceid))
        db.close()

    def enable_cred(self, serviceid, userid, enable=1):
        db = self._get_creds_db()
        db.execute("update credentials set enabled = %s where userid = %s and serviceid = %s",
                   (enable, userid, serviceid))
        db.close()
