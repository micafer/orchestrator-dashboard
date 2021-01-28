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
from cryptography.fernet import Fernet
from app.db import DataBase


class Credentials:

    def __init__(self, cred_db_url, key=None):
        self.cred_db_url = cred_db_url
        self.key = None
        if key:
            self.key = Fernet(key)

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
        db = DataBase(self.cred_db_url)
        if db.connect():
            if not db.table_exists("credentials"):
                db.execute("CREATE TABLE credentials(userid VARCHAR(255), serviceid VARCHAR(255), data LONGBLOB,"
                           " PRIMARY KEY (userid, serviceid))")
        else:
            raise Exception("Error connecting DB: %s" % self.cred_db_url)
        return db

    def get_creds(self, userid):
        db = self._get_creds_db()
        res = db.select("select serviceid, data from credentials where userid = %s", (userid,))
        db.close()

        data = {}
        if len(res) > 0:
            for elem in res:
                data[elem[0]] = json.loads(self._decrypt(elem[1]))

        return data

    def get_cred(self, serviceid, userid):
        db = self._get_creds_db()
        res = db.select("select data from credentials where userid = %s and serviceid = %s",
                        (userid, serviceid))
        db.close()

        data = {}
        if len(res) > 0:
            data = json.loads(self._decrypt(res[0][0]))

        return data

    def write_creds(self, serviceid, userid, data, insert=False):
        db = self._get_creds_db()
        str_data = self._encrypt(json.dumps(data))
        op = "replace"
        if insert:
            op = "insert"
        db.execute(op + " into credentials (data, userid, serviceid) values (%s, %s, %s)",
                   (str_data, userid, serviceid))
        db.close()

    def delete_cred(self, serviceid, userid):
        db = self._get_creds_db()
        db.execute("delete from credentials where userid = %s and serviceid = %s", (userid, serviceid))
        db.close()
