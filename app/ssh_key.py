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
"""Class to manage user SSH key using a DB backend."""
import paramiko
from app.db import DataBase


class SSHKey():

    def __init__(self, url):
        self.url = url

    def _get_ssh_db(self):
        db = DataBase(self.url)
        if db.connect():
            if not db.table_exists("ssh_keys"):
                if db.db_type == DataBase.MYSQL:
                    db.execute("CREATE TABLE ssh_keys(rowid INTEGER NOT NULL AUTO_INCREMENT UNIQUE, "
                               "description VARCHAR(255), userid VARCHAR(255), ssh_key TEXT)")
                elif db.db_type == DataBase.SQLITE:
                    db.execute("CREATE TABLE ssh_keys(userid VARCHAR(255), description VARCHAR(255), "
                               "ssh_key TEXT)")
        else:
            raise Exception("Error connecting DB: %s" % self.url)
        return db

    def get_ssh_keys(self, userid):
        db = self._get_ssh_db()
        res = db.select("select rowid, description, ssh_key from ssh_keys where userid = %s", (userid,))
        db.close()

        if len(res) > 0:
            return res
        else:
            return []

    def get_ssh_key(self, keyid):
        db = self._get_ssh_db()
        res = db.select("select description, ssh_key from ssh_keys where rowid = %s", (keyid,))
        db.close()

        if len(res) > 0:
            return res[0]
        else:
            return None

    def write_ssh_key(self, userid, ssh_key, desc):
        db = self._get_ssh_db()

        db.execute("insert into ssh_keys (userid, ssh_key, description) values (%s, %s, %s)",
                   (userid, ssh_key, desc))
        db.close()

    def delete_ssh_key(self, userid, keyid):
        db = self._get_ssh_db()
        db.execute("delete from ssh_keys where userid = %s and rowid = %s", (userid, keyid))
        db.close()

    @staticmethod
    def check_ssh_key(key):
        try:
            paramiko.PublicBlob.from_string(key)
        except Exception as ex:
            return False
        return True
