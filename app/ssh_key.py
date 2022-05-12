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
import base64
import binascii
import struct
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
                               "description VARCHAR(255), userid VARCHAR(255), ssh_key VARCHAR(255))")
                elif db.db_type == DataBase.SQLITE:
                    db.execute("CREATE TABLE ssh_keys(userid VARCHAR(255), description VARCHAR(255), "
                               "ssh_key VARCHAR(255))")
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
        # credits to: https://gist.github.com/piyushbansal/5243418

        array = key.split()

        # Each rsa-ssh key has 2 or 3 different strings in it, first one being
        # typeofkey second one being keystring third one being username (optional).
        if len(array) not in [2, 3]:
            return 1

        typeofkey = array[0]
        string = array[1]

        # must have only valid rsa-ssh key characters ie binascii characters
        try:
            data = base64.decodebytes(string)
        except binascii.Error:
            return 1

        a = 4
        # unpack the contents of data, from data[:4] , it must be equal to 7 , property of ssh key .
        try:
            str_len = struct.unpack('>I', data[:a])[0]
        except struct.error:
            return 1

        # data[4:11] must have string which matches with the typeofkey , another ssh key property.
        if data[a:a + str_len] == typeofkey and int(str_len) == int(7):
            return 0
        else:
            return 1
