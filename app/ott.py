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
import time
from app.db import DataBase
from uuid import uuid4

class OneTimeTokenData():

    def __init__(self, ott_db, ttl=86400):
        self._ott_db = ott_db
        self.ttl = ttl

    def _get_ott_db(self):
        db = DataBase(self._ott_db)
        if db.connect():
            if not db.table_exists("ott"):
                db.execute("CREATE TABLE ott(token VARCHAR(255), data VARCHAR(255), exp INTEGER, PRIMARY KEY (token))")
        else:
            raise Exception("Error connecting DB: %s" % self.url)
        return db

    def get_data(self, token):
        data = None
        try:
            now = int(time.time())
            db = self._get_ott_db()
            res = db.select("select token, data, exp from ott where token = %s and exp > %s", (token, now))
            if len(res) > 0:
                data = res[0][1]
            db.execute("delete from ott where token = %s", (token,))
            # Clean expired tokens
            db.execute("delete from ott where exp < %s", (now,))
            db.close()
        except Exception as e:
            pass
        return data

    def write_data(self, data):
        token = str(uuid4())
        now = int(time.time())
        db = self._get_ott_db()
        db.execute("insert into ott (token, data, exp) values (%s, %s, %s)", (token, data, now + self.ttl))
        # Clean expired tokens
        db.execute("delete from ott where exp < %s", (now,))
        db.close()
        return token
