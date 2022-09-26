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
"""Class to manage Infrastructures static data."""
from flask import json
from app.db import DataBase


class Infrastructures:

    def __init__(self, inf_db_url):
        """Creation function."""
        self.inf_db_url = inf_db_url

    def _get_inf_db(self):
        db = DataBase(self.inf_db_url)
        if db.connect():
            if not db.table_exists("infrastructures"):
                db.execute("CREATE TABLE infrastructures(infid VARCHAR(255) PRIMARY KEY, data LONGBLOB)")
        else:
            raise Exception("Error connecting DB: %s" % self.inf_db_url)
        return db

    def get_infra(self, infid):
        db = self._get_inf_db()
        res = db.select("select data from infrastructures where infid = %s", (infid,))
        db.close()

        data = {}
        if len(res) > 0:
            data = json.loads(res[0][0])

        return data

    def write_infra(self, infid, data):
        db = self._get_inf_db()

        res = db.select("select data from infrastructures where infid = %s", (infid,))

        old_data = {}
        if len(res) > 0:
            old_data = json.loads(res[0][0])
        old_data.update(data)

        str_data = json.dumps(old_data)
        db.execute("replace into infrastructures (infid, data) values (%s, %s)", (infid, str_data))
        db.close()

    def delete_infra(self, infid):
        db = self._get_inf_db()
        db.execute("delete from infrastructures where infid = %s", (infid, ))
        db.close()

    def get_infra_cred_id(self, infid):
        try:
            infra_data = self.get_infra(infid)
        except Exception:
            infra_data = {}
        return infra_data.get("site", {}).get("id")
