#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2011 - GRyCAP - Universitat Politecnica de Valencia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import os
import json

from mock import patch, MagicMock

from app.db_cred import DBCredentials
from app.vault_cred import VaultCredentials


class TestDBCredentials(unittest.TestCase):
    """Class to test the Credentials class."""

    def tearDown(self):
        os.unlink('/tmp/creds.db')

    def test_creds(self):
        creds = DBCredentials("sqlite:///tmp/creds.db")
        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username":
                                             "user", "password": "pass", "host": "host"}, True)

        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {"id": "credid", "type": "type", "username": "user",
                               "password": "pass", "host": "host", "enabled": 1})

        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username":"user1", "host": "host"})
        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass",
                               "host": "host", "enabled": 1})

        new_cred = {"id": "credid", "type": "type", "username": "user1", "password": "pass", "host": "host"}
        res = creds.validate_cred("user", new_cred)
        self.assertEqual(res, (1, 'Duplicated ID.'))

        new_cred = {"id": "credid1", "type": "type", "username": "user1", "password": "pass", "host": "host"}
        res = creds.validate_cred("user", new_cred)
        self.assertEqual(res, (1, 'Credentials already available.'))

        new_cred = {"id": "credid2", "type": "type", "username": "user2", "password": "pass", "host": "host"}
        res = creds.validate_cred("user", new_cred)
        self.assertEqual(res[0], 2)

        new_cred = {"id": "credid2", "type": "type", "username": "user2", "password": "pass", "host": "host2"}
        res = creds.validate_cred("user", new_cred)
        self.assertEqual(res[0], 0)

        creds.delete_cred("credid", "user")
        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {})

    def test_creds_enc(self):
        creds = DBCredentials("sqlite:///tmp/creds.db", 'ZMiCBQwtVu2HE6TS4METx84d4LhqmZ5NJtgiTjJzbeU=')
        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user", "password": "pass"},
                          True)

        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1})

        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.enable_cred("credid", "user", 0)
        res = creds.get_cred("credid", "user")
        self.assertEqual(res["enabled"], 0)

        creds.delete_cred("credid", "user")
        res = creds.get_cred("credid", "user")
        self.assertEqual(res, {})


class TestVaultCredentials(unittest.TestCase):
    """Class to test the Credentials class."""

    @patch("hvac.Client")
    @patch("requests.post")
    def test_creds(self, post, hvac):
        response = MagicMock()
        response.json.return_value = {"auth": {"entity_id": "entity_id", "client_token": "client_token"}}
        post.return_value = response

        client = MagicMock()
        client.secrets.kv.v1.read_secret.return_value = None
        response2 = MagicMock()
        client.secrets.kv.v1.create_or_update_secret.return_value = response2

        hvac.return_value = client

        token = "token", []
        token_vault = "token", ["http://some2.com", "mount_point", "path", 2]
        creds = VaultCredentials("http://some.com")
        creds.write_creds("credid", token, {"id": "credid", "type": "type", "username":
                                            "user", "password": "pass"}, True)
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][0], "entity_id")
        exp_res = {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1}
        self.assertEqual(json.loads(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][1]['credid']),
                         exp_res)

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": json.dumps(exp_res)}}
        res = creds.get_cred("credid", token)
        self.assertEqual(res, exp_res)
        self.assertEqual(post.call_args_list[1][0][0], 'http://some.com/v1/auth/jwt/login')
        self.assertEqual(client.secrets.kv.v1.read_secret.call_args_list[0][1], {'path': 'entity_id',
                                                                                 'mount_point': 'credentials/'})
        client.secrets.kv.v2.read_secret.return_value = {"data": {"credid": json.dumps(exp_res)}}
        res = creds.get_cred("credid", token_vault)
        self.assertEqual(res, exp_res)
        self.assertEqual(post.call_args_list[2][0][0], 'http://some2.com/v1/auth/jwt/login')
        self.assertEqual(client.secrets.kv.v2.read_secret.call_args_list[0][1], {'path': 'path',
                                                                                 'mount_point': 'mount_point'})

        creds.write_creds("credid", token, {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", token)
        self.assertEqual(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.enable_cred("credid", token, 0)
        self.assertEqual(json.loads(client.secrets.kv.v1.create_or_update_secret.call_args_list[2][0][1]['credid']),
                         {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 0})

        creds.delete_cred("credid", token)
        self.assertEqual(client.secrets.kv.v1.delete_secret.call_args_list[0][0], ("entity_id",))

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": json.dumps(exp_res),
                                                                  "credid2": ""}}
        creds.delete_cred("credid", token)
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[3][0][1], {"credid2": ""})


if __name__ == '__main__':
    unittest.main()
