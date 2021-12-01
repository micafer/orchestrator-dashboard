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
                                             "user", "password": "pass"}, True)

        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1})

        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.delete_cred("credid", "user")
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {})

    def test_creds_enc(self):
        creds = DBCredentials("sqlite:///tmp/creds.db", 'ZMiCBQwtVu2HE6TS4METx84d4LhqmZ5NJtgiTjJzbeU=')
        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user", "password": "pass"},
                          True)

        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1})

        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.enable_cred("credid", "user", 0)
        res = creds.get_cred("credid", "user")
        self.assertEquals(res["enabled"], 0)

        creds.delete_cred("credid", "user")
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {})


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

        creds = VaultCredentials("http://some.com")
        creds.write_creds("credid", "token", {"id": "credid", "type": "type", "username":
                                              "user", "password": "pass"}, True)
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][0], "entity_id")
        exp_res = {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1}
        self.assertEqual(json.loads(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][1]['credid']),
                         exp_res)

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": json.dumps(exp_res)}}
        res = creds.get_cred("credid", "token")
        self.assertEquals(res, exp_res)

        creds.write_creds("credid", "token", {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.delete_cred("credid", "token")
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[1][0][1], {})

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": json.dumps(exp_res)}}
        creds.enable_cred("credid", "token", 0)
        exp_res["enabled"] = 0
        self.assertEqual(json.loads(client.secrets.kv.v1.create_or_update_secret.call_args_list[3][0][1]['credid']),
                         exp_res)

    @patch("hvac.Client")
    @patch("requests.post")
    def test_creds_enc(self, post, hvac):
        response = MagicMock()
        response.json.return_value = {"auth": {"entity_id": "entity_id", "client_token": "client_token"}}
        post.return_value = response

        client = MagicMock()
        client.secrets.kv.v1.read_secret.return_value = None
        response2 = MagicMock()
        client.secrets.kv.v1.create_or_update_secret.return_value = response2

        hvac.return_value = client

        creds = VaultCredentials("http://some.com", key='ZMiCBQwtVu2HE6TS4METx84d4LhqmZ5NJtgiTjJzbeU=')
        creds.write_creds("credid", "token", {"id": "credid", "type": "type", "username":
                                              "user", "password": "pass"}, True)
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][0], "entity_id")
        exp_res = {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1}
        res = json.loads(
            creds._decrypt(client.secrets.kv.v1.create_or_update_secret.call_args_list[0][0][1]['credid']))
        self.assertEqual(res, exp_res)

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": creds._encrypt(json.dumps(exp_res))}}
        res = creds.get_cred("credid", "token")
        self.assertEquals(res, exp_res)

        creds.delete_cred("credid", "token")
        self.assertEqual(client.secrets.kv.v1.create_or_update_secret.call_args_list[1][0][1], {})

        client.secrets.kv.v1.read_secret.return_value = {"data": {"credid": creds._encrypt(json.dumps(exp_res))}}
        creds.enable_cred("credid", "token", 0)
        exp_res["enabled"] = 0
        res = json.loads(creds._decrypt(client.secrets.kv.v1.create_or_update_secret.call_args_list[2][0][1]['credid']))
        self.assertEqual(res, exp_res)


if __name__ == '__main__':
    unittest.main()
