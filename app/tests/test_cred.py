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

from app.cred import Credentials


class TestCredentials(unittest.TestCase):
    """Class to test the Credentials class."""

    def tearDown(self):
        os.unlink('/tmp/creds.db')

    def test_creds(self):
        creds = Credentials("sqlite:///tmp/creds.db")
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
        creds = Credentials("sqlite:///tmp/creds.db", 'ZMiCBQwtVu2HE6TS4METx84d4LhqmZ5NJtgiTjJzbeU=')
        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user", "password": "pass"},
                          True)

        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user", "password": "pass", "enabled": 1})

        creds.write_creds("credid", "user", {"id": "credid", "type": "type", "username": "user1"})
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {"id": "credid", "type": "type", "username": "user1", "password": "pass", "enabled": 1})

        creds.delete_cred("credid", "user")
        res = creds.get_cred("credid", "user")
        self.assertEquals(res, {})


if __name__ == '__main__':
    unittest.main()
