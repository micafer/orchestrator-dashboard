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

from app.infra import Infrastructures


class TestInfrastructures(unittest.TestCase):
    """Class to test the Infrastructures class."""

    def tearDown(self):
        os.unlink('/tmp/creds.db')

    def test_get_infra(self):
        infra = Infrastructures("sqlite:///tmp/creds.db")
        res = infra._get_inf_db()
        str_data = '{"name": "infra_name"}'
        res.execute("replace into infrastructures (infid, data) values (%s, %s)",
                    ("infid", str_data))
        res.close()

        res = infra.get_infra("infid")
        self.assertEquals(res, {'name': 'infra_name'})

    def test_write_infra(self):
        infra = Infrastructures("sqlite:///tmp/creds.db")
        infra.write_infra("infid", {"name": "infra_name"})
        res = infra.get_infra("infid")
        self.assertEquals(res, {"name": "infra_name"})
        infra.write_infra("infid", {"state": "infra_state"})
        res = infra.get_infra("infid")
        self.assertEquals(res, {"name": "infra_name", "state": "infra_state"})

    def test_delete_infra(self):
        infra = Infrastructures("sqlite:///tmp/creds.db")
        infra.delete_infra("infid")
        res = infra.get_infra("infid")
        self.assertEquals(res, {})


if __name__ == '__main__':
    unittest.main()
