#! /usr/bin/env python
#
# IM - Infrastructure Manager
# Copyright (C) 2023 - GRyCAP - Universitat Politecnica de Valencia
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
from app.vault_info import VaultInfo


class TestVaultInfo(unittest.TestCase):
    """Class to test the VaultInfo class."""

    def test_vault_info(self):
        filename = "/tmp/test_vault.dat"
        if os.path.exists(filename):
            os.unlink(filename)
        db_url = "sqlite://" + filename
        vi = VaultInfo(db_url)
        vi.write_vault_info("user1", "url1", "mount1", "path1")

        res = vi.get_vault_info("user1")
        self.assertEqual(res, ('url1', 'mount1', 'path1', 1))

        vi.delete_vault_info("user1")

        res = vi.get_vault_info("user1")
        self.assertEqual(res, {})

        os.unlink(filename)


if __name__ == '__main__':
    unittest.main()
