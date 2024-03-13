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
import xmltodict

from app import egi_catch_all
from mock import patch, MagicMock
from urllib.parse import urlparse


class TestEGICatchAll(unittest.TestCase):
    """Class to test the EGI Catch all functions."""

    @staticmethod
    def requests_response(url, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.ok = False

        if url == "/repos/EGI-Federation/fedcloud-catchall-operations/contents/sites":
            resp.status_code = 200
            resp.json.return_value = [{
                "name": "UPV-GRyCAP.yaml",
                "sha": "f9688bafd4d5645611b2905cdffd8e1b9cd1676a",
                "size": 390,
                "type": "file",
            }]
        elif url == "/EGI-Federation/fedcloud-catchall-operations/main/sites/UPV-GRyCAP.yaml":
            resp.status_code = 200
            resp.text = """---
gocdb: UPV-GRyCAP
endpoint: https://menoscloud.i3m.upv.es:5000/v3
vos:
- name: eosc-synergy.eu
  auth:
    project_id: 6f84e31391024330b16d29d6ccd26932
- name: fedcloud.egi.eu
  auth:
    project_id: db929e9034f04d1698c1a0d58283366e
- name: ops
  auth:
    project_id: 292568ead7454709a17f19189d5a840a
- name: saps-vo.i3m.upv.es
  auth:
    project_id: e7608e969cfd4f49907cff17d1774898"""

        return resp

    @patch('requests.get')
    def test_get_sites(self, requests):
        requests.side_effect = self.requests_response
        res = egi_catch_all.get_sites()
        expected = {
            "UPV-GRyCAP": {
                "id": "UPV-GRyCAP",
                "name": "UPV-GRyCAP",
                "state": "",
                "url": "https://menoscloud.i3m.upv.es:5000",
                "vos": {
                    "eosc-synergy.eu": "6f84e31391024330b16d29d6ccd26932",
                    "fedcloud.egi.eu": "db929e9034f04d1698c1a0d58283366e",
                    "ops": "292568ead7454709a17f19189d5a840a",
                    "saps-vo.i3m.upv.es": "e7608e969cfd4f49907cff17d1774898",
                },
            }
        }
        self.assertEquals(res, expected)

    @patch('requests.get')
    def test_get_project_ids(self, requests):
        requests.side_effect = self.requests_response
        res = egi_catch_all.get_project_ids('UPV-GRyCAP')
        expected = {
            "eosc-synergy.eu": "6f84e31391024330b16d29d6ccd26932",
            "fedcloud.egi.eu": "db929e9034f04d1698c1a0d58283366e",
            "ops": "292568ead7454709a17f19189d5a840a",
            "saps-vo.i3m.upv.es": "e7608e969cfd4f49907cff17d1774898",
        }
        self.assertEquals(res, expected)


if __name__ == '__main__':
    unittest.main()
