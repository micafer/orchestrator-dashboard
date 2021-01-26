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

from app import appdb
from mock import patch, MagicMock
from urllib.parse import urlparse


def read_file_as_string(file_name):
    tests_path = os.path.dirname(os.path.abspath(__file__))
    abs_file_path = os.path.join(tests_path, file_name)
    return open(abs_file_path, 'r').read()


class TestAppDB(unittest.TestCase):
    """Class to test the AppDB functions."""

    @staticmethod
    def requests_response(method, url, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.ok = False

        if url == "/rest/1.0/vos":
            resp.ok = True
            resp.status_code = 200
            resp.text = """<appdb:appdb>
                            <vo:vo id="15551" name="acc-comp.egi.eu" alias="acc-comp">
                            </vo:vo>
                            </appdb:appdb>"""

        return resp

    @patch('requests.request')
    def test_appdb_call(self, requests):
        requests.side_effect = self.requests_response
        res = appdb.appdb_call('/rest/1.0/vos')
        self.assertEquals(res["vo:vo"]["@name"], "acc-comp.egi.eu")

    @patch('app.appdb.appdb_call')
    def test_vo_list(self, appdb_call):
        appdb.VO_LIST = []
        vos = '<vo:vo id="15551" name="acc-comp.egi.eu"></vo:vo>'
        appdb_call.return_value = xmltodict.parse(vos.replace('\n', ''))
        res = appdb.get_vo_list()
        self.assertEquals(res, ['acc-comp.egi.eu'])
        appdb.VO_LIST = []

        vos = '<appdb:appdb><vo:vo id="15551" name="acc-comp.egi.eu"></vo:vo>'
        vos += '<vo:vo id="15527" name="vo.access.egi.eu"></vo:vo></appdb:appdb>'
        appdb_call.return_value = xmltodict.parse(vos)["appdb:appdb"]
        res = appdb.get_vo_list()
        self.assertEquals(res, ['acc-comp.egi.eu', 'vo.access.egi.eu'])

    @patch('app.appdb.appdb_call')
    def test_get_services(self, appdb_call):
        site = """<appdb:site id="80090G0" name="100IT" infrastructure="Production" status="Certified">
                  <site:service type="openstack" id="11541G0" host="devcloud-egi.100percentit.com">
                  </site:service>
                  <site:service type="openstack" id="11556G0" host="cloud-egi.100percentit.com">
                  </site:service>
                  </appdb:site>"""
        appdb_call.return_value = xmltodict.parse(site.replace('\n', ''))
        res = appdb._get_services()
        self.assertEquals(res[0]["@type"], "openstack")

        site = """<appdb:appdb><appdb:site id="80090G0" name="100IT" infrastructure="Production" status="Certified">
                  <site:service type="openstack" id="11541G0" host="devcloud-egi.100percentit.com">
                  </site:service>
                  <site:service type="openstack" id="11556G0" host="cloud-egi.100percentit.com">
                  </site:service>
                  </appdb:site>
                  <appdb:site id="32330G0" name="AEGIS02-RCUB" infrastructure="Production">
                  </appdb:site>
                  </appdb:appdb>"""
        appdb_call.return_value = xmltodict.parse(site.replace('\n', ''))["appdb:appdb"]
        res = appdb._get_services()
        self.assertEquals(res[0]["@type"], "openstack")

    @patch('app.appdb.appdb_call')
    @patch('app.appdb._get_services')
    def test_get_sites(self, get_services, appdb_call):
        get_services.return_value = [{"@id": "1"}]
        va_provider = read_file_as_string("files/va_provider.xml")
        appdb_call.return_value = xmltodict.parse(va_provider.replace('\n', ''))["appdb:appdb"]
        res = appdb.get_sites("vo.access.egi.eu")
        self.assertEquals(res, {'CESGA': {'url': 'https://fedcloud-osservices.egi.cesga.es:5000',
                                          'state': '', 'id': '1'}})
        self.assertEquals(appdb_call.call_args_list[0][0][0], "/rest/1.0/va_providers/1")

    @patch('app.appdb.appdb_call')
    def test_get_project_ids(self, appdb_call):
        shares = """<virtualization:provider id="11548G0">
                    <provider:shares>
                    <vo:vo id="15527" projectid="3a8e9d966e644405bf19b536adf7743d">vo.access.egi.eu</vo:vo>
                    <vo:vo projectid="972298c557184a2192ebc861f3184da8">covid-19.eosc-synergy.eu</vo:vo>
                    </provider:shares>
                    </virtualization:provider>"""
        appdb_call.return_value = xmltodict.parse(shares.replace('\n', ''))
        res = appdb.get_project_ids("11548G0")
        self.assertEquals(res, {"vo.access.egi.eu": "3a8e9d966e644405bf19b536adf7743d",
                                "covid-19.eosc-synergy.eu": "972298c557184a2192ebc861f3184da8"})


    @patch('app.appdb.appdb_call')
    def test_get_images(self, appdb_call):
        images = """<virtualization:provider id="11548G0">
                    <provider:image appcname="scipioncloud.gpu" voname="vo.access.egi.eu" archived="false"/>
                    </virtualization:provider>"""
        appdb_call.return_value = xmltodict.parse(images.replace('\n', ''))
        res = appdb.get_images('11548G0', 'vo.access.egi.eu')
        self.assertEquals(res, ["scipioncloud.gpu"])

if __name__ == '__main__':
    unittest.main()
