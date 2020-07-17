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
from app import utils
from mock import patch, MagicMock


class TestUtils(unittest.TestCase):
    """Class to test the Utils functions."""

    def test_getUserVOs(self):
        entitlements = ['urn:mace:egi.eu:group:vo.test.egi.eu:role=member#aai.egi.eu',
                        'urn:mace:egi.eu:group:vo.test2.egi.eu:role=member#aai.egi.eu']
        res = utils.getUserVOs(entitlements)
        self.assertEquals(res, ['vo.test.egi.eu', 'vo.test2.egi.eu'])

    @patch("app.utils.getStaticSitesProjectIDs")
    @patch("app.utils.getCachedSiteList")
    @patch("app.utils._getStaticSitesInfo")
    @patch("app.appdb.get_project_ids")
    def test_getUserAuthData(self, get_project_ids, getStaticSitesInfo, getCachedSiteList, getStaticSitesProjectIDs):
        cred = MagicMock()
        cred.get_cred.return_value = {"project": "project_name"}
        getCachedSiteList.return_value = {'CESGA': ('https://fedcloud-osservices.egi.cesga.es:5000', '', '11548G0')}
        getStaticSitesInfo.return_value = [{"name": "static_site_name", "api_version": "1.1"}]
        get_project_ids.return_value = {"vo_name": "project_id"}
        getStaticSitesProjectIDs.return_value = {"vo_name_st": "project_id_st"}

        res = utils.getUserAuthData("token", cred, "user")
        self.assertEquals(res, ("type = InfrastructureManager; token = token\\nid = ost1; type = OpenStack;"
                                " username = egi.eu; tenant = openid; auth_version = 3.x_oidc_access_token;"
                                " host = https://fedcloud-osservices.egi.cesga.es:5000; password = 'token';"
                                " domain = project_name"))

        res = utils.getUserAuthData("token", cred, "user", "vo_name", "CESGA")
        self.assertEquals(res, ("type = InfrastructureManager; token = token\\nid = ost1; type = OpenStack;"
                                " username = egi.eu; tenant = openid; auth_version = 3.x_oidc_access_token;"
                                " host = https://fedcloud-osservices.egi.cesga.es:5000; password = 'token';"
                                " domain = project_id"))
        self.assertEqual(cred.write_creds.call_args_list[0][0], ('CESGA', 'user', {'project': 'project_id'}))

    @patch("app.utils.getCachedSiteList")
    @patch('libcloud.compute.drivers.openstack.OpenStackNodeDriver')
    def test_get_site_images(self, get_driver, getCachedSiteList):
        cred = MagicMock()
        cred.get_cred.return_value = {"project": "project_name"}
        getCachedSiteList.return_value = {'CESGA': ('https://fedcloud-osservices.egi.cesga.es:5000', '', '11548G0')}
        driver = MagicMock()
        get_driver.return_value = driver
        image1 = MagicMock()
        image1.id = "imageid1"
        image1.name = "imagename1"
        driver.list_images.return_value = [image1]
        res = utils.get_site_images("CESGA", "vo.access.egi.eu", "token", cred, "user")
        self.assertEquals(res, [('imagename1', 'imageid1')])


if __name__ == '__main__':
    unittest.main()
