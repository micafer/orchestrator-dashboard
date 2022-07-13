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
import flask
from app import utils
from mock import patch, MagicMock


class TestUtils(unittest.TestCase):
    """Class to test the Utils functions."""

    def test_getUserVOs(self):
        entitlements = ['urn:mace:egi.eu:group:vo.test.egi.eu:role=member#aai.egi.eu',
                        'urn:mace:egi.eu:group:vo.test2.egi.eu:role=member#aai.egi.eu']
        res = utils.getUserVOs(entitlements)
        self.assertEquals(res, ['vo.test.egi.eu', 'vo.test2.egi.eu'])

    @patch("app.utils.getCachedProjectIDs")
    @patch("app.utils.getCachedSiteList")
    def test_getUserAuthData(self, getCachedSiteList, getCachedProjectIDs):
        cred = MagicMock()
        with flask.Flask(__name__).test_request_context() as flask_context:
            cred.get_creds.return_value = [{'enabled': 1, 'type': 'OpenNebula', 'id': 'one',
                                            'username': 'user', 'password': 'pass'},
                                           {'enabled': 1, 'type': 'fedcloud', 'id': 'fed',
                                            'host': 'https://api.cloud.ifca.es:5000', 'vo': 'vo_name'},
                                           {'enabled': 1, 'type': 'CH', 'id': 'ch', 'region': 'f1a',
                                            'username': 'user', 'password': 'pass', 'tenant': 'tenant'}]
            getCachedSiteList.return_value = {
                'CESGA': {'url': 'https://fedcloud-osservices.egi.cesga.es:5000', 'state': '', 'id': '11548G0'},
                'IFCA': {'url': 'https://api.cloud.ifca.es:5000', 'state': '', 'id': 'ifca', 'identity_method': 'oidc'}
            }
            getCachedProjectIDs.return_value = {"vo_name_st": "project_id_st", "vo_name": "project_id"}

            flask_context.g.settings = MagicMock()
            flask_context.g.settings.im_auth = ""
            res = utils.getUserAuthData("token", cred, "user")
            self.assertEquals(res, ("type = InfrastructureManager; token = token\\nid = one; type = OpenNebula;"
                                    " username = user; password = pass\\n"
                                    "id = fed; type = OpenStack; username = egi.eu;"
                                    " tenant = oidc; auth_version = 3.x_oidc_access_token; host ="
                                    " https://api.cloud.ifca.es:5000; password = 'token'; domain = project_id\\n"
                                    "id = ch; type = OpenStack; auth_version = 3.x_password;"
                                    " host = https://identity-f1a.cloudandheat.com:5000; username = user;"
                                    " tenant = tenant; password = 'pass'"))

            flask_context.g.settings.im_auth = "Bearer"
            res = utils.getUserAuthData("token", cred, "user")
            self.assertEquals(res, ("Bearer token"))


if __name__ == '__main__':
    unittest.main()
