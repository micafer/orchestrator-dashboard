import unittest
import json
from app import create_app
from urllib.parse import urlparse
from mock import patch, MagicMock


class IMDashboardTests(unittest.TestCase):

    oauth = MagicMock()

    def setUp(self):
        self.app = create_app(self.oauth)
        self.client = self.app.test_client()

    @staticmethod
    def get_response(url, params=None, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]
        params = parts[4]

        resp.status_code = 404
        resp.ok = False

        if url == "/im/infrastructures":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"uri-list": [{"uri": "http://server.com/im/infrastructures/infid"}]}
        elif url == "/im/infrastructures/infid/state":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"state": {"state": "configured", "vm_states": {"0": "configured"}}}
        elif url == "/im/infrastructures/infid/vms/0":
            resp.ok = True
            resp.status_code = 200
            resp.text = ""
            radl = {"class": "system",
                    "cpu.arch": "x86_64",
                    "cpu.count_min": 1,
                    "disk.0.image.url": "one://server.com/id",
                    "disk.0.os.name": "linux",
                    "id": "front",
                    "state": "configured",
                    "disk.0.os.credentials.username": "user",
                    "disk.0.os.credentials.password": "pass",
                    "memory.size_min": 536870912,
                    "net_interface.0.connection": "publica",
                    "net_interface.0.ip": "10.10.10.10",
                    "provider.type": "OpenNebula",
                    "provider.host": "server.com"}
            resp.json.return_value = {"radl": [radl]}
        elif url == "/im/infrastructures/infid/vms/0/stop":
            resp.ok = True
            resp.status_code = 200
        elif url == "/im/infrastructures/infid/tosca":
            resp.ok = True
            resp.status_code = 200
            resp.text = "TOSCA"
        elif url == "/im/infrastructures/infid/contmsg":
            resp.ok = True
            resp.status_code = 200
            resp.text = "CONT_MSG"
        elif url == "/im/infrastructures/infid/vms/0/contmsg":
            resp.ok = True
            resp.status_code = 200
            resp.text = "VM_CONT_MSG"
        elif url == "/im/infrastructures/infid/outputs":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"outputs": {"key": "value", "key2": "http://server.com"}}
        elif url == "/im/infrastructures/infid/radl":
            resp.ok = True
            resp.status_code = 200
            resp.text = "system wn ()\nsystem front ()"
        elif url == "/im/clouds/credid/images":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"images": [{"uri": "one://server/imageid", "name": "imagename"}]}
        elif url == "/im/clouds/credid/quotas":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"quotas": {"cores": {"used": 1, "limit": 10},
                                                 "ram": {"used": 1, "limit": 10},
                                                 "instances": {"used": 1, "limit": 10},
                                                 "floating_ips": {"used": 1, "limit": 10},
                                                 "security_groups": {"used": 1, "limit": 10}}}

        return resp

    @staticmethod
    def put_response(url, params=None, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.ok = False

        if url == "/im/infrastructures/infid/vms/0/stop":
            resp.ok = True
            resp.status_code = 200
        elif url == "/im/infrastructures/infid/reconfigure":
            resp.ok = True
            resp.status_code = 200

        return resp

    @staticmethod
    def delete_response(url, params=None, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.ok = False

        if url == "/im/infrastructures/infid/vms/0":
            resp.ok = True
            resp.status_code = 200
        elif url == "/im/infrastructures/infid":
            resp.ok = True
            resp.status_code = 200

        return resp

    def post_response(self, url, params=None, **kwargs):
        resp = MagicMock()
        parts = urlparse(url)
        url = parts[2]

        resp.status_code = 404
        resp.ok = False

        if url == "/im/infrastructures":
            resp.ok = True
            resp.status_code = 200
            self.assertIn("IMAGE_NAME", kwargs["data"])
            self.assertIn("default: 4", kwargs["data"])
        elif url == "/im/infrastructures/infid":
            resp.ok = True
            resp.status_code = 200
            resp.json.return_value = {"uri-list": [{"uri": "VM_URI"}]}

        return resp

    def login(self, avatar):
        self.oauth.session.authorized = True
        self.oauth.session.token = {'expires_in': 500, 'access_token': 'token'}
        account_info = MagicMock()
        account_info.ok = True
        account_info.json.return_value = {"sub": "userid", "name": "username",
                                          "eduperson_entitlement": ["urn:mace:egi.eu:group:VO_NAME:role=r#aai.egi.eu",
                                                                    "urn:mace:egi.eu:group:vo:role=r#aai.egi.eu"]}
        self.oauth.session.get.return_value = account_info
        avatar.return_value = ""
        return self.client.get('/')

    def test_index_with_no_login(self):
        self.oauth.session.authorized = False
        res = self.client.get('/')
        self.assertEqual(302, res.status_code)
        self.assertIn('/login', res.headers['location'])

    @patch("app.utils.avatar")
    def test_index(self, avatar):
        res = self.login(avatar)
        self.assertEqual(200, res.status_code)

    @patch("app.utils.avatar")
    def test_settings(self, avatar):
        self.login(avatar)
        res = self.client.get('/settings')
        self.assertEqual(200, res.status_code)
        self.assertIn(b"https://appsgrycap.i3m.upv.es:31443/im", res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_infrastructures(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/infrastructures')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'infid', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.put')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_manageinf_start(self, flash, avatar, put, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        put.side_effect = self.put_response
        self.login(avatar)
        res = self.client.get('/manage_inf/infid/stop')
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/infrastructures', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0],
                          ("Operation 'stop' successfully made on Infrastructure ID: infid", 'info'))

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_vm_info(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/vminfo?infId=infid&vmId=0')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'Username: user', res.data)
        self.assertIn(b'Password: pass', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.put')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_managevm_stop(self, flash, avatar, put, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        put.side_effect = self.put_response
        self.login(avatar)
        res = self.client.get('/managevm/stop/infid/0')
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/vminfo?infId=infid&vmId=0', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Operation 'stop' successfully made on VM ID: 0", 'info'))

    @patch("app.utils.getUserAuthData")
    @patch('requests.delete')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_managevm_delet(self, flash, avatar, delete, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        delete.side_effect = self.delete_response
        self.login(avatar)
        res = self.client.get('/managevm/terminate/infid/0')
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/infrastructures', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Operation 'terminate' successfully made on VM ID: 0", 'info'))

    @patch("app.utils.getUserAuthData")
    @patch('requests.put')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_reconfigure(self, flash, avatar, put, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        put.side_effect = self.put_response
        self.login(avatar)
        res = self.client.get('/reconfigure/infid')
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/infrastructures', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Infrastructure successfuly reconfigured.", 'info'))

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_template(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/template/infid')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'TOSCA', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_log(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/log/infid')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'CONT_MSG', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_vm_log(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/vmlog/infid/0')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'VM_CONT_MSG', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_outputs(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/outputs/infid')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'key', res.data)
        self.assertIn(b'key2', res.data)
        self.assertIn(b'value', res.data)
        self.assertIn(b"<a href='http://server.com' target='_blank'>http://server.com</a>", res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.delete')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_delete(self, flash, avatar, delete, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        delete.side_effect = self.delete_response
        self.login(avatar)
        res = self.client.get('/delete/infid/0')
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/infrastructures', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Infrastructure 'infid' successfuly deleted.", 'info'))

    @patch("app.utils.avatar")
    @patch("app.cred.Credentials.get_creds")
    def test_configure(self, get_creds, avatar):
        self.login(avatar)
        get_creds.return_value = [{"id": "credid", "type": "fedcloud", "host": "site_url", "vo": "voname"},
                                  {"id": "credid1", "type": "OpenStack", "host": "site_url1", "tenant_id": "tenid"}]
        res = self.client.get('/configure?selected_tosca=simple-node.yml')
        self.assertEqual(200, res.status_code)
        self.assertIn(b"Launch a compute node getting the IP and SSH credentials to access via ssh", res.data)
        self.assertIn(b'<option data-tenant-id="" data-type="fedcloud" name="selectedCred" '
                      b'value=credid>credid</option>', res.data)
        self.assertIn(b'<option data-tenant-id="tenid" data-type="OpenStack" '
                      b'name="selectedCred" value=credid1>credid1</option>', res.data)

    @patch("app.utils.avatar")
    @patch("app.appdb.get_sites")
    def test_sites(self, get_sites, avatar):
        self.login(avatar)
        get_sites.return_value = {"SITE_NAME": {"url": "URL", "state": "", "id": ""},
                                  "SITE2": {"url": "URL2", "state": "CRITICAL", "id": ""}}
        res = self.client.get('/sites/vo')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'<option name="selectedSite" value=URL>SITE_NAME</option>', res.data)
        self.assertIn(b'<option name="selectedSite" value=static_site_url>static_site_name</option>', res.data)
        self.assertIn(b'<option name="selectedSite" value=URL2>SITE2 (WARNING: CRITICAL state!)</option>', res.data)

    @patch("app.utils.avatar")
    @patch("app.utils.getUserAuthData")
    @patch("app.utils.get_site_info")
    @patch("app.appdb.get_images")
    @patch('requests.get')
    def test_images(self, get, get_images, get_site_info, user_data, avatar):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        get_site_info.return_value = ({"id": "siteid"}, "", "vo_name")

        res = self.client.get('/images/credid?local=1')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'<option name="selectedSiteImage" value=one://server/imageid>imagename</option>', res.data)

        get_images.return_value = [("IMAGE_NAME", "IMAGE")]
        res = self.client.get('/images/credid')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'<option name="selectedImage" value=IMAGE>IMAGE_NAME</option>', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.post')
    @patch("app.utils.avatar")
    @patch("app.cred.Credentials.get_cred")
    def test_submit(self, get_cred, avatar, post, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        post.side_effect = self.post_response
        get_cred.return_value = {"id": "credid", "type": "fedcloud"}
        self.login(avatar)
        params = {'extra_opts.selectedImage': '',
                  'extra_opts.selectedSiteImage': 'IMAGE_NAME',
                  'extra_opts.selectedCred': 'credid',
                  'num_cpus': '4',
                  'ports': '22,80,443'}
        res = self.client.post('/submit?template=simple-node.yml', data=params)
        self.assertEqual(302, res.status_code)
        self.assertIn('http://localhost/infrastructures', res.headers['location'])

    @patch("app.utils.avatar")
    @patch("app.cred.Credentials.get_creds")
    def test_manage_creds(self, get_creds, avatar):
        self.login(avatar)
        get_creds.return_value = [{"id": "credid", "type": "fedcloud", "host": "site_url"}]
        res = self.client.get('/manage_creds')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'credid', res.data)
        self.assertIn(b'site_url', res.data)
        self.assertIn(b'fedcloudRow.png', res.data)

    @patch("app.utils.avatar")
    @patch("app.cred.Credentials.get_cred")
    @patch("app.cred.Credentials.write_creds")
    @patch("app.flash")
    def test_write_creds(self, flash, write_creds, get_cred, avatar):
        self.login(avatar)
        get_cred.return_value = {"id": "credid", "type": "OpenNebula", "host": "SITE_URL",
                                 "username": "USER", "password": "PASS"}
        res = self.client.get('/write_creds?cred_type=OpenNebula&cred_id=')
        self.assertEqual(200, res.status_code)
        self.assertNotIn(b'site_url', res.data)

        res = self.client.get('/write_creds?cred_id=credid&cred_type=OpenNebula')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'SITE_URL', res.data)
        self.assertIn(b'USER', res.data)

        res = self.client.post('/write_creds?cred_id=credid&cred_type=OpenNebula', data={"host": "SITE_URL2",
                                                                                         "id": "credid"})
        self.assertEqual(302, res.status_code)
        self.assertIn('/manage_creds', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Credentials successfully written!", 'info'))
        self.assertEquals(write_creds.call_args_list[0][0], ('credid', 'userid', {'host': 'SITE_URL2',
                                                             'id': 'credid'}, False))

        res = self.client.post('/write_creds?cred_id=&cred_type=OpenNebula', data={"host": "SITE_URL3",
                                                                                   "id": "credid"})
        self.assertEqual(302, res.status_code)
        self.assertIn('/manage_creds', res.headers['location'])
        self.assertEquals(flash.call_args_list[1][0], ("Credentials successfully written!", 'info'))
        self.assertEquals(write_creds.call_args_list[1][0], ('credid', 'userid', {'host': 'SITE_URL3',
                                                                                  'id': 'credid'}, True))

    @patch("app.utils.avatar")
    @patch("app.cred.Credentials.delete_cred")
    @patch("app.flash")
    def test_delete_creds(self, flash, delete_cred, avatar):
        self.login(avatar)
        delete_cred.return_value = True
        res = self.client.get('/delete_creds?service_id=SERVICE_ID')
        self.assertEqual(302, res.status_code)
        self.assertIn('/manage_creds', res.headers['location'])
        self.assertEquals(flash.call_args_list[0][0], ("Credentials successfully deleted!", 'info'))

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch("app.utils.avatar")
    def test_addresourcesform(self, avatar, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)
        res = self.client.get('/addresourcesform/infid')
        self.assertEqual(200, res.status_code)
        self.assertIn(b'infid', res.data)
        self.assertIn(b'wn', res.data)
        self.assertIn(b'front', res.data)

    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    @patch('requests.post')
    @patch("app.utils.avatar")
    @patch("app.flash")
    def test_addresources(self, flash, avatar, post, get, user_data):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        post.side_effect = self.post_response
        self.login(avatar)
        res = self.client.post('/addresources/infid', data={"wn_num": "1"})
        self.assertEqual(302, res.status_code)
        self.assertEquals(flash.call_args_list[0][0], ("1 nodes added successfully", 'info'))

    @patch("app.utils.avatar")
    @patch("app.utils.getUserAuthData")
    @patch('requests.get')
    def test_quotas(self, get, user_data, avatar):
        user_data.return_value = "type = InfrastructureManager; token = access_token"
        get.side_effect = self.get_response
        self.login(avatar)

        res = self.client.get('/usage/credid')
        self.assertEqual(200, res.status_code)
        expected_res = {"cores": {"used": 1, "limit": 10},
                        "ram": {"used": 1, "limit": 10},
                        "instances": {"used": 1, "limit": 10},
                        "floating_ips": {"used": 1, "limit": 10},
                        "security_groups": {"used": 1, "limit": 10}}
        self.assertEquals(expected_res, json.loads(res.data))
