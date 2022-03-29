#
# IM - Infrastructure Manager Dashboard
# Copyright (C) 2020 - GRyCAP - Universitat Politecnica de Valencia
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Function to contact IM Service."""
import os.path
import requests


class InfrastructureManager():

    def __init__(self, im_url, timeout=120):
        self.im_url = im_url
        self.timeout = timeout

    def get_version(self):
        url = "%s/version" % self.im_url
        try:
            response = requests.get(url, timeout=self.timeout)
            return response.text
        except Exception as ex:
            return str(ex)

    def get_inf_list(self, auth_data):
        headers = {"Authorization": auth_data, "Accept": "application/json"}
        url = "%s/infrastructures" % self.im_url
        response = requests.get(url, headers=headers, timeout=self.timeout)

        infrastructures = []
        if not response.ok:
            raise Exception("Error retrieving infrastructure list: \n" + response.text)
        else:
            json_res = response.json()
            if "uri-list" in json_res:
                infrastructures = [os.path.basename(elem["uri"]) for elem in json_res["uri-list"]]

        return infrastructures

    def get_inf_state(self, infid, auth_data):
        headers = {"Authorization": auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s/state" % (self.im_url, infid)
        response = requests.get(url, headers=headers, timeout=self.timeout)
        if response.status_code == 404:
            # This case appears when the Inf existed in the list operation
            # but no when the state function is called.
            return {"state": "deleting", "vm_states": {}}
        response.raise_for_status()
        inf_state = response.json()
        return inf_state['state']

    def get_vm_info(self, infid, vmid, auth_data):
        headers = {"Authorization": auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s/vms/%s" % (self.im_url, infid, vmid)
        return requests.get(url, headers=headers, timeout=self.timeout)

    def manage_vm(self, op, infid, vmid, auth_data):
        headers = {"Authorization": auth_data}
        op = op.lower()
        if op in ["stop", "start", "reboot"]:
            url = "%s/infrastructures/%s/vms/%s/%s" % (self.im_url, infid, vmid, op)
            response = requests.put(url, headers=headers, timeout=self.timeout)
        elif op == "terminate":
            url = "%s/infrastructures/%s/vms/%s" % (self.im_url, infid, vmid)
            response = requests.delete(url, headers=headers, timeout=self.timeout)
        else:
            raise Exception("Invalid VM Operation: %s." % op)

        return response

    def reconfigure_inf(self, infid, auth_data, vmids=None):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/reconfigure" % (self.im_url, infid)
        if vmids:
            url += "?vm_list=%s" % ",".join(vmids)
        return requests.put(url, headers=headers, timeout=self.timeout)

    def get_inf_property(self, infid, prop, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/%s" % (self.im_url, infid, prop)
        return requests.get(url, headers=headers, timeout=self.timeout)

    def get_vm_contmsg(self, infid, vmid, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/vms/%s/contmsg" % (self.im_url, infid, vmid)
        return requests.get(url, headers=headers, timeout=self.timeout)

    def delete_inf(self, infid, force, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s?async=1" % (self.im_url, infid)
        if force:
            url += "&force=1"
        return requests.delete(url, headers=headers, timeout=self.timeout)

    def create_inf(self, payload, auth_data):
        headers = {"Authorization": auth_data, "Content-Type": "text/yaml"}
        url = "%s/infrastructures?async=1" % self.im_url
        return requests.post(url, headers=headers, data=payload, timeout=self.timeout)

    def addresource_inf(self, infid, payload, auth_data):
        headers = {"Authorization": auth_data, "Accept": "application/json"}
        url = "%s/infrastructures/%s" % (self.im_url, infid)
        return requests.post(url, headers=headers, data=payload, timeout=self.timeout)

    def get_cloud_images(self, cloud_id, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/clouds/%s/images" % (self.im_url, cloud_id)
        return requests.get(url, headers=headers, timeout=self.timeout)

    def get_cloud_quotas(self, cloud_id, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/clouds/%s/quotas" % (self.im_url, cloud_id)
        return requests.get(url, headers=headers, timeout=self.timeout)

    def manage_inf(self, op, infid, auth_data):
        headers = {"Authorization": auth_data}
        op = op.lower()
        if op in ["stop", "start"]:
            url = "%s/infrastructures/%s/%s" % (self.im_url, infid, op)
            response = requests.put(url, headers=headers, timeout=self.timeout)
        else:
            raise Exception("Invalid Infrastructure Operation: %s." % op)

        return response

    def resize_vm(self, infid, vmid, radl, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/vms/%s" % (self.im_url, infid, vmid)
        response = requests.put(url, headers=headers, data=radl, timeout=self.timeout)

        return response

    def change_user(self, infid, token, overwrite, auth_data):
        if token:
            new_auth = '{"token":"%s"}' % token
        else:
            raise Exception("Empty token.")

        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/authorization" % (self.im_url, infid)
        if overwrite:
            url += "?overwrite=1"

        return requests.post(url, headers=headers, timeout=self.timeout, data=new_auth)

    def get_stats(self, auth_data, init_date=None, end_date=None):
        headers = {"Authorization": auth_data}
        url = "%s/stats" % self.im_url
        if init_date:
            url += "?init_date=%s" % init_date
        if end_date:
            if init_date:
                url += "&"
            else:
                url += "?"
            url += "end_date=%s" % end_date
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        stats = response.json()
        return stats['stats']
