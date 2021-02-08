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

    def __init__(self, im_url, timeout=30):
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

        infrastructures = {}
        if not response.ok:
            raise Exception("Error retrieving infrastructure list: \n" + response.text)
        else:
            state_res = response.json()
            if "uri-list" in state_res:
                inf_id_list = [elem["uri"] for elem in state_res["uri-list"]]
            else:
                inf_id_list = []
            for inf_id in inf_id_list:
                url = "%s/state" % inf_id
                try:
                    response = requests.get(url, headers=headers, timeout=self.timeout)
                    response.raise_for_status()
                    inf_state = response.json()
                    infrastructures[os.path.basename(inf_id)] = inf_state['state']
                except Exception:
                    infrastructures[os.path.basename(inf_id)] = {"state": "unknown", "vm_states": {}}

        return infrastructures

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

    def reconfigure_inf(self, infid, auth_data):
        headers = {"Authorization": auth_data}
        url = "%s/infrastructures/%s/reconfigure" % (self.im_url, infid)
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
