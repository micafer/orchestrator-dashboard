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
"""Function to get sites info from https://github.com/EGI-Federation/fedcloud-catchall-operations/tree/main/sites."""
import requests
import yaml
from urllib.parse import urlparse


GIT_REPO = "EGI-Federation/fedcloud-catchall-operations"
GIT_BRANCH = "main"
REQUESTS_TIMEOUT = 10
RAW_URL = "https://raw.githubusercontent.com/%s/%s/sites/" % (GIT_REPO, GIT_BRANCH)
SITES_CACHE = {}


def get_sites(vo=None):
    global SITES_CACHE
    sites = {}
    url = "https://api.github.com/repos/%s/contents/sites?branch%s" % (GIT_REPO, GIT_BRANCH)
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    resp = requests.get(url, headers=headers, timeout=REQUESTS_TIMEOUT)
    if resp.status_code == 200:
        for file_info in resp.json():
            if file_info["type"] == "file":
                name = file_info["name"]
                if (name in SITES_CACHE and SITES_CACHE[name] and SITES_CACHE[name]["sha"] == file_info["sha"] and
                        SITES_CACHE[name]["size"] == file_info["size"]):
                    site_info = SITES_CACHE[name]["info"]
                else:
                    site_info = get_site_info(name)
                    SITES_CACHE[name] = {"sha": file_info["sha"],
                                         "size": file_info["size"],
                                         "info": site_info}
                if vo is None or vo in site_info["vos"]:
                    sites[site_info["name"]] = site_info

    return sites


def get_site_info(site_name):
    site_file = "%s%s" % (RAW_URL, site_name if site_name.endswith(".yaml") else site_name + ".yaml")
    resp = requests.get(site_file, timeout=REQUESTS_TIMEOUT)
    if resp.status_code == 200:
        site_info = yaml.safe_load(resp.text)
        site_info["gocdb"]
        site_info["endpoint"]
        vos = {}
        for vo in site_info["vos"]:
            vos[vo["name"]] = vo["auth"]["project_id"]

        url = urlparse(site_info["endpoint"])
        return {"url": "%s://%s" % url[0:2],
                "state": "",
                "id": site_info["gocdb"],
                "name": site_info["gocdb"],
                "vos": vos}


def get_images(site_id, vo):
    return []


def get_project_ids(site_name):
    site_info = get_site_info(site_name)
    return site_info["vos"]
