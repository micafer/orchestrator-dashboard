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
"""Util functions."""

import json
import yaml
import requests
import os
import io
import ast
import time
import sys
from flask import flash, g
from app import appdb
from fnmatch import fnmatch
from hashlib import md5
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

SITE_LIST = {}
LAST_UPDATE = 0


def _getStaticSitesInfo():
    if g.settings.static_sites:
        return g.settings.static_sites
    elif g.settings.static_sites_url:
        try:
            response = requests.get(g.settings.static_sites_url)
            if not response.ok:
                return []
            else:
                try:
                    sites = response.json()
                except Exception:
                    sites = []
                g.settings.static_sites = sites
                return sites
        except Exception:
            return []
    else:
        return []


def getCachedProjectIDs(site_id):
    res = {}
    for site in getCachedSiteList().values():
        if site_id == site["id"]:
            if "vos" not in site:
                site["vos"] = {}
            if "vos_updated" not in site or not site["vos_updated"]:
                try:
                    site["vos"].update(appdb.get_project_ids(site_id))
                    site["vos_updated"] = True
                except Exception as ex:
                    print("Error loading project IDs from AppDB: %s" % ex, file=sys.stderr)

            for vo, projectid in site["vos"].items():
                res[vo] = projectid
    return res


def getStaticSites(vo=None):
    res = {}
    for site in _getStaticSitesInfo():
        if vo is None or ("vos" in site and site["vos"] and vo in site["vos"]):
            res[site["name"]] = site
            site["state"] = ""

    return res


def getStaticVOs():
    res = []
    for site in _getStaticSitesInfo():
        if "vos" in site and site["vos"]:
            res.extend(list(site["vos"].keys()))

    return list(set(res))


def get_site_info(cred_id, cred, userid):
    domain = None

    cred_data = cred.get_cred(cred_id, userid)
    vo = cred_data['vo']

    for site in list(getCachedSiteList().values()):
        if site['url'] == cred_data['host']:
            break

    project_ids = getCachedProjectIDs(site["id"])
    if vo in project_ids:
        domain = project_ids[vo]

    return site, domain, vo


def getUserVOs(entitlements):
    vos = []
    for elem in entitlements:
        if elem.startswith('urn:mace:egi.eu:group:'):
            vo = elem[22:22 + elem[22:].find(':')]
            if vo:
                vos.append(vo)
    return vos


def getCachedSiteList(force=False):
    global SITE_LIST
    global LAST_UPDATE

    now = int(time.time())
    if force or not SITE_LIST or now - LAST_UPDATE > g.settings.appdb_cache_timeout:
        try:
            SITE_LIST = appdb.get_sites()
            # in case of error do not update time
            LAST_UPDATE = now
        except Exception as ex:
            flash("Error retrieving site list from AppDB: %s" % ex, 'warning')

        SITE_LIST.update(getStaticSites())

    return SITE_LIST


def getUserAuthData(access_token, cred, userid):
    res = "type = InfrastructureManager; token = %s" % access_token

    fedcloud_sites = None
    for cred in cred.get_creds(userid):
        if cred['enabled']:
            res += "\\nid = %s" % cred['id']
            if cred['type'] != "fedcloud":
                for key, value in cred.items():
                    if value and key not in ['enabled', 'id']:
                        res += "; %s = %s" % (key, value.replace('\n', '\\\\n'))
            else:
                res += "; type = OpenStack;"
                res += " username = egi.eu; tenant = openid; auth_version = 3.x_oidc_access_token;"
                res += " host = %s; password = '%s'" % (cred['host'], access_token)
                # only load this data if a EGI Cloud site appears
                if fedcloud_sites is None:
                    fedcloud_sites = {}
                    for site in list(getCachedSiteList().values()):
                        fedcloud_sites[site['url']] = site

                site_info = fedcloud_sites[cred['host']]
                if 'api_version' in site_info:
                    res += "; api_version  = %s" % site_info['api_version']

                projectid = None
                project_ids = getCachedProjectIDs(site_info["id"])
                if cred['vo'] in project_ids:
                    projectid = project_ids[cred['vo']]

                if projectid:
                    res += "; domain = %s" % projectid

    return res


def format_json_radl(vminfo):
    res = {}
    for elem in vminfo:
        if elem["class"] == "system":
            for field, value in elem.items():
                if field not in ["class", "id"]:
                    if field.endswith("_min"):
                        field = field[:-4]
                    res[field] = value
    return res


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


def loadToscaTemplates(directory):

    toscaTemplates = []
    for path, _, files in os.walk(directory):
        for name in files:
            if (fnmatch(name, "*.yml") or fnmatch(name, "*.yaml")) and \
                    not (fnmatch(name, "*.parameters.yaml") or fnmatch(name, "*.parameters.yml")):
                # skip hidden files
                if name[0] != '.':
                    toscaTemplates.append(os.path.relpath(os.path.join(path, name), directory))

    return toscaTemplates


def extractToscaInfo(toscaDir, tosca_pars_dir, toscaTemplates):
    toscaInfo = {}
    for tosca in toscaTemplates:
        with io.open(toscaDir + tosca) as stream:
            template = yaml.full_load(stream)

            toscaInfo[tosca] = {"valid": True,
                                "description": "TOSCA Template",
                                "metadata": {
                                    "icon": "https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png"
                                },
                                "enable_config_form": False,
                                "inputs": {},
                                "tabs": {}}

            if 'topology_template' not in template:
                toscaInfo[tosca]["valid"] = False
            else:
                if 'description' in template:
                    toscaInfo[tosca]["description"] = template['description']

                if 'metadata' in template and template['metadata'] is not None:
                    for k, v in template['metadata'].items():
                        toscaInfo[tosca]["metadata"][k] = v

                if 'inputs' in template['topology_template']:
                    toscaInfo[tosca]['inputs'] = template['topology_template']['inputs']

                # add parameters code here
                if tosca_pars_dir:
                    tosca_pars_path = tosca_pars_dir + "/"  # this has to be reassigned here because is local.
                    for fpath, _, fnames in os.walk(tosca_pars_path):
                        for fname in fnames:
                            if fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yml') or \
                                    fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yaml'):
                                # skip hidden files
                                if fname[0] != '.':
                                    tosca_pars_file = os.path.join(fpath, fname)
                                    with io.open(tosca_pars_file) as pars_file:
                                        toscaInfo[tosca]['enable_config_form'] = True
                                        pars_data = yaml.full_load(pars_file)
                                        # only read expected fields tab and tag_type
                                        for key, value in pars_data["inputs"].items():
                                            if "tab" in value:
                                                toscaInfo[tosca]['inputs'][key]["tab"] = value["tab"]
                                            if "tag_type" in value:
                                                toscaInfo[tosca]['inputs'][key]["tag_type"] = value["tag_type"]
                                        if "tabs" in pars_data:
                                            toscaInfo[tosca]['tabs'] = pars_data["tabs"]

    return toscaInfo


def exchange_token_with_audience(oidc_url, client_id, client_secret, oidc_token, audience):

    payload_string = ('{ "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": "' +
                      audience + '", "subject_token": "' + oidc_token + '", "scope": "openid profile" }')

    # Convert string payload to dictionary
    payload = ast.literal_eval(payload_string)

    oidc_response = requests.post(oidc_url + "/token", data=payload, auth=(client_id, client_secret), verify=False)

    if not oidc_response.ok:
        raise Exception("Error exchanging token: {} - {}".format(oidc_response.status_code, oidc_response.text))

    deserialized_oidc_response = json.loads(oidc_response.text)

    return deserialized_oidc_response['access_token']
