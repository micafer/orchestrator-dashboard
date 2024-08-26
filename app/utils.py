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

import io
import json
import os
import sys
import time
import re
from collections import OrderedDict
from fnmatch import fnmatch
from hashlib import md5
from random import randint

import requests
import urllib3
import yaml
from flask import flash, g
from radl.radl_json import parse_radl
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from app import appdb

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(InsecureRequestWarning)

SITE_LIST = {}
LAST_UPDATE = 0
PORT_SPECT_TYPES = ["PortSpec", "tosca.datatypes.network.PortSpec", "tosca.datatypes.indigo.network.PortSpec"]


def _getStaticSitesInfo(force=False):
    # Remove cache if force is True
    if force and g.settings.static_sites_url:
        g.settings.static_sites = None

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


def getStaticSites(vo=None, force=False):
    res = {}
    for site in _getStaticSitesInfo(force=force):
        if vo is None or ("vos" in site and site["vos"] and vo in site["vos"]):
            res[site["name"]] = site
            site["state"] = ""

    return res


def get_site_info(cred_id, cred, userid):
    domain = None
    res_site = {}

    cred_data = cred.get_cred(cred_id, userid)
    vo = cred_data['vo']

    for site in list(getCachedSiteList().values()):
        if site['url'] == cred_data['host']:
            res_site = site
            project_ids = getCachedProjectIDs(site["id"])
            if vo in project_ids:
                domain = project_ids[vo]
            break

    return res_site, domain, vo


def getUserVOs(entitlements, vo_role=None):
    vos = []
    for elem in entitlements:
        # format: urn:mace:egi.eu:group:eosc-synergy.eu:role=vm_operator#aai.egi.eu
        if elem.startswith('urn:mace:egi.eu:group:'):
            vo = elem[22:22 + elem[22:].find(':')]
            if vo and (not vo_role or ":role=%s#" % vo_role in elem) and vo not in vos:
                vos.append(vo)
        elif elem in g.settings.vo_map and g.settings.vo_map[elem] not in vos:
            vos.append(g.settings.vo_map[elem])
    vos.sort()
    return vos


def getCachedSiteList(force=False):
    global SITE_LIST
    global LAST_UPDATE

    now = int(time.time())
    if force or not SITE_LIST or now - LAST_UPDATE > g.settings.appdb_cache_timeout:
        try:
            sites = appdb.get_sites()
            if sites:
                SITE_LIST = appdb.get_sites()
            # in case of error do not update time
            LAST_UPDATE = now
        except Exception as ex:
            flash("Error retrieving site list from AppDB: %s" % ex, 'warning')

        SITE_LIST.update(getStaticSites(force=force))

    return SITE_LIST


def getIMUserAuthData(access_token, cred, userid):
    if g.settings.im_auth == "Bearer":
        return "Bearer %s" % access_token
    res = "type = InfrastructureManager; token = '%s'" % access_token
    for cred in cred.get_creds(userid):
        if cred['enabled']:
            if cred['type'] == "InfrastructureManager":
                res += "\\nid = %s" % cred['id']
                for key, value in cred.items():
                    if value and key not in ['enabled', 'id']:
                        res += "; %s = '%s'" % (key, value.replace('\n', '\\\\n'))
    return res


def getUserAuthData(access_token, cred, userid, cred_id=None, full=False, add_extra_auth=True):
    if g.settings.im_auth == "Bearer" and not full:
        return "Bearer %s" % access_token
    res = "type = InfrastructureManager; token = %s" % access_token

    fedcloud_sites = None
    creds = cred.get_creds(userid)

    # Add the extra auth configured in the Dashboard
    extra_auth_ids = []
    try:
        if g.settings.extra_auth and add_extra_auth:
            creds.extend(g.settings.extra_auth)
            extra_auth_ids = [elem["id"] for elem in g.settings.extra_auth]
    except Exception:
        print("Error getting extra credentials.", file=sys.stderr)

    # Check if the cred_id provided exists
    cred_found = False
    for cred in creds:
        if cred['enabled'] and (cred_id is None or cred_id == cred['id'] or cred['id'] in extra_auth_ids):
            cred_found = True
            break
    # if not, set to none to send all creds
    if not cred_found:
        cred_id = None

    for cred in creds:
        if cred['enabled'] and (cred_id is None or cred_id == cred['id'] or cred['id'] in extra_auth_ids):
            res += "\\nid = %s" % cred['id']
            if cred['type'] == "CH":
                # Add the Cloud&Heat provider as OpenStack
                res += "; type = OpenStack; auth_version = 3.x_password;"
                res += " host = https://identity-%s.cloudandheat.com:5000;" % cred['region']
                res += " username = %s; tenant = %s; password = '%s'" % (cred['username'],
                                                                         cred['tenant'],
                                                                         cred['password'])
                if "tenant_id" in cred:
                    res += "; tenant_id = %s;" % cred["tenant_id"]
            elif cred['type'] != "fedcloud":
                for key, value in cred.items():
                    if value and key not in ['enabled', 'id']:
                        res += "; %s = '%s'" % (key, value.replace('\n', '\\\\n'))
            else:
                res += "; type = OpenStack;"
                res += " username = egi.eu; tenant = openid; auth_version = 3.x_oidc_access_token;"
                res += " host = %s; password = '%s'; vo = %s" % (cred['host'], access_token, cred['vo'])

                projectid = cred['project_id'] if 'project_id' in cred else None
                # only load this data if a EGI Cloud site appears
                if fedcloud_sites is None:
                    fedcloud_sites = {}
                    for site in list(getCachedSiteList().values()):
                        fedcloud_sites[site['url']] = site

                if cred['host'] in fedcloud_sites:
                    site_info = fedcloud_sites[cred['host']]
                    if 'api_version' in site_info:
                        res += "; api_version  = %s" % site_info['api_version']
                    if 'identity_method' in site_info:
                        res = res.replace("tenant = openid", "tenant = %s" % site_info['identity_method'])
                    if 'region' in site_info:
                        res += "; service_region = %s" % site_info['region']

                    project_ids = getCachedProjectIDs(site_info["id"])
                    if cred['vo'] in project_ids and project_ids[cred['vo']]:
                        projectid = project_ids[cred['vo']]
                else:
                    print("Error %s not in list of FedCloud sites." % cred['host'], file=sys.stderr)

                if projectid:
                    res += "; domain = %s" % projectid
                else:
                    print("Error not project ID for Cred %s." % cred['id'], file=sys.stderr)

    return res


def format_json_radl(vminfo):
    res = {}
    for elem in vminfo:
        if elem["class"] == "system":
            for field, value in elem.items():
                if field not in ["class"]:
                    if field.endswith("_min"):
                        field = field[:-4]
                    res[field] = value
    return res


def get_out_ports(vminfo):
    outports = []

    radl_info = parse_radl(vminfo)
    system = radl_info.systems[0]

    for net in radl_info.networks:
        if net.isPublic() and system.getNumNetworkWithConnection(net.id):
            outports = net.getOutPorts()

    return outports


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()  # nosec
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


def reLoadToscaTemplates(directory, oldToscaTemplates, delay):

    newToscaTemplates = []
    toscaTemplates = []
    for path, _, files in os.walk(directory):
        for name in files:
            if (fnmatch(name, "*.yml") or fnmatch(name, "*.yaml")) and \
                    not (fnmatch(name, "*.parameters.yaml") or fnmatch(name, "*.parameters.yml")):
                # skip hidden files
                if name[0] != '.':
                    filename = os.path.relpath(os.path.join(path, name), directory)
                    toscaTemplates.append(filename)
                    diff_time = time.time() - os.path.getmtime(os.path.join(path, name))
                    if filename not in oldToscaTemplates or diff_time < delay:
                        newToscaTemplates.append(filename)

    deletedToscaTemplates = [x for x in oldToscaTemplates if x not in toscaTemplates]

    return deletedToscaTemplates, newToscaTemplates


def _addTabs(tabs, toscaInfo, tosca):
    if tabs:
        toscaInfo[tosca]['enable_config_form'] = True
    for tab, input_elems in tabs.items():
        toscaInfo[tosca]['tabs'].append(tab)
        # Special case for a regex to select inputs
        if isinstance(input_elems, str):
            all_inputs = list(toscaInfo[tosca]['inputs'].keys())
            res = [elem for elem in all_inputs if re.match(input_elems, elem)]
            input_elems = res
        for input_elem in input_elems:
            input_name = input_elem
            input_params = {}
            if isinstance(input_elem, dict):
                input_name = list(input_elem.keys())[0]
                input_params = list(input_elem.values())[0]
            if input_name in toscaInfo[tosca]['inputs']:
                toscaInfo[tosca]['inputs'][input_name]["tab"] = tab
                if "tag_type" in input_params:
                    toscaInfo[tosca]['inputs'][input_name]["tag_type"] = input_params["tag_type"]
                if "pattern" in input_params:
                    toscaInfo[tosca]['inputs'][input_name]["pattern"] = input_params["pattern"]


def _addAddons(toscaInfo, toscaDir):
    # Add addons to description
    for tosca in toscaInfo.keys():
        if "childs" in toscaInfo[tosca]["metadata"] and toscaInfo[tosca]["metadata"]["childs"]:
            if 'addons' not in toscaInfo[tosca]['metadata']:
                toscaInfo[tosca]['metadata']["addons"] = ""
            child_names = []
            for child in toscaInfo[tosca]["metadata"]["childs"]:
                child_name = ""
                if child in toscaInfo:
                    child_name = toscaInfo[child].get("metadata", {}).get("template_name")
                else:
                    try:
                        with io.open(toscaDir + child) as stream:
                            child_template = yaml.full_load(stream)
                    except Exception:
                        child_template = {}
                    child_name = child_template.get("metadata", {}).get("template_name")
                if child_name:
                    child_names.append(child_name)
            toscaInfo[tosca]['metadata']["addons"] += ", ".join(child_names)


def extractToscaInfo(toscaDir, toscaTemplates, tags_to_hide):
    toscaInfoOrder = toscaInfo = {}
    for tosca in toscaTemplates:
        with io.open(toscaDir + tosca) as stream:
            template = yaml.full_load(stream)

            # skip tosca templates with hidden tags
            if tags_to_hide and template.get('metadata', {}).get('tag') in tags_to_hide:
                continue

            toscaInfo[tosca] = {"valid": True,
                                "description": "TOSCA Template",
                                "metadata": {
                                    "order": 99999999,
                                    "icon": "https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png"
                                },
                                "enable_config_form": False,
                                "inputs": {},
                                "tabs": []}

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

                tabs = template.get('metadata', {}).get('tabs', {})
                _addTabs(tabs, toscaInfo, tosca)

        toscaInfoOrder = OrderedDict(sorted(toscaInfo.items(), key=lambda x: x[1]["metadata"]['order']))

    # Add addons to description
    _addAddons(toscaInfo, toscaDir)

    return toscaInfoOrder


def generate_random_name():
    left = [
        "admiring",
        "adoring",
        "affectionate",
        "agitated",
        "amazing",
        "angry",
        "awesome",
        "beautiful",
        "blissful",
        "bold",
        "boring",
        "brave",
        "busy",
        "charming",
        "clever",
        "cool",
        "compassionate",
        "competent",
        "condescending",
        "confident",
        "cranky",
        "crazy",
        "dazzling",
        "determined",
        "distracted",
        "dreamy",
        "eager",
        "ecstatic",
        "elastic",
        "elated",
        "elegant",
        "eloquent",
        "epic",
        "exciting",
        "fervent",
        "festive",
        "flamboyant",
        "focused",
        "friendly",
        "frosty",
        "funny",
        "gallant",
        "gifted",
        "goofy",
        "gracious",
        "great",
        "happy",
        "hardcore",
        "heuristic",
        "hopeful",
        "hungry",
        "infallible",
        "inspiring",
        "interesting",
        "intelligent",
        "jolly",
        "jovial",
        "keen",
        "kind",
        "laughing",
        "loving",
        "lucid",
        "magical",
        "mystifying",
        "modest",
        "musing",
        "naughty",
        "nervous",
        "nice",
        "nifty",
        "nostalgic",
        "objective",
        "optimistic",
        "peaceful",
        "pedantic",
        "pensive",
        "practical",
        "priceless",
        "quirky",
        "quizzical",
        "recursing",
        "relaxed",
        "reverent",
        "romantic",
        "sad",
        "serene",
        "sharp",
        "silly",
        "sleepy",
        "stoic",
        "strange",
        "stupefied",
        "suspicious",
        "sweet",
        "tender",
        "thirsty",
        "trusting",
        "unruffled",
        "upbeat",
        "vibrant",
        "vigilant",
        "vigorous",
        "wizardly",
        "wonderful",
        "xenodochial",
        "youthful",
        "zealous",
        "zen"
    ]
    rigth = [
        "albattani",
        "allen",
        "almeida",
        "antonelli",
        "agnesi",
        "archimedes",
        "ardinghelli",
        "aryabhata",
        "austin",
        "babbage",
        "banach",
        "banzai",
        "bardeen",
        "bartik",
        "bassi",
        "beaver",
        "bell",
        "benz",
        "bhabha",
        "bhaskara",
        "black",
        "blackburn",
        "blackwell",
        "bohr",
        "booth",
        "borg",
        "bose",
        "bouman",
        "boyd",
        "brahmagupta",
        "brattain",
        "brown",
        "buck",
        "burnell",
        "cannon",
        "carson",
        "cartwright",
        "carver",
        "cerf",
        "chandrasekhar",
        "chaplygin",
        "chatelet",
        "chatterjee",
        "chebyshev",
        "cohen",
        "chaum",
        "clarke",
        "colden",
        "cori",
        "cray",
        "curran",
        "curie",
        "darwin",
        "davinci",
        "dewdney",
        "dhawan",
        "diffie",
        "dijkstra",
        "dirac",
        "driscoll",
        "dubinsky",
        "easley",
        "edison",
        "einstein",
        "elbakyan",
        "elgamal",
        "elion",
        "ellis",
        "engelbart",
        "euclid",
        "euler",
        "faraday",
        "feistel",
        "fermat",
        "fermi",
        "feynman",
        "franklin",
        "gagarin",
        "galileo",
        "galois",
        "ganguly",
        "gates",
        "gauss",
        "germain",
        "goldberg",
        "goldstine",
        "goldwasser",
        "golick",
        "goodall",
        "gould",
        "greider",
        "grothendieck",
        "haibt",
        "hamilton",
        "haslett",
        "hawking",
        "hellman",
        "heisenberg",
        "hermann",
        "herschel",
        "hertz",
        "heyrovsky",
        "hodgkin",
        "hofstadter",
        "hoover",
        "hopper",
        "hugle",
        "hypatia",
        "ishizaka",
        "jackson",
        "jang",
        "jemison",
        "jennings",
        "jepsen",
        "johnson",
        "joliot",
        "jones",
        "kalam",
        "kapitsa",
        "kare",
        "keldysh",
        "keller",
        "kepler",
        "khayyam",
        "khorana",
        "kilby",
        "kirch",
        "knuth",
        "kowalevski",
        "lalande",
        "lamarr",
        "lamport",
        "leakey",
        "leavitt",
        "lederberg",
        "lehmann",
        "lewin",
        "lichterman",
        "liskov",
        "lovelace",
        "lumiere",
        "mahavira",
        "margulis",
        "matsumoto",
        "maxwell",
        "mayer",
        "mccarthy",
        "mcclintock",
        "mclaren",
        "mclean",
        "mcnulty",
        "mendel",
        "mendeleev",
        "meitner",
        "meninsky",
        "merkle",
        "mestorf",
        "mirzakhani",
        "montalcini",
        "moore",
        "morse",
        "murdock",
        "moser",
        "napier",
        "nash",
        "neumann",
        "newton",
        "nightingale",
        "nobel",
        "noether",
        "northcutt",
        "noyce",
        "panini",
        "pare",
        "pascal",
        "pasteur",
        "payne",
        "perlman",
        "pike",
        "poincare",
        "poitras",
        "proskuriakova",
        "ptolemy",
        "raman",
        "ramanujan",
        "ride",
        "ritchie",
        "rhodes",
        "robinson",
        "roentgen",
        "rosalind",
        "rubin",
        "saha",
        "sammet",
        "sanderson",
        "satoshi",
        "shamir",
        "shannon",
        "shaw",
        "shirley",
        "shockley",
        "shtern",
        "sinoussi",
        "snyder",
        "solomon",
        "spence",
        "stonebraker",
        "sutherland",
        "swanson",
        "swartz",
        "swirles",
        "taussig",
        "tereshkova",
        "tesla",
        "tharp",
        "thompson",
        "torvalds",
        "tu",
        "turing",
        "varahamihira",
        "vaughan",
        "visvesvaraya",
        "volhard",
        "villani",
        "wescoff",
        "wilbur",
        "wiles",
        "williams",
        "williamson",
        "wilson",
        "wing",
        "wozniak",
        "wright",
        "wu",
        "yalow",
        "yonath",
        "zhukovsky"
    ]
    return "%s-%s%d" % (left[randint(0, len(left) - 1)], rigth[randint(0, len(rigth) - 1)], randint(0, 9))


def get_project_ids(creds):
    """Get the project ID associted with the fedcloud creds."""
    fedcloud_sites = None
    for cred in creds:
        if cred['type'] == "fedcloud":
            # only load this data the first time EGI Cloud site appears
            if fedcloud_sites is None:
                fedcloud_sites = {}
                for site in list(getCachedSiteList().values()):
                    fedcloud_sites[site['url']] = site

            if cred['host'] in fedcloud_sites:
                site_info = fedcloud_sites[cred['host']]

                project_ids = getCachedProjectIDs(site_info["id"])
                if cred['vo'] in project_ids:
                    cred['project_id'] = project_ids[cred['vo']]

    return creds


def getVOs(session):
    return session["vos"] if "vos" in session and session["vos"] else []


def get_site_info_from_radl(radl, creds):
    res_site = {}

    site_type = None
    site_host = None
    site_vo = None

    # Get provider info from RADL
    for elem in radl:
        if elem["class"] == "system":
            site_type = elem.get("provider.type")
            site_host = elem.get("provider.host")
            site_vo = elem.get("provider.vo")
            if site_vo:
                site_type = "fedcloud"
            break

    if not site_type:
        return res_site

    # Now try to get the corresponding cred
    # only for EGI sites
    for cred in creds:
        if cred["type"] == "fedcloud" and site_host in cred["host"] and site_vo == cred["vo"]:
            return cred

    # If there is no cred for it
    if site_vo:
        res_site["vo"] = site_vo

        # in case of FedCLoud sites get site name
        for site_name, site in getCachedSiteList().items():
            if site_host in site['url']:
                res_site["site_name"] = site_name
                break

    if site_host and "cloudandheat" in site_host:
        site_type = "CH"

    if site_host:
        res_site["host"] = site_host
    res_site["type"] = site_type

    return res_site


def discover_oidc_urls(base_url):
    """Get OIDC URLs"""
    url = "%s/.well-known/openid-configuration" % base_url
    res = {}
    try:
        response = requests.get(url, timeout=10)
        if response.ok:
            data = response.json()
            for elem in ["authorization_endpoint", "token_endpoint", "introspection_endpoint", "userinfo_endpoint"]:
                res[elem] = data[elem]
    except Exception:
        return res
    return res


def valid_template_vos(user_vos, template_metadata):
    if not user_vos:
        return []
    if 'vos' in template_metadata and template_metadata['vos']:
        return [vo for vo in user_vos if vo in template_metadata['vos']]
    else:
        return ['all']


def convert_value(value, value_type):
    if value_type == "integer":
        value = int(value)
    elif value_type == "float":
        value = float(value)
    elif value_type == "boolean":
        value = value.lower() in ["true", "yes", "1"]
    return value


def get_list_values(name, inputs, value_type="string", retun_type="list"):

    cont = 1
    # Special case for ports
    if value_type in PORT_SPECT_TYPES:
        ports_value = {}
        while "%s_list_value_%d_range" % (name, cont) in inputs:
            port_num = inputs["%s_list_value_%d_range" % (name, cont)]
            remote_cidr = inputs.get("%s_list_value_%d_cidr" % (name, cont))
            target_port = inputs.get("%s_list_value_%d_target" % (name, cont))
            port_name = "port_%s" % port_num.replace(":", "_")
            # Should we also open UDP?
            ports_value[port_name] = {"protocol": "tcp"}

            if target_port:
                ports_value[port_name]["target"] = int(target_port)
            if ":" in port_num:
                port_range = port_num.split(":")
                ports_value[port_name]["source_range"] = [int(port_range[0]), int(port_range[1])]
            else:
                ports_value[port_name]["source"] = int(port_num)
            if remote_cidr:
                ports_value[port_name]["remote_cidr"] = remote_cidr
            cont += 1
        if retun_type == "map":
            return ports_value
        else:
            return list(ports_value.values())
    elif retun_type == "list":
        values = []
        while "%s_list_value_%d" % (name, cont) in inputs:
            value = inputs["%s_list_value_%d" % (name, cont)]
            values.append(convert_value(value, value_type))
            cont += 1
        return values
    else:
        values = {}
        while "%s_list_value_%d_key" % (name, cont) in inputs:
            key = inputs["%s_list_value_%d_key" % (name, cont)]
            value = inputs["%s_list_value_%d_value" % (name, cont)]
            values[key] = convert_value(value, value_type)
            cont += 1
        return values


def formatPortSpec(ports):
    res = {}
    if isinstance(ports, dict):
        ports_list = list(ports.values())
    elif isinstance(ports, list):
        ports_list = ports
    for num, port_value in enumerate(ports_list):
        port_name = "port_%s" % num
        if 'remote_cidr' in port_value and port_value['remote_cidr']:
            res[port_name] = str(port_value['remote_cidr']) + "-"
        else:
            res[port_name] = ""

        if 'target' in port_value and port_value['target']:
            res[port_name] += "%s-" % port_value['target']

        # if target is defined, source_range should not be defined
        if 'source_range' in port_value and port_value['source_range']:
            res[port_name] += "%s:%s" % (port_value['source_range'][0],
                                         port_value['source_range'][1])
        elif 'source' in port_value and port_value['source']:
            res[port_name] += "%s" % port_value['source']

    return res


def getReconfigureInputs(template_str):
    """Get the inputs that can be reconfigured."""
    inputs = {}
    template = yaml.safe_load(template_str)
    tabs = template.get("metadata", {}).get("tabs", {})

    template_inputs = template.get('topology_template', {}).get('inputs', {})

    for tab, input_elems in tabs.items():
        for input_elem in input_elems:
            if isinstance(input_elem, dict):
                input_name = list(input_elem.keys())[0]
                input_params = list(input_elem.values())[0]

                elem = template_inputs.get(input_name, {})
                if "tag_type" in input_params:
                    elem["tag_type"] = input_params["tag_type"]
                if "pattern" in input_params:
                    elem["pattern"] = input_params["pattern"]

                if "reconfigure" in input_params and input_params["reconfigure"]:
                    if tab not in inputs:
                        inputs[tab] = {}
                    inputs[tab][input_name] = elem

    return inputs


def merge_templates(template, new_template):
    for item in ["inputs", "node_templates", "outputs"]:
        if item in new_template["topology_template"]:
            if item not in template["topology_template"]:
                template["topology_template"][item] = {}
            template["topology_template"][item].update(new_template["topology_template"][item])

    tabs = new_template.get("metadata", {}).get("tabs", {})
    if tabs:
        if "metadata" not in template:
            template["metadata"] = {}
        if "tabs" not in template["metadata"]:
            template["metadata"]["tabs"] = {}
        template["metadata"]["tabs"].update(tabs)

    return template
