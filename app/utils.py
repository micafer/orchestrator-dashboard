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
from radl.radl import outport
from radl.radl_json import parse_radl
from flask import flash, g
from app import appdb
from fnmatch import fnmatch
from hashlib import md5
from random import randint
from collections import OrderedDict
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


def getUserAuthData(access_token, cred, userid, cred_id=None):
    res = "type = InfrastructureManager; token = %s" % access_token

    fedcloud_sites = None
    for cred in cred.get_creds(userid):
        if cred['enabled'] and (cred_id is None or cred_id == cred['id']):
            res += "\\nid = site%s" % cred['id']
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

                if cred['host'] in fedcloud_sites:
                    site_info = fedcloud_sites[cred['host']]
                    if 'api_version' in site_info:
                        res += "; api_version  = %s" % site_info['api_version']

                    projectid = cred['project_id'] if 'project_id' in cred else None
                    project_ids = getCachedProjectIDs(site_info["id"])
                    if cred['vo'] in project_ids:
                        projectid = project_ids[cred['vo']]

                    if projectid:
                        res += "; domain = %s" % projectid
                    else:
                        print("Error not project ID for Cred %s." % cred['id'], file=sys.stderr)
                else:
                    print("Error %s not in list of FedCloud sites." % cred['host'], file=sys.stderr)

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
    toscaInfoOrder = toscaInfo = {}
    for tosca in toscaTemplates:
        with io.open(toscaDir + tosca) as stream:
            template = yaml.full_load(stream)

            toscaInfo[tosca] = {"valid": True,
                                "description": "TOSCA Template",
                                "metadata": {
                                    "order": 99999999,
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

        toscaInfoOrder = OrderedDict(sorted(toscaInfo.items(), key=lambda x: x[1]["metadata"]['order']))

    return toscaInfoOrder


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


def delete_dns_record(infid, im, auth_data):
    """Helper function to delete DNS registry created with the tosca.nodes.ec3.DNSRegistry node type."""
    template = ""
    try:
        response = im.get_inf_property(infid, 'tosca', auth_data)
        if not response.ok:
            raise Exception(response.text)
        template = response.text
    except Exception as ex:
        return False, "Error getting infrastructure template: %s" % ex

    msg = ""
    success = True
    try:
        yaml_template = yaml.safe_load(template)
        for node in list(yaml_template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.ec3.DNSRegistry":
                record = node["properties"]["record_name"]
                domain = node["properties"]["domain_name"]
                credentials = node["properties"]["dns_service_credentials"]["token"].strip()
                res, dm = delete_route53_record(record, domain, credentials)
                if not res:
                    success = False
                msg += dm + "\n"
    except Exception as ex:
        return False, "Error deleting DNS record: %s" % ex

    return success, msg


def delete_route53_record(record_name, domain, credentials):
    if not (record_name and domain and credentials):
        return False, "Error some empty value deleting DNS record"

    import boto3

    if credentials.find(":") != -1:
        parts = credentials.split(":")
        route53 = boto3.client(
            'route53',
            aws_access_key_id=parts[0],
            aws_secret_access_key=parts[1]
        )
    else:
        raise Exception("Invalid credentials")

    zone = route53.list_hosted_zones_by_name(DNSName=domain)["HostedZones"][0]

    record = route53.list_resource_record_sets(HostedZoneId=zone['Id'],
                                               StartRecordType='A',
                                               StartRecordName='%s.%s.' % (record_name, domain),
                                               MaxItems='1')["ResourceRecordSets"][0]

    if record["Name"] != '%s.%s.' % (record_name, domain):
        return False, "Discard to delete DNS record %s as is not %s.%s." % (record["Name"], record_name, domain)

    route53.change_resource_record_sets(
        HostedZoneId=zone['Id'],
        ChangeBatch={
            'Changes': [
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': record
                }
            ]
        })

    return True, record["Name"]


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
