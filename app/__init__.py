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
"""Main Flask App file."""

import yaml
import io
import os
import logging
import copy
import requests
from requests.exceptions import Timeout
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.consumer import OAuth2ConsumerBlueprint
from app.settings import Settings
from app.db_cred import DBCredentials
from app.vault_cred import VaultCredentials
from app.infra import Infrastructures
from app.im import InfrastructureManager
from app.ssh_key import SSHKey
from app.ott import OneTimeTokenData
from app import utils, appdb, db
from app.vault_info import VaultInfo
from oauthlib.oauth2.rfc6749.errors import InvalidTokenError, TokenExpiredError, InvalidGrantError, MissingTokenError
from werkzeug.exceptions import Forbidden
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, g, make_response
from markupsafe import Markup
from functools import wraps
from urllib.parse import urlparse
from radl import radl_parse
from radl.radl import deploy, description, Feature
from flask_apscheduler import APScheduler
from flask_wtf.csrf import CSRFProtect, CSRFError
from toscaparser.tosca_template import ToscaTemplate
from app.oaipmh.oai import OAI


def create_app(oidc_blueprint=None):
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    app.secret_key = "8210f566-4981-11ea-92d1-f079596e599b"
    app.config.from_file("config.json", load=json.load)
    settings = Settings(app.config)
    if settings.vault_url:
        cred = VaultCredentials(settings.vault_url)
    else:
        if 'CREDS_KEY' in os.environ:
            key = os.environ['CREDS_KEY']
        else:
            key = None
        cred = DBCredentials(settings.db_url, key)
    csrf = CSRFProtect(app)
    infra = Infrastructures(settings.db_url)
    im = InfrastructureManager(settings.imUrl, settings.imTimeout)
    ssh_key = SSHKey(settings.db_url)
    vault_info = VaultInfo(settings.db_url)
    ott = OneTimeTokenData(settings.vault_url)

    # To Reload internally the site cache
    scheduler = APScheduler()
    scheduler.api_enabled = False
    scheduler.init_app(app)
    scheduler.start()

    toscaTemplates = utils.loadToscaTemplates(settings.toscaDir)
    toscaInfo = utils.extractToscaInfo(settings.toscaDir, toscaTemplates, settings.hide_tosca_tags)

    app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json
    app.logger.debug("TOSCA INFO: " + json.dumps(toscaInfo))

    loglevel = app.config.get("LOG_LEVEL") if app.config.get("LOG_LEVEL") else "INFO"

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logging.basicConfig(level=numeric_level)

    oidc_base_url = settings.oidcUrl
    oidc_urls = utils.discover_oidc_urls(settings.oidcUrl)
    if oidc_urls:
        oidc_token_url = oidc_urls['token_endpoint']
        oidc_authorization_url = oidc_urls['authorization_endpoint']
        settings.oidcUserInfoPath = urlparse(oidc_urls['userinfo_endpoint']).path
    else:
        oidc_token_url = settings.oidcTokenUrl
        oidc_authorization_url = settings.oidcAuthorizeUrl

    if not oidc_blueprint:
        oidc_blueprint = OAuth2ConsumerBlueprint(
            "oidc", __name__,
            client_id=app.config['OIDC_CLIENT_ID'],
            client_secret=app.config['OIDC_CLIENT_SECRET'],
            scope=app.config['OIDC_SCOPES'],
            base_url=oidc_base_url,
            token_url=oidc_token_url,
            auto_refresh_url=oidc_token_url,
            authorization_url=oidc_authorization_url,
            redirect_to='home'
        )
    app.register_blueprint(oidc_blueprint, url_prefix="/login")

    @app.before_request
    def before_request_checks():
        if 'external_links' not in session:
            session['external_links'] = settings.external_links
        g.analytics_tag = settings.analytics_tag
        g.motomo_info = settings.motomo_info
        g.settings = settings

    def authorized_with_valid_token(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            if settings.debug_oidc_token:
                oidc_blueprint.session.token = {'access_token': settings.debug_oidc_token}
            else:
                try:
                    if not oidc_blueprint.session.authorized or 'username' not in session:
                        return logout(next_url=request.full_path)

                    if oidc_blueprint.session.token['expires_in'] < 20:
                        app.logger.debug("Force refresh token")
                        oidc_blueprint.session.get(settings.oidcUserInfoPath)
                except (InvalidTokenError, TokenExpiredError, InvalidGrantError, MissingTokenError):
                    flash("Token expired.", 'warning')
                    return logout(next_url=request.full_path)

            return f(*args, **kwargs)

        return decorated_function

    @app.route('/settings')
    @authorized_with_valid_token
    def show_settings():
        imUrl = "%s (v. %s)" % (settings.imUrl, im.get_version())
        access_token = oidc_blueprint.session.token['access_token']
        return render_template('settings.html', oidc_url=settings.oidcUrl, im_url=imUrl,
                               access_token=access_token, vault_url=settings.vault_url,
                               version=settings.version)

    @app.route('/login')
    def login():
        # Maintain filter session value
        template_filter = None
        if "filter" in session:
            template_filter = session["filter"]
        session.clear()
        if template_filter:
            session["filter"] = template_filter
        if 'next_url' in request.args:
            session["next"] = request.args.get("next_url")
        return render_template('home.html', oidc_name=settings.oidcName, oidc_image=settings.oidcImage)

    @app.route('/')
    def home():
        template_filter = None
        if 'filter' in request.args:
            template_filter = request.args['filter']
        if "filter" in session:
            template_filter = session["filter"]

        templates = {}
        for name, tosca in toscaInfo.items():
            if "parents" not in tosca["metadata"]:
                templates[name] = tosca

        if template_filter:
            session["filter"] = template_filter
            templates = {}
            for k, v in toscaInfo.items():
                if 'description' and v['description']:
                    if v['description'].find(template_filter) != -1 and "parents" not in tosca["metadata"]:
                        templates[k] = v

        if settings.debug_oidc_token:
            oidc_blueprint.session.token = {'access_token': settings.debug_oidc_token}
        else:
            if not oidc_blueprint.session.authorized:
                return redirect(url_for('login'))

        if 'userid' not in session or not session['userid']:
            # Only contact userinfo endpoint first time in session
            try:
                account_info = oidc_blueprint.session.get(settings.oidcUserInfoPath)
            except (InvalidTokenError, TokenExpiredError, InvalidGrantError):
                flash("Token expired.", 'warning')
                return logout()

            if account_info.ok:
                account_info_json = account_info.json()

                session["vos"] = None
                if 'eduperson_entitlement' in account_info_json:
                    session["vos"] = utils.getUserVOs(account_info_json['eduperson_entitlement'],
                                                      settings.vos_user_role)

                if settings.oidcGroups:
                    user_groups = []
                    if 'groups' in account_info_json:
                        user_groups = account_info_json['groups']
                    elif 'eduperson_entitlement' in account_info_json:
                        user_groups = account_info_json['eduperson_entitlement']
                    if not set(settings.oidcGroups).issubset(user_groups):
                        app.logger.debug("No match on group membership. User group membership: " +
                                         json.dumps(user_groups))
                        message = Markup('You need to be a member of the following groups: {0}. <br>'
                                         ' Please, visit <a href="{1}">{1}</a> and apply for the requested '
                                         'membership.'.format(json.dumps(settings.oidcGroups), settings.oidcUrl))
                        raise Forbidden(description=message)

                session['userid'] = account_info_json['sub']
                if 'name' in account_info_json:
                    session['username'] = account_info_json['name']
                else:
                    session['username'] = ""
                    if 'given_name' in account_info_json:
                        session['username'] = account_info_json['given_name']
                    if 'family_name' in account_info_json:
                        session['username'] += " " + account_info_json['family_name']
                    if session['username'] == "":
                        session['username'] = account_info_json['sub']
                if 'email' in account_info_json:
                    session['gravatar'] = utils.avatar(account_info_json['email'], 26)
                else:
                    session['gravatar'] = utils.avatar(account_info_json['sub'], 26)
            else:
                flash("Error getting User info: \n" + account_info.text, 'error')
                return render_template('home.html', oidc_name=settings.oidcName)

        # if there are any next url, redirect to it
        if "next" in session and session["next"]:
            next_url = session.pop("next")
            return redirect(url_for('home') + next_url[1:])
        else:
            return render_template('portfolio.html', templates=templates, parent=None)

    @app.route('/vminfo')
    @authorized_with_valid_token
    def showvminfo():
        access_token = oidc_blueprint.session.token['access_token']
        vmid = request.args['vmId']
        infid = request.args['infId']

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), infra.get_infra_cred_id(infid))
        try:
            response = im.get_vm_info(infid, vmid, auth_data)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')
            return redirect(url_for('showinfrastructures'))

        if not response.ok:
            flash("Error retrieving VM info: \n" + response.text, 'error')
            return redirect(url_for('showinfrastructures'))
        else:
            vminfo = {}
            state = ""
            nets = ""
            disks = ""
            deployment = ""
            app.logger.debug("VM Info: %s" % response.text)
            radl_json = response.json()["radl"]
            outports = utils.get_out_ports(radl_json)
            vminfo = utils.format_json_radl(radl_json)
            if "cpu.arch" in vminfo:
                del vminfo["cpu.arch"]
            if "state" in vminfo:
                state = vminfo["state"]
                del vminfo["state"]
            if "provider.type" in vminfo:
                deployment = vminfo["provider.type"]
                del vminfo["provider.type"]
            if "provider.vo" in vminfo:
                del vminfo["provider.vo"]
            if "provider.host" in vminfo:
                if "provider.port" in vminfo:
                    deployment += ": %s:%s" % (vminfo["provider.host"], vminfo["provider.port"])
                    del vminfo["provider.port"]
                else:
                    deployment += ": " + vminfo["provider.host"]
                del vminfo["provider.host"]
            if "disk.0.os.name" in vminfo:
                del vminfo["disk.0.os.name"]
            if "gpu.count" in vminfo and vminfo["gpu.count"] <= 0:
                del vminfo["gpu.count"]
                if "gpu.model" in vminfo:
                    del vminfo["gpu.model"]
                if "gpu.vendor" in vminfo:
                    del vminfo["gpu.vendor"]

            cont = 0
            while "net_interface.%s.connection" % cont in vminfo:
                if "net_interface.%s.ip" % cont in vminfo:
                    if cont > 0:
                        nets += Markup('<br/>')
                    nets += Markup('<i class="fa fa-network-wired"></i>')
                    nets += Markup(' <span class="badge bg-secondary">%s</span>' % cont)
                    nets += ": %s" % vminfo["net_interface.%s.ip" % cont]
                    del vminfo["net_interface.%s.ip" % cont]
                    if "net_interface.%s.dns_name" % cont in vminfo:
                        nets += " (%s)" % vminfo["net_interface.%s.dns_name" % cont]
                        del vminfo["net_interface.%s.dns_name" % cont]

                    if ("net_interface.%s.additional_dns_names" % cont in vminfo and
                            vminfo["net_interface.%s.additional_dns_names" % cont]):
                        dns_names = vminfo["net_interface.%s.additional_dns_names" % cont]
                        nets += " (%s)" % ", ".join(dns_names).replace("@", ".")
                        del vminfo["net_interface.%s.additional_dns_names" % cont]

                cont += 1

            cont = 0
            while "net_interface.%s.connection" % cont in vminfo:
                del vminfo["net_interface.%s.connection" % cont]
                cont += 1

            for elem in vminfo:
                if elem.endswith("size") and isinstance(vminfo[elem], (int, float)):
                    vminfo[elem] = "%.1f GiB" % (vminfo[elem] / 1073741824.0)

            cont = 0
            while "disk.%s.size" % cont in vminfo or "disk.%s.image.url" % cont in vminfo:
                if cont > 0:
                    disks += Markup('<br/>')
                disks += Markup('<i class="fa fa-database"></i> <span class="badge bg-secondary">'
                                '%s</span><br/>' % cont)

                prop_map = {"size": "Size", "image.url": "URL", "device": "Device", "mount_path": "Mount Path",
                            "fstype": "F.S. type", "os.flavour": "O.S. Flavor", "os.version": "O.S. Version",
                            "type": "Volume Type"}
                for name, label in prop_map.items():
                    prop = "disk.%s.%s" % (cont, name)
                    if prop in vminfo:
                        disks += Markup('&nbsp;&nbsp;')
                        disks += "- %s: %s" % (label, vminfo[prop])
                        disks += Markup('<br/>')
                        del vminfo[prop]

                cont += 1

            # delete disk info of disks without size
            for prop_name in ["device", "fstype", "mount_path"]:
                new_cont = cont
                prop = "disk.%s.%s" % (new_cont, prop_name)
                while prop in vminfo:
                    del vminfo[prop]
                    new_cont += 1

            str_outports = ""
            if outports:
                for port in outports:
                    remote_cidr = ""
                    if port.get_remote_cidr() != "0.0.0.0/0":
                        remote_cidr = "%s-" % port.get_remote_cidr()
                    str_outports += Markup('<i class="fas fa-project-diagram"></i> <span class="badge '
                                           'bg-secondary">%s%s</span>' % (remote_cidr, port.get_remote_port()))
                    if not port.is_range():
                        if port.get_remote_port() != port.get_local_port():
                            str_outports += Markup(' <i class="fas fa-long-arrow-alt-right">'
                                                   '</i> <span class="badge bg-secondary">%s</span>' %
                                                   port.get_local_port())
                    else:
                        str_outports += Markup(' : </i> <span class="badge bg-secondary">%s</span>' %
                                               port.get_local_port())
                    str_outports += Markup('<br/>')

        return render_template('vminfo.html', infid=infid, vmid=vmid, vminfo=vminfo, outports=str_outports,
                               state=state, nets=nets, deployment=deployment, disks=disks)

    @app.route('/managevm/<op>/<infid>/<vmid>', methods=['POST'])
    @authorized_with_valid_token
    def managevm(op=None, infid=None, vmid=None):
        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), infra.get_infra_cred_id(infid))
        try:
            if op == "reconfigure":
                response = im.reconfigure_inf(infid, auth_data, [vmid])
            elif op == "resize":
                form_data = request.form.to_dict()
                cpu = int(form_data['cpu'])
                memory = float(form_data['memory'])
                gpu = int(form_data.get('gpu', 0))
                disk_size = float(form_data.get('disk_size', 0))

                vminforesp = im.get_vm_info(infid, vmid, auth_data, "text/plain")
                if vminforesp.ok:
                    vminfo = radl_parse.parse_radl(vminforesp.text)
                    vminfo.systems[0].delValue("instance_type")
                    vminfo.systems[0].delValue("cpu.count")
                    vminfo.systems[0].addFeature(Feature("cpu.count", ">=", cpu),
                                                 conflict="other", missing="other")
                    vminfo.systems[0].delValue("memory.size")
                    vminfo.systems[0].addFeature(Feature("memory.size", ">=", memory, "GB"),
                                                 conflict="other", missing="other")
                    if gpu > 0:
                        vminfo.systems[0].delValue("gpu.count")
                        vminfo.systems[0].addFeature(Feature("gpu.count", ">=", gpu),
                                                     conflict="other", missing="other")
                    if disk_size > 0:
                        vminfo.systems[0].delValue("disks.free_size")
                        vminfo.systems[0].delValue("disks.0.free_size")
                        vminfo.systems[0].addFeature(Feature("disks.free_size", ">=", disk_size, "GB"),
                                                     conflict="other", missing="other")
                    response = im.resize_vm(infid, vmid, str(vminfo), auth_data)
                else:
                    raise Exception("Error getting VM info: %s" % vminforesp.text)
            else:
                response = im.manage_vm(op, infid, vmid, auth_data)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')
            return redirect(url_for('showinfrastructures'))

        if response.ok:
            flash("Operation '%s' successfully made on VM ID: %s" % (op, vmid), 'success')
        else:
            flash("Error making %s op on VM %s: \n%s" % (op, vmid, response.text), 'error')

        if op == "terminate":
            return redirect(url_for('showinfrastructures'))
        else:
            return redirect(url_for('showvminfo', infId=infid, vmId=vmid))

    @app.route('/infrastructures')
    @authorized_with_valid_token
    def showinfrastructures():
        access_token = oidc_blueprint.session.token['access_token']

        reload_infid = None
        if 'reload' in request.args:
            reload_infid = request.args['reload']

        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        inf_list = []
        try:
            inf_list = im.get_inf_list(auth_data)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')

        infrastructures = {}
        for inf_id in inf_list:
            infrastructures[inf_id] = {}
            try:
                infra_data = infra.get_infra(inf_id)
            except Exception:
                infra_data = {}
            infrastructures[inf_id] = {'name': '', 'state': {}}
            if 'name' in infra_data:
                infrastructures[inf_id]['name'] = infra_data["name"]
            else:
                try:
                    response = im.get_inf_property(inf_id, "radl", auth_data)
                    if not response.ok:
                        raise Exception(response.text)
                    infra_radl = radl_parse.parse_radl(response.text)
                    if infra_radl.description and infra_radl.description.getValue("name"):
                        infra_data["name"] = infra_radl.description.getValue("name")
                        infrastructures[inf_id]['name'] = infra_data["name"]
                        try:
                            infra.write_infra(inf_id, infra_data)
                        except Exception as se:
                            app.logger.error("Error saving infrastructure name: %s" % se)
                except Exception as ex:
                    app.logger.error("Error getting infrastructure name: %s" % ex)
            if 'state' in infra_data:
                infrastructures[inf_id]['state'] = infra_data["state"]
            if 'site' not in infra_data:
                try:
                    response = im.get_vm_info(inf_id, "0", auth_data)
                    if not response.ok:
                        raise Exception(response.text)
                    radl_json = response.json()["radl"]
                except Exception as ex:
                    app.logger.exception("Error getting vm info: %s" % ex)
                    radl_json = []
                try:
                    creds = cred.get_creds(get_cred_id())
                except Exception as ex:
                    app.logger.exception("Error getting user credentials: %s" % ex)
                    creds = []
                site_info = utils.get_site_info_from_radl(radl_json, creds)
                if site_info:
                    infra_data["site"] = site_info
                try:
                    infra.write_infra(inf_id, infra_data)
                except Exception as se:
                    app.logger.error("Error saving infrastructure site: %s" % se)
            if 'site' in infra_data:
                site_info = ""
                if "site_name" in infra_data["site"]:
                    site_info += "Site: " + infra_data["site"]["site_name"]
                else:
                    if "host" in infra_data["site"] and infra_data["site"]["host"]:
                        site_info += "Host: " + infra_data["site"]["host"]
                    if "tenant" in infra_data["site"] and infra_data["site"]["tenant"]:
                        if site_info:
                            site_info += "<br>"
                        site_info += "Tenant: " + infra_data["site"]["tenant"]

                if "subscription_id" in infra_data["site"] and infra_data["site"]["subscription_id"]:
                    site_info += "Subs. ID: " + infra_data["site"]["subscription_id"]
                if "vo" in infra_data["site"] and infra_data["site"]["vo"]:
                    site_info += "<br>VO: " + infra_data["site"]["vo"]
                if "project" in infra_data["site"] and infra_data["site"]["project"]:
                    site_info += "Project: " + infra_data["site"]["project"]

                infrastructures[inf_id]['cloud_type'] = infra_data["site"]["type"]
                infrastructures[inf_id]['site'] = Markup(site_info)

        return render_template('infrastructures.html', infrastructures=infrastructures,
                               reload=reload_infid, inf_list=inf_list)

    @app.route('/infrastructures/state')
    @authorized_with_valid_token
    def infrastructure_state():
        access_token = oidc_blueprint.session.token['access_token']
        infid = request.args['infid']
        if not infid:
            return {"state": "error", "vm_states": {}}

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), infra.get_infra_cred_id(infid))
        try:
            state = im.get_inf_state(infid, auth_data)
            try:
                infra.write_infra(infid, {"state": state})
            except Exception as ex:
                app.logger.error("Error saving infrastructure state: %s" % ex)
            return state
        except Timeout as texs:
            app.logger.error("Timeout waiting infrastructure state: %s" % texs)
            try:
                # There is a timeout
                infra_data = infra.get_infra(infid)
                infra_data["state"]["state"] = "timeout"
                return infra_data["state"]
            except Exception:
                return {"state": "error", "vm_states": {}}
        except Exception as exs:
            app.logger.error("Error getting infrastructure state: %s" % exs)
            try:
                # We cannot get the current state, show error, but return
                # previous VMs states
                infra_data = infra.get_infra(infid)
                infra_data["state"]["state"] = "error"
                return infra_data["state"]
            except Exception:
                return {"state": "error", "vm_states": {}}

    def hide_sensitive_data(template):
        """Remove/Hide sensitive data (passwords, credentials)."""

        # TODO: Replace using this regexp
        # AKID: (?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])
        # SK:   (?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])
        data = yaml.full_load(template)

        for node in list(data['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.indigo.LRMS.FrontEnd.Kubernetes":
                try:
                    if "cert_manager_challenge_dns01_ak" in node["properties"]:
                        node["properties"]["cert_manager_challenge_dns01_ak"] = "AK"
                    if "cert_manager_challenge_dns01_sk" in node["properties"]:
                        node["properties"]["cert_manager_challenge_dns01_sk"] = "SK"
                except KeyError:
                    pass

            if node["type"] == "tosca.nodes.ec3.ElasticCluster":
                if "im_auth" in node["properties"]:
                    node["properties"]["im_auth"] = "redacted"
                if "auth_token" in node["properties"]:
                    node["properties"]["auth_token"] = "redacted"
                try:
                    node["interfaces"]["Standard"]["configure"]["inputs"]["CLIENT_ID"] = "client_id"
                    node["interfaces"]["Standard"]["configure"]["inputs"]["CLIENT_SECRET"] = "client_secret"
                except KeyError:
                    pass

        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @app.route('/template/<infid>')
    @authorized_with_valid_token
    def template(infid=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        template = ""
        try:
            response = im.get_inf_property(infid, 'tosca', auth_data)
            if not response.ok:
                raise Exception(response.text)
            template = hide_sensitive_data(response.text)
        except Exception as ex:
            flash("Error getting template: \n%s" % ex, "error")

        return render_template('deptemplate.html', template=template)

    def add_colors(log):
        """Add color in error messages in logs."""
        res = ""
        lines = log.split('\n')
        for n, line in enumerate(lines):
            if "ERROR executing task" in line or ("fatal: " in line and "...ignoring" not in lines[n + 1]):
                res += Markup('<span class="bg-danger text-white">%s</span><br>' % line)
            else:
                res += Markup("%s<br>\n" % line)
        return res

    def add_vm_separators(log):
        res = ""
        lines = log.split('\n')
        vms = 0
        for line in lines:
            sline = str(line)
            if len(sline) > 8 and len(sline) < 12 and sline.startswith("VM ") and sline.endswith(":<br>"):
                res += Markup('<p id="vm_%s" class="bg-dark text-white">%s</p><br>' % (vms, line))
                vms += 1
            else:
                res += Markup("%s\n" % line)
        return res, vms

    @app.route('/log/<infid>')
    @authorized_with_valid_token
    def inflog(infid=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        log = "Not found"
        vms = 0
        try:
            response = im.get_inf_property(infid, 'contmsg', auth_data)
            if not response.ok:
                raise Exception(response.text)
            log = add_colors(response.text)
            log, vms = add_vm_separators(log)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')

        return render_template('inflog.html', log=log, vms=vms)

    @app.route('/vmlog/<infid>/<vmid>')
    @authorized_with_valid_token
    def vmlog(infid=None, vmid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        log = "Not found"
        try:
            response = im.get_vm_contmsg(infid, vmid, auth_data)
            if not response.ok:
                raise Exception(response.text)
            log = add_colors(response.text)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')

        return render_template('inflog.html', log=log, vmid=vmid, vms=0)

    @app.route('/outputs/<infid>')
    @authorized_with_valid_token
    def infoutputs(infid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        outputs = {}
        try:
            response = im.get_inf_property(infid, 'outputs', auth_data)
            if not response.ok:
                raise Exception(response.text)

            outputs = response.json()["outputs"]
            for elem in outputs:
                if isinstance(outputs[elem], str) and (outputs[elem].startswith('http://') or
                                                       outputs[elem].startswith('https://')):
                    outputs[elem] = Markup("<a href='%s' target='_blank'>%s</a>" % (outputs[elem], outputs[elem]))
        except Exception as ex:
            flash("Error: %s." % ex, 'error')

        return render_template('outputs.html', infid=infid, outputs=outputs)

    @app.route('/configure')
    @authorized_with_valid_token
    def configure():
        selected_tosca = None
        inf_id = request.args.get('inf_id', None)
        childs = request.args.get('childs', None)
        if childs:
            childs = childs.split(",")

        inputs = {}
        infra_name = ""
        if inf_id:
            access_token = oidc_blueprint.session.token['access_token']
            auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
            try:
                response = im.get_inf_property(inf_id, 'tosca', auth_data)
                if not response.ok:
                    raise Exception(response.text)
                template = response.text
                data = yaml.full_load(template)
                for input_name, input_value in list(data['topology_template']['inputs'].items()):
                    inputs[input_name] = input_value.get("default", None)
                if 'filename' in data['metadata'] and data['metadata']['filename']:
                    selected_tosca = data['metadata']['filename']
                if 'childs' in data['metadata']:
                    childs = data['metadata']['childs']
            except Exception as ex:
                flash("Error getting TOSCA template inputs: \n%s" % ex, "error")

            try:
                infra_data = infra.get_infra(inf_id)
                infra_name = infra_data["name"] + " New"
            except Exception:
                pass

        if 'selected_tosca' in request.args:
            selected_tosca = request.args['selected_tosca']

        if not selected_tosca or selected_tosca not in toscaInfo:
            flash("Invalid TOSCA template name: %s" % selected_tosca, "error")
            return redirect(url_for('home'))

        if not utils.valid_template_vos(session['vos'], toscaInfo[selected_tosca]["metadata"]):
            flash("Invalid TOSCA template name: %s" % selected_tosca, "error")
            return redirect(url_for('home'))

        child_templates = {}
        selected_template = copy.deepcopy(toscaInfo[selected_tosca])
        if "childs" in toscaInfo[selected_tosca]["metadata"]:
            if childs is not None:
                for child in childs:
                    if child in toscaInfo and utils.valid_template_vos(session['vos'], toscaInfo[child]["metadata"]):
                        child_templates[child] = toscaInfo[child]
                        if "inputs" in toscaInfo[child]:
                            for k, v in toscaInfo[child]["inputs"].items():
                                if k not in selected_template["inputs"]:
                                    selected_template["inputs"][k] = v
                                else:
                                    selected_template["inputs"][k].update(v)
                        if "tabs" in toscaInfo[child]:
                            selected_template["tabs"].extend(toscaInfo[child]["tabs"])
            else:
                for child in toscaInfo[selected_tosca]["metadata"]["childs"]:
                    if child in toscaInfo and utils.valid_template_vos(session['vos'], toscaInfo[child]["metadata"]):
                        child_templates[child] = toscaInfo[child]
                return render_template('portfolio.html', templates=child_templates, parent=selected_tosca)
        else:
            app.logger.debug("Template: " + json.dumps(toscaInfo[selected_tosca]))

        # Enable to get input values from URL parameters
        for input_name, input_value in selected_template["inputs"].items():
            value = request.args.get(input_name, None)
            if value:
                if input_value['type'] == 'integer':
                    inputs[input_name] = int(value)
                elif input_value['type'] == 'float':
                    inputs[input_name] = float(value)
                elif input_value['type'] == 'map' and input_value['entry_schema']['type'] in utils.PORT_SPECT_TYPES:
                    inputs[input_name] = json.loads(value)
                else:
                    inputs[input_name] = value

        return render_template('createdep.html',
                               template=selected_template,
                               selectedTemplate=selected_tosca,
                               input_values=inputs,
                               infra_name=infra_name, child_templates=child_templates,
                               vos=utils.getVOs(session), utils=utils)

    @app.route('/vos')
    def getvos():
        res = ""
        for vo in utils.getVOs(session):
            res += '<option name="selectedVO" value=%s>%s</option>' % (vo, vo)
        return res

    @app.route('/sites/<vo>')
    def getsites(vo=None):
        res = ""
        static_sites = utils.getStaticSites(vo)
        for site_name, site in static_sites.items():
            res += '<option name="selectedSite" value=%s>%s</option>' % (site['url'], site_name)

        appdb_sites = appdb.get_sites(vo)
        for site_name, site in appdb_sites.items():
            # avoid site duplication
            if site_name not in static_sites:
                if site["state"]:
                    site["state"] = " (WARNING: %s state!)" % site["state"]
                res += '<option name="selectedSite" value=%s>%s%s</option>' % (site['url'], site_name, site["state"])

        return res

    @app.route('/images/<cred_id>')
    @authorized_with_valid_token
    def getimages(cred_id=None):
        res = ""
        local = request.args.get('local', None)

        if local:
            access_token = oidc_blueprint.session.token['access_token']
            auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), cred_id)
            try:
                response = im.get_cloud_images(cred_id, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                for image in response.json()["images"]:
                    res += '<option name="selectedSiteImage" value=%s>%s</option>' % (image['uri'], image['name'])
            except Exception as ex:
                res += '<option name="selectedSiteImage" value=%s>%s</option>' % (ex, ex)

        else:
            site, _, vo = utils.get_site_info(cred_id, cred, get_cred_id())
            for image_name, image_id in appdb.get_images(site['id'], vo):
                res += '<option name="selectedImage" value=%s>%s</option>' % (image_id, image_name)
        return res

    @app.route('/usage/<cred_id>')
    @authorized_with_valid_token
    def getusage(cred_id=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), cred_id)
        try:
            response = im.get_cloud_quotas(cred_id, auth_data)
            if not response.ok:
                raise Exception(response.text)
            return json.dumps(response.json()["quotas"])
        except Exception as ex:
            return "Error loading site quotas: %s!" % str(ex), 400

    @app.route('/secret/<path>')
    def secret(path=None):
        try:
            auth = request.headers.get('Authorization')
            if auth and auth.startswith('Bearer '):
                token = auth.split(' ')[1]
                data = ott.get_data(path, token)
                return make_response(data, 200, {"Content-Type": "text/plain"})
            else:
                return make_response("Unauthorized", 401)
        except Exception as ex:
            return make_response("Invalid request: %s" % ex, 400)

    def add_image_to_template(template, image):
        # Add the image to all compute nodes

        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.indigo.Compute":
                if "capabilities" not in node:
                    node["capabilities"] = {}
                if "os" not in node["capabilities"]:
                    node["capabilities"]["os"] = {}
                if "properties" not in node["capabilities"]["os"]:
                    node["capabilities"]["os"]["properties"] = {}
                # Only set the image if the image is not already set
                if not node["capabilities"]["os"]["properties"].get("image"):
                    node["capabilities"]["os"]["properties"]["image"] = image

        app.logger.debug(yaml.dump(template, default_flow_style=False))

        return template

    def add_auth_to_template(template, access_token, cred_id):
        # Add the auth_data ElasticCluster node

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), cred_id, True, False)

        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.ec3.ElasticCluster":
                if "properties" not in node:
                    node["properties"] = {}
                token, path = ott.write_data(access_token, auth_data)
                node["properties"]["auth_token"] = {"token": token,
                                                    "url": url_for('secret', path=path, _external=True)}

        app.logger.debug(yaml.dump(template, default_flow_style=False))

        return template

    def add_instance_name_to_compute(template, inf_name):
        # Prepend the infrastructure name to tne instance name

        for node_name, node in template['topology_template']['node_templates'].items():
            if node["type"] == "tosca.nodes.indigo.Compute":
                if "properties" not in node:
                    node["properties"] = {}
                    # Remove non ascii chars to avoid issues
                    inf_name = ''.join(char for char in inf_name if ord(char) < 128)
                node["properties"]["instance_name"] = "%s_%s" % (inf_name.replace(" ", "_"), node_name)

        app.logger.debug(yaml.dump(template, default_flow_style=False))

        return template

    def set_inputs_to_template(template, inputs):
        # Add the image to all compute nodes
        if 'inputs' not in template['topology_template']:
            return template

        for name, value in template['topology_template']['inputs'].items():
            if name in inputs:
                if value["type"] == "integer":
                    value["default"] = int(inputs[name])
                elif value["type"] == "float":
                    value["default"] = float(inputs[name])
                elif value["type"] == "boolean":
                    if inputs[name].lower() in ['yes', 'true', '1']:
                        value["default"] = True
                    else:
                        value["default"] = False
                elif value["type"] in ["map", "list"] and value["entry_schema"]["type"] not in ["map", "list"]:
                    try:
                        value["default"] = utils.get_list_values(name, inputs, value["entry_schema"]["type"],
                                                                 value["type"])
                    except Exception as ex:
                        flash("Invalid input value '%s' specified: '%s'." % (name, ex), "warning")
                        value["default"] = []
                # Special case for ports, convert a list of strings like 80,443,8080-8085,9000-10000/udp
                # to a PortSpec map or list
                elif value["type"] in ["map", "list"] and value["entry_schema"]["type"] in utils.PORT_SPECT_TYPES:
                    try:
                        value["default"] = utils.get_list_values(name, inputs, "PortSpec", value["type"])
                    except Exception as ex:
                        flash("Invalid input value '%s' specified: '%s'." % (name, ex), "warning")
                        value["default"] = {}
                else:
                    value["default"] = inputs[name]

        app.logger.debug(yaml.dump(template, default_flow_style=False))
        return template

    def add_network_id_to_template(template, priv_network_id, pub_network_id):
        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.network.Network":
                try:
                    if node["properties"]["network_type"] == "public":
                        node["properties"]["network_name"] = pub_network_id
                    elif node["properties"]["network_type"] == "private":
                        node["properties"]["network_name"] = priv_network_id
                except KeyError:
                    # if network_type is not set it is a private net
                    if "properties" not in node:
                        node["properties"] = {}
                    node["properties"]["network_name"] = priv_network_id
            elif node["type"] == "tosca.nodes.indigo.Compute":
                try:
                    if node["capabilities"]["endpoint"]["properties"]["network_name"] == "PUBLIC":
                        node["capabilities"]["endpoint"]["properties"]["network_name"] = "%s,%s" % (priv_network_id,
                                                                                                    pub_network_id)
                except KeyError:
                    continue
        return template

    def add_ssh_keys_to_template(template):
        for num, _, sshkey in ssh_key.get_ssh_keys(session['userid']):
            artifact = "https://raw.githubusercontent.com/grycap/ec3/tosca/tosca/artifacts/add_ssh_key.yml"

            computers = []
            for node_name, node in template['topology_template']['node_templates'].items():
                if node["type"] in ["tosca.nodes.indigo.Compute", "tosca.nodes.Compute"]:
                    computers.append(node_name)

            for computer in computers:
                ssh_node = {"type": "tosca.nodes.ec3.Application",
                            "interfaces": {"Standard": {"configure": {"implementation": artifact,
                                                                      "inputs": {"ssh_key": sshkey}}}},
                            "requirements": [{"host": computer}]}
                template['topology_template']['node_templates']["dash_ssh_key_%s_%s" % (computer, num)] = ssh_node

        return template

    @app.route('/submit', methods=['POST'])
    @authorized_with_valid_token
    def createdep():

        form_data = request.form.to_dict()

        app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

        childs = []
        if 'extra_opts.childs' in form_data:
            childs = form_data['extra_opts.childs'].split(",")
        cred_id = form_data['extra_opts.selectedCred']
        cred_data = cred.get_cred(cred_id, get_cred_id())
        access_token = oidc_blueprint.session.token['access_token']

        site = {}
        image = None
        priv_network_id = None
        pub_network_id = None
        if cred_data['type'] in ['fedcloud', 'OpenStack', 'OpenNebula', 'Linode', 'Orange', 'GCE', 'CH']:
            if cred_data['type'] == 'fedcloud':
                site, _, vo = utils.get_site_info(cred_id, cred, get_cred_id())
                if "networks" in site and vo in site["networks"]:
                    if "private" in site["networks"][vo]:
                        priv_network_id = site["networks"][vo]["private"]
                    if "public" in site["networks"][vo]:
                        pub_network_id = site["networks"][vo]["public"]

            if form_data.get('extra_opts.selectedImage', "") != "" and 'name' in site:
                image = "appdb://%s/%s?%s" % (site['name'], form_data['extra_opts.selectedImage'], vo)
            elif form_data.get('extra_opts.selectedSiteImage', "") != "":
                image = form_data['extra_opts.selectedSiteImage']
        else:
            image_id = form_data['extra_opts.imageID']
            protocol_map = {
                'EC2': 'aws',
                'Kubernetes': 'docker',
                'Azure': 'azr'
            }
            image = "%s://%s" % (protocol_map.get(cred_data['type']), image_id)

        if not image:
            flash("No correct image specified.", "error")
            return redirect(url_for('showinfrastructures'))

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), cred_id, True)

        # Special case for a TOSCA template provided by the user
        if request.args.get('template') == 'tosca.yml':
            try:
                if form_data.get('tosca'):
                    template = yaml.safe_load(form_data.get('tosca'))
                    ToscaTemplate(yaml_dict_tpl=copy.deepcopy(template))
                else:
                    response = requests.get(form_data.get('tosca_url'), timeout=10)
                    response.raise_for_status()
                    template = yaml.safe_load(response.text)
                    ToscaTemplate(yaml_dict_tpl=copy.deepcopy(template))
            except Exception as ex:
                msg = "%s" % ex
                flash("Invalid TOSCA specified: '%s'." % msg[:512], "error")
                return redirect(url_for('showinfrastructures'))
        else:
            with io.open(settings.toscaDir + request.args.get('template')) as stream:
                template = yaml.full_load(stream)

        for child in childs:
            with io.open(settings.toscaDir + child) as stream:
                template = utils.merge_templates(template, yaml.full_load(stream))

        if 'metadata' not in template:
            template['metadata'] = {}
        template['metadata']['filename'] = request.args.get('template')
        template['metadata']['childs'] = childs

        if priv_network_id and pub_network_id:
            template = add_network_id_to_template(template, priv_network_id, pub_network_id)

        if form_data['infra_name']:
            template['metadata']['infra_name'] = form_data['infra_name']
            template = add_instance_name_to_compute(template, form_data['infra_name'])

        template = add_image_to_template(template, image)

        template = add_auth_to_template(template, access_token, cred_id)

        template = add_ssh_keys_to_template(template)

        inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

        app.logger.debug("Parameters: " + json.dumps(inputs))

        template = set_inputs_to_template(template, inputs)

        payload = yaml.dump(template, default_flow_style=False, sort_keys=False)

        try:
            response = im.create_inf(payload, auth_data)
            if not response.ok:
                raise Exception(response.text)

            try:
                # Remove all sensible data
                for elem in ["password", "username", "token", "proxy", "private_key", "client_id", "secret"]:
                    if elem in cred_data:
                        del cred_data[elem]
                if "name" in site:
                    cred_data["site_name"] = site["name"]
                inf_id = os.path.basename(response.text)
                infra.write_infra(inf_id, {"name": form_data['infra_name'],
                                           "site": cred_data,
                                           "state": {"state": "pending", "vm_states": {}}})
            except Exception as ex:
                flash("Error storing Infrastructure name: %s" % str(ex), "warning")

        except Exception as ex:
            flash("Error creating infrastrucrure: \n%s." % ex, 'error')

        return redirect(url_for('showinfrastructures'))

    @app.route('/manage_creds')
    @authorized_with_valid_token
    def manage_creds():
        creds = {}

        try:
            creds = cred.get_creds(get_cred_id())
            # Get the project_id in case it has changed
            utils.get_project_ids(creds)
        except Exception as e:
            flash("Error retrieving credentials: \n" + str(e), 'warning')

        if request.args.get('json', 0):
            json_creds = json.dumps(creds)
            to_delete = ['password', 'token', 'proxy', 'private_key', 'client_id', 'secret']
            for cred in json_creds:
                for key in to_delete:
                    if key in cred:
                        del cred[key]
            return json_creds
        else:
            return render_template('service_creds.html', creds=creds,
                                   vault=(settings.vault_url and settings.enable_external_vault))

    @app.route('/write_creds', methods=['GET', 'POST'])
    @authorized_with_valid_token
    def write_creds():
        cred_id = request.args.get('cred_id', "")
        cred_type = request.args.get('cred_type', "")
        app.logger.debug("service_id={}".format(cred_id))

        if request.method == 'GET':
            res = {}
            try:
                if cred_id:
                    res = cred.get_cred(cred_id, get_cred_id())
                    cred_type = res['type']
            except Exception as ex:
                flash("Error reading credentials %s!" % ex, 'error')

            return render_template('modal_creds.html', creds=res, cred_id=cred_id,
                                   cred_type=cred_type, vos=utils.getVOs(session))
        else:
            app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

            creds = request.form.to_dict()
            if 'cred_id' in creds:
                cred_id = creds['cred_id']
                del creds['cred_id']
            if 'password' in request.files:
                if request.files['password'].filename != "":
                    creds['password'] = request.files['password'].read().decode()

            try:
                if 'password' in creds and creds['password'] in [None, '']:
                    del creds['password']
                if 'csrf_token' in creds:
                    del creds['csrf_token']
                val_res = 0
                if not cred_id:
                    val_res, val_msg = cred.validate_cred(get_cred_id(), creds)
                    if val_res != 0:
                        if val_res == 1:
                            flash("%s. Not addded." % val_msg, 'info')
                        elif val_res == 2:
                            flash(val_msg, 'warning')
                if val_res != 1:
                    # Get project_id to save it to de DB
                    utils.get_project_ids([creds])
                    cred.write_creds(creds["id"], get_cred_id(), creds, cred_id in [None, ''])
                    if val_res == 0:
                        flash("Credentials successfully written!", 'success')
            except db.IntegrityError:
                flash("Error writing credentials: Duplicated Credential ID!", 'error')
            except Exception as ex:
                flash("Error writing credentials: %s!" % ex, 'error')

            return redirect(url_for('manage_creds'))

    @app.route('/delete_creds')
    @authorized_with_valid_token
    def delete_creds():

        cred_id = request.args.get('cred_id', "")
        try:
            cred.delete_cred(cred_id, get_cred_id())
            flash("Credentials successfully deleted!", 'success')
        except Exception as ex:
            flash("Error deleting credentials %s!" % ex, 'error')

        return redirect(url_for('manage_creds'))

    @app.route('/enable_creds')
    @authorized_with_valid_token
    def enable_creds():
        cred_id = request.args.get('cred_id', "")
        enable = request.args.get('enable', 0)
        try:
            if enable == '1':
                val_res, val_msg = cred.validate_cred(get_cred_id(), cred_id)
                if val_res == 2:
                    flash(val_msg, 'warning')
            cred.enable_cred(cred_id, get_cred_id(), enable)
        except Exception as ex:
            flash("Error updating credentials %s!" % ex, 'error')

        return redirect(url_for('manage_creds'))

    @app.route('/addresources/<infid>', methods=['POST', 'GET'])
    @authorized_with_valid_token
    def addresources(infid=None):

        access_token = oidc_blueprint.session.token['access_token']

        if request.method == 'GET':
            auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
            try:
                response = im.get_inf_property(infid, 'radl', auth_data)
                if not response.ok:
                    raise Exception(response.text)

                systems = []
                image_url_str = None
                image_url = None
                try:
                    radl = radl_parse.parse_radl(response.text)
                    systems = radl.systems
                    image_url_str = systems[0].getValue("disk.0.image.url")
                    image_url = urlparse(image_url_str)
                except Exception as ex:
                    flash("Error parsing RADL: \n%s" % str(ex), 'error')

                images = None
                try:
                    infra_data = infra.get_infra(infid)
                    cred_id = None
                    if infra_data.get("site", {}).get("id"):
                        cred_id = infra_data["site"]["id"]
                    auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), cred_id)
                    response = im.get_cloud_images(cred_id, auth_data)
                    if not response.ok:
                        raise Exception(response.text)
                    images = [(image['uri'], image['name'], image['uri'] == image_url_str)
                              for image in response.json()["images"]]
                except Exception as ex:
                    app.logger.warning('Error getting site images: %s', (ex))

                return render_template('addresource.html', infid=infid, systems=systems,
                                       image_url=image_url, images=images)
            except Exception as ex:
                flash("Error getting RADL: \n%s" % ex, 'error')
                return redirect(url_for('showinfrastructures'))
        else:
            form_data = request.form.to_dict()

            auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), infra.get_infra_cred_id(infid))
            try:
                response = im.get_inf_property(infid, 'radl', auth_data)
            except Exception as ex:
                flash("Error: %s." % ex, 'error')

            if response.ok:
                radl = None
                total_dep = 0
                try:
                    radl = radl_parse.parse_radl(response.text)
                    radl.deploys = []
                    for system in radl.systems:
                        if 'newImage' in form_data and form_data['newImage']:
                            system.setValue('disk.0.image.url', form_data['newImage'])
                        sys_dep = deploy(system.name, 0)
                        if "%s_num" % system.name in form_data:
                            vm_num = int(form_data["%s_num" % system.name])
                            if vm_num > 0:
                                sys_dep.vm_number = vm_num
                                total_dep += vm_num
                        radl.deploys.append(sys_dep)
                except Exception as ex:
                    flash("Error parsing RADL: \n%s\n%s" % (str(ex), response.text), 'error')

                if radl and total_dep:
                    try:
                        response = im.addresource_inf(infid, str(radl), auth_data)
                        if not response.ok:
                            raise Exception(response.text)
                        num = len(response.json()["uri-list"])
                        flash("%d nodes added successfully" % num, 'success')
                    except Exception as ex:
                        flash("Error adding nodes: \n%s\n%s" % (ex, response.text), 'error')

                if total_dep == 0:
                    flash("No nodes added (0 nodes set)", 'warning')

                return redirect(url_for('showinfrastructures'))
            else:
                flash("Error getting RADL: \n%s" % (response.text), 'error')
                return redirect(url_for('showinfrastructures'))

    @app.route('/manage_inf/<infid>/<op>', methods=['POST'])
    @authorized_with_valid_token
    def manage_inf(infid=None, op=None):
        access_token = oidc_blueprint.session.token['access_token']

        # Try to get the Cred ID to restrict the auth info sent to the IM
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id(), infra.get_infra_cred_id(infid))
        reload = None
        form_data = request.form.to_dict()

        try:
            if op == "descr":
                if 'description' in form_data and form_data['description'] != "":
                    try:
                        infra_data = infra.get_infra(infid)
                        infra_data["name"] = form_data['description']

                        # Set the name in the infrastructure RADL
                        response = im.get_inf_property(infid, "radl", auth_data)
                        if not response.ok:
                            raise Exception(response.text)
                        infra_radl = radl_parse.parse_radl(response.text)
                        if not infra_radl.description:
                            infra_radl.description = description("desc")
                        if not infra_radl.description.getValue("name"):
                            infra_radl.description.setValue("name", infra_data["name"])
                        infra_radl.deploys = []
                        response = im.addresource_inf(infid, str(infra_radl), auth_data, context=False)
                        if not response.ok:
                            raise Exception(response.text)

                        infra.write_infra(infid, infra_data)
                    except Exception as uex:
                        flash("Error updating infrastructure description: %s" % str(uex), "error")
            elif op in ["start", "stop"]:
                response = im.manage_inf(op, infid, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("Operation '%s' successfully made on Infrastructure ID: %s" % (op, infid), 'success')
                reload = infid
            elif op in ["delete"]:
                force = False
                recreate = False
                if 'force' in form_data and form_data['force'] != "0":
                    force = True
                if 'recreate' in form_data and form_data['recreate'] != "0":
                    recreate = True
                response = im.delete_inf(infid, force, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("Infrastructure '%s' successfuly deleted." % infid, "success")
                try:
                    infra_data = infra.get_infra(infid)
                    infra_data["state"]["state"] = "deleting"
                    infra.write_infra(infid, infra_data)
                    scheduler.add_job('delete_infra_%s' % infid, delete_infra, trigger='interval',
                                      seconds=60, args=(infid,))
                except Exception as dex:
                    app.logger.error('Error setting infra state to deleting.: %s', (dex))

                if recreate:
                    return redirect(url_for('configure', inf_id=infid))

            elif op == "reconfigure":
                if 'reconfigure_template' in form_data and form_data['reconfigure_template'] != "":
                    # If the template has some reconfigure inputs, set them
                    try:
                        template = yaml.safe_load(form_data['reconfigure_template'])
                        template_inputs = template.get('topology_template', {}).get('inputs', {})
                        for input_name, input_params in template_inputs.items():
                            if input_name in form_data:
                                input_params['default'] = form_data[input_name]
                        tosca = yaml.safe_dump(template)
                    except Exception as ex:
                        flash("Error passing reconfigure values (changes ignored): %s." % ex, 'warn')
                        tosca = None

                    response = im.reconfigure_inf(infid, auth_data, tosca=tosca)
                else:
                    # otherwise, just reconfigure the infrastructure
                    response = im.reconfigure_inf(infid, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("Reconfiguration process successfuly started.", "success")
            elif op == "change_user":
                overwrite = False
                if 'overwrite' in form_data and form_data['overwrite'] != "0":
                    overwrite = True

                if 'token' in form_data and form_data['token'] != '':
                    response = im.change_user(infid, form_data['token'].strip(),
                                              overwrite, auth_data)
                    if not response.ok:
                        raise Exception(response.text)
                else:
                    flash("Empty token. Owner not changed.", 'warning')
                flash("Infrastructure owner successfully changed.", "success")
            elif op == "removeresources":
                vm_list = form_data.get('vm_list')
                response = im.remove_resources(infid, vm_list, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("VMs %s successfully deleted." % vm_list, "success")
            elif op == "migrate":
                new_im_url = form_data.get('new_im_url')
                new_im = InfrastructureManager(new_im_url, settings.imTimeout)
                infra_data = im.export_inf(infid, auth_data)
                new_infra_id = new_im.import_inf(infra_data, auth_data)
                if new_infra_id:
                    im.export_inf(infid, auth_data, delete=True)
                    infra.delete_infra(infid)
                    flash("Infrastructure successfully migrated to %s." % new_infra_id, "success")
                else:
                    flash("Error migrating the infrastructure %s." % infid, "error")
            else:
                flash("Invalid operation: %s" % op, 'error')
        except Exception as ex:
            flash("Error in '%s' operation: %s." % (op, ex), 'error')

        return redirect(url_for('showinfrastructures', reload=reload))

    @app.route('/ssh_keys')
    @authorized_with_valid_token
    def get_ssh_keys():

        ssh_keys = ssh_key.get_ssh_keys(session['userid'])
        return render_template('ssh_keys.html', ssh_keys=ssh_keys)

    @app.route('/delete_ssh_key')
    @authorized_with_valid_token
    def delete_ssh_key():

        try:
            keyid = request.args['ssh_id']
            ssh_key.delete_ssh_key(session['userid'], keyid)
            flash("SSH Key successfully deleted!", 'success')
        except Exception as ex:
            flash("Error deleting SSH Key %s!" % ex, 'error')

        return redirect(url_for('get_ssh_keys'))

    @app.route('/write_ssh_key', methods=['POST'])
    @authorized_with_valid_token
    def write_ssh_key():

        key = request.form['sshkey']
        desc = request.form['desc']
        if key == "" or not SSHKey.check_ssh_key(key):
            flash("Invaild SSH public key. Please insert a correct one.", 'warning')
            return redirect(url_for('get_ssh_keys'))

        ssh_key.write_ssh_key(session['userid'], key, desc)

        return redirect(url_for('get_ssh_keys'))

    @app.route('/owners/<infid>')
    @authorized_with_valid_token
    def getowners(infid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        res = ""
        try:
            response = im.get_inf_property(infid, 'authorization', auth_data)
            if not response.ok:
                raise Exception(response.text)

            owners = response.text.split()
            res = "Current Owners:<br><ul>"
            for owner in owners:
                owner = owner.replace("__OPENID__", "")
                res += "<li>%s</li>" % owner
            res += "</ul>"
        except Exception as ex:
            res = "Error: %s." % ex

        return Markup(res)

    @app.route('/manage_vault_info', methods=['GET', 'POST'])
    @authorized_with_valid_token
    def manage_vault_info():
        if request.method == 'GET':
            vinfo = []
            try:
                vinfo = vault_info.get_vault_info(session['userid'])
            except Exception as ex:
                flash("Error reading Vault Info %s!" % ex, 'error')

            return render_template('modal_vault.html', vinfo=vinfo)
        else:
            vinfo = request.form.to_dict()

            if 'overwrite' not in vinfo:
                try:
                    vault_info.delete_vault_info(session['userid'])
                    flash("Vault Info successfully deleted!", 'success')
                except Exception as ex:
                    flash("Error deleting Vault Info %s!" % ex, 'error')
            else:
                try:
                    vault_info.write_vault_info(session['userid'], vinfo['url'],
                                                vinfo['mount_point'], vinfo['path'], int(vinfo['kv_ver']))
                    flash("Vault Info successfully written!", 'success')
                except Exception as ex:
                    flash("Error writing Vault Info %s!" % ex, 'error')

            return redirect(url_for('manage_creds'))

    @app.route('/oai', methods=['GET', 'POST'])
    @csrf.exempt
    def oai_pmh():
        if not settings.oaipmh_repo_name:
            return make_response("OAI-PMH not enabled.", 404, {'Content-Type': 'text/plain'})

        oai = OAI(settings.oaipmh_repo_name, request.base_url, settings.oaipmh_repo_description,
                  settings.oaipmh_repo_base_identifier_url, repo_admin_email=app.config.get('SUPPORT_EMAIL'))

        metadata_dict = {}
        for name, tosca in toscaInfo.items():
            metadata = tosca["metadata"]
            metadata_dict[name] = metadata

        response_xml = oai.processRequest(request, metadata_dict)
        return make_response(response_xml, 200, {'Content-Type': 'text/xml'})

    @app.route('/reconfigure/<infid>')
    @authorized_with_valid_token
    def reconfigure(infid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getIMUserAuthData(access_token, cred, get_cred_id())
        template = ""
        try:
            response = im.get_inf_property(infid, 'tosca', auth_data)
            if not response.ok:
                raise Exception(response.text)
            template = response.text
        except Exception as ex:
            app.logger.warning("Error getting infrastructure template: %s" % ex)

        infra_name = ""
        inputs = utils.getReconfigureInputs(template)
        if inputs:
            try:
                infra_data = infra.get_infra(infid)
            except Exception:
                infra_data = {}
            infra_name = infra_data.get("name", "")

        return render_template('reconfigure.html', infid=infid, inputs=inputs, infra_name=infra_name, template=template)

    @app.route('/logout')
    def logout(next_url=None):
        session.clear()
        try:
            oidc_blueprint.session.get("/logout")
        except Exception as ex:
            app.logger.warning("Error in OIDC logout: %s" % ex)
        return redirect(url_for('login', next_url=next_url))

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('error_pages/403.html', message=error.description)

    @app.errorhandler(404)
    def page_not_found(error):
        app.logger.error('Page not found: %s', (request.path))
        return render_template('error_pages/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error('Server Error: %s', (error))
        return render_template('error_pages/500.html', support_email=app.config.get('SUPPORT_EMAIL'),
                               support_link=app.config.get('SUPPORT_LINK'),
                               support_link_name=app.config.get('SUPPORT_LINK_NAME')), 500

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash(e.description, 'error')
        return redirect(url_for('home'))

    # Reload internally the site cache
    @scheduler.task('interval', id='reload_sites', seconds=5)
    def reload_sites():
        scheduler.modify_job('reload_sites', trigger='interval', seconds=settings.appdb_cache_timeout - 30)
        with app.app_context():
            app.logger.debug('Reload Site List.')
            g.settings = settings
            utils.getCachedSiteList(True)

    # Reload internally the TOSCA tamplates
    @scheduler.task('interval', id='reload_templates', seconds=settings.checkToscaChangesTime)
    def reload_templates():
        with app.app_context():
            deletedTemplates, newTemplates = utils.reLoadToscaTemplates(settings.toscaDir, toscaTemplates,
                                                                        delay=settings.checkToscaChangesTime + 10)
            if newTemplates:
                app.logger.info('Reloading TOSCA templates %s' % newTemplates)
                for elem in newTemplates:
                    if elem not in toscaTemplates:
                        toscaTemplates.append(elem)
                newToscaInfo = utils.extractToscaInfo(settings.toscaDir, newTemplates, settings.hide_tosca_tags)
                toscaInfo.update(newToscaInfo)

            if deletedTemplates:
                app.logger.info('Removing TOSCA templates %s' % deletedTemplates)
                for elem in deletedTemplates:
                    if elem in toscaInfo:
                        del toscaInfo[elem]

    def delete_infra(infid):
        infra.delete_infra(infid)
        scheduler.remove_job('delete_infra_%s' % infid)

    def get_cred_id():
        if settings.vault_url:
            return oidc_blueprint.session.token['access_token'], vault_info.get_vault_info(session['userid'])
        else:
            return session['userid']

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0')
