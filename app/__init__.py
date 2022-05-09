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
from requests.exceptions import Timeout
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.consumer import OAuth2ConsumerBlueprint
from app.settings import Settings
from app.db_cred import DBCredentials
from app.vault_cred import VaultCredentials
from app.infra import Infrastructures
from app.im import InfrastructureManager
from app.ssh_key import SSHKey
from app import utils, appdb, db
from oauthlib.oauth2.rfc6749.errors import InvalidTokenError, TokenExpiredError
from werkzeug.exceptions import Forbidden
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, Markup, g
from functools import wraps
from urllib.parse import urlparse
from radl import radl_parse
from radl.radl import deploy
from flask_apscheduler import APScheduler
from flask_wtf.csrf import CSRFProtect


def create_app(oidc_blueprint=None):
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    app.secret_key = "8210f566-4981-11ea-92d1-f079596e599b"
    app.config.from_json('config.json')
    settings = Settings(app.config)
    if settings.vault_url:
        cred = VaultCredentials(settings.vault_url)
    else:
        if 'CREDS_KEY' in os.environ:
            key = os.environ['CREDS_KEY']
        else:
            key = None
        cred = DBCredentials(settings.db_url, key)
    CSRFProtect(app)
    infra = Infrastructures(settings.db_url)
    im = InfrastructureManager(settings.imUrl, settings.imTimeout)
    ssh_key = SSHKey(settings.db_url)

    # To Reload internally the site cache
    scheduler = APScheduler()
    scheduler.api_enabled = False
    scheduler.init_app(app)
    scheduler.start()

    toscaTemplates = utils.loadToscaTemplates(settings.toscaDir)
    toscaInfo = utils.extractToscaInfo(settings.toscaDir, settings.toscaParamsDir, toscaTemplates)

    app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json
    app.logger.debug("TOSCA INFO: " + json.dumps(toscaInfo))

    loglevel = app.config.get("LOG_LEVEL") if app.config.get("LOG_LEVEL") else "INFO"

    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logging.basicConfig(level=numeric_level)

    oidc_base_url = app.config['OIDC_BASE_URL']
    oidc_token_url = oidc_base_url + '/token'
    oidc_refresh_url = oidc_base_url + '/token'
    oidc_authorization_url = oidc_base_url + '/authorize'

    if not oidc_blueprint:
        oidc_blueprint = OAuth2ConsumerBlueprint(
            "oidc", __name__,
            client_id=app.config['OIDC_CLIENT_ID'],
            client_secret=app.config['OIDC_CLIENT_SECRET'],
            scope=app.config['OIDC_SCOPES'],
            base_url=oidc_base_url,
            token_url=oidc_token_url,
            auto_refresh_url=oidc_refresh_url,
            authorization_url=oidc_authorization_url,
            redirect_to='home'
        )
    app.register_blueprint(oidc_blueprint, url_prefix="/login")

    @app.before_request
    def before_request_checks():
        if 'external_links' not in session:
            session['external_links'] = settings.external_links
        g.analytics_tag = settings.analytics_tag
        g.settings = settings

    def authorized_with_valid_token(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            if settings.debug_oidc_token:
                oidc_blueprint.session.token = {'access_token': settings.debug_oidc_token}
            else:
                try:
                    if not oidc_blueprint.session.authorized or 'username' not in session:
                        return logout()

                    if oidc_blueprint.session.token['expires_in'] < 20:
                        app.logger.debug("Force refresh token")
                        oidc_blueprint.session.get('/userinfo')
                except (InvalidTokenError, TokenExpiredError):
                    flash("Token expired.", 'warning')
                    return logout()

            return f(*args, **kwargs)

        return decorated_function

    @app.route('/settings')
    @authorized_with_valid_token
    def show_settings():
        imUrl = "%s (v. %s)" % (settings.imUrl, im.get_version())
        if settings.debug_oidc_token:
            access_token = settings.debug_oidc_token
        else:
            access_token = oidc_blueprint.session.token['access_token']
        return render_template('settings.html', oidc_url=settings.oidcUrl, im_url=imUrl,
                               access_token=access_token, vault_url=settings.vault_url)

    @app.route('/login')
    def login():
        # Maintain filter session value
        template_filter = None
        if "filter" in session:
            template_filter = session["filter"]
        session.clear()
        if template_filter:
            session["filter"] = template_filter
        return render_template('home.html', oidc_name=settings.oidcName)

    @app.route('/')
    def home():
        template_filter = None
        if 'filter' in request.args:
            template_filter = request.args['filter']
        if "filter" in session:
            template_filter = session["filter"]

        if template_filter:
            session["filter"] = template_filter
            templates = {}
            for k, v in toscaInfo.items():
                if 'description' and v['description']:
                    if v['description'].find(template_filter) != -1:
                        templates[k] = v
        else:
            templates = toscaInfo

        if settings.debug_oidc_token:
            session["vos"] = None
            session['userid'] = "a_very_long_user_id_00000000000000000000000000000000000000000000@egi.es"
            session['username'] = "username"
            session['gravatar'] = ""
            return render_template('portfolio.html', templates=templates)
        else:
            if not oidc_blueprint.session.authorized:
                return redirect(url_for('login'))

            try:
                account_info = oidc_blueprint.session.get(urlparse(settings.oidcUrl)[2] + "/userinfo")
            except (InvalidTokenError, TokenExpiredError):
                flash("Token expired.", 'warning')
                return logout()

            if account_info.ok:
                account_info_json = account_info.json()

                session["vos"] = None
                if 'eduperson_entitlement' in account_info_json:
                    session["vos"] = utils.getUserVOs(account_info_json['eduperson_entitlement'])

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

                return render_template('portfolio.html', templates=templates)
            else:
                flash("Error getting User info: \n" + account_info.text, 'error')
                return render_template('home.html', oidc_name=settings.oidcName)

    @app.route('/vminfo')
    @authorized_with_valid_token
    def showvminfo():
        access_token = oidc_blueprint.session.token['access_token']
        vmid = request.args['vmId']
        infid = request.args['infId']

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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
            if "provider.host" in vminfo:
                if "provider.port" in vminfo:
                    deployment += ": %s:%s" % (vminfo["provider.host"], vminfo["provider.port"])
                    del vminfo["provider.port"]
                else:
                    deployment += ": " + vminfo["provider.host"]
                del vminfo["provider.host"]
            if "disk.0.os.name" in vminfo:
                del vminfo["disk.0.os.name"]

            cont = 0
            while "net_interface.%s.connection" % cont in vminfo:
                if "net_interface.%s.ip" % cont in vminfo:
                    if cont > 0:
                        nets += Markup('<br/>')
                    nets += Markup('<i class="fa fa-network-wired"></i>')
                    nets += Markup(' <span class="badge badge-secondary">%s</span>' % cont)
                    nets += ": %s" % vminfo["net_interface.%s.ip" % cont]
                    del vminfo["net_interface.%s.ip" % cont]
                    if "net_interface.%s.dns_name" % cont in vminfo:
                        nets += " (%s)" % vminfo["net_interface.%s.dns_name" % cont]
                        del vminfo["net_interface.%s.dns_name" % cont]

                cont += 1

            cont = 0
            while "net_interface.%s.connection" % cont in vminfo:
                del vminfo["net_interface.%s.connection" % cont]
                cont += 1

            for elem in vminfo:
                if elem.endswith("size") and isinstance(vminfo[elem], (int, float)):
                    vminfo[elem] = "%.1f GB" % (vminfo[elem] / 1073741824.0)

            cont = 0
            while "disk.%s.size" % cont in vminfo or "disk.%s.image.url" % cont in vminfo:
                if cont > 0:
                    disks += Markup('<br/>')
                disks += Markup('<i class="fa fa-database"></i> <span class="badge badge-secondary">'
                                '%s</span><br/>' % cont)

                prop_map = {"size": "Size", "image.url": "URL", "device": "Device", "mount_path": "Mount Path",
                            "fstype": "F.S. type", "os.flavour": "O.S. Flavor", "os.version": "O.S. Version"}
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
                                           'badge-secondary">%s%s</span>' % (remote_cidr, port.get_remote_port()))
                    if not port.is_range():
                        if port.get_remote_port() != port.get_local_port():
                            str_outports += Markup(' <i class="fas fa-long-arrow-alt-right">'
                                                   '</i> <span class="badge badge-secondary">%s</span>' %
                                                   port.get_local_port())
                    else:
                        str_outports += Markup(' : </i> <span class="badge badge-secondary">%s</span>' %
                                               port.get_local_port())
                    str_outports += Markup('<br/>')

        return render_template('vminfo.html', infid=infid, vmid=vmid, vminfo=vminfo, outports=str_outports,
                               state=state, nets=nets, deployment=deployment, disks=disks)

    @app.route('/managevm/<op>/<infid>/<vmid>', methods=['POST'])
    @authorized_with_valid_token
    def managevm(op=None, infid=None, vmid=None):
        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
        try:
            if op == "reconfigure":
                response = im.reconfigure_inf(infid, auth_data, [vmid])
            elif op == "resize":
                form_data = request.form.to_dict()
                cpu = int(form_data['cpu'])
                memory = int(form_data['memory'])
                system_name = form_data['system_name']

                radl = "system %s (cpu.count >= %d and memory.size >= %dg)" % (system_name, cpu, memory)
                response = im.resize_vm(infid, vmid, radl, auth_data)
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
            if 'state' in infra_data:
                infrastructures[inf_id]['state'] = infra_data["state"]

        return render_template('infrastructures.html', infrastructures=infrastructures, reload=reload_infid)

    @app.route('/infrastructures/state')
    @authorized_with_valid_token
    def infrastructure_state():
        access_token = oidc_blueprint.session.token['access_token']
        infid = request.args['infid']
        if not infid:
            return {"state": "error", "vm_states": {}}

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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
        data = yaml.full_load(template)

        for node in list(data['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.ec3.DNSRegistry":
                try:
                    node["properties"]["dns_service_credentials"]["token"] = "AK:SK"
                except KeyError:
                    pass

            if node["type"] == "tosca.nodes.ec3.ElasticCluster":
                if "im_auth" in node["properties"]:
                    node["properties"]["im_auth"] = "protected"
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
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
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

        inputs = {}
        infra_name = ""
        if inf_id:
            access_token = oidc_blueprint.session.token['access_token']
            auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
            try:
                response = im.get_inf_property(inf_id, 'tosca', auth_data)
                if not response.ok:
                    raise Exception(response.text)
                template = response.text
                data = yaml.full_load(template)
                for input_name, input_value in list(data['topology_template']['inputs'].items()):
                    inputs[input_name] = None
                    if input_value.get("default", None):
                        if input_value["type"] == "map" and input_name == "ports":
                            inputs[input_name] = ""
                            for port_value in input_value["default"].values():
                                if inputs[input_name]:
                                    inputs[input_name] += ","
                                if 'remote_cidr' in port_value and port_value['remote_cidr']:
                                    inputs[input_name] += str(port_value['remote_cidr']) + "-"
                                inputs[input_name] += str(port_value['source'])
                        else:
                            inputs[input_name] = input_value["default"]
                if 'filename' in data['metadata'] and data['metadata']['filename']:
                    selected_tosca = data['metadata']['filename']
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
            flash("InvalidTOSCA template name: %s" % selected_tosca, "error")
            return redirect(url_for('home'))

        app.logger.debug("Template: " + json.dumps(toscaInfo[selected_tosca]))

        try:
            creds = cred.get_creds(get_cred_id(), 1)
        except Exception as ex:
            flash("Error getting user credentials: %s" % ex, "error")
            creds = []
        utils.get_project_ids(creds)

        return render_template('createdep.html',
                               template=toscaInfo[selected_tosca],
                               selectedTemplate=selected_tosca,
                               creds=creds, input_values=inputs,
                               infra_name=infra_name)

    @app.route('/vos')
    def getvos():
        res = ""
        vos = utils.getStaticVOs()
        vos.extend(appdb.get_vo_list())
        vos = list(set(vos))
        vos.sort()
        if "vos" in session and session["vos"]:
            vos = [vo for vo in vos if vo in session["vos"]]
        for vo in vos:
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

    def add_image_to_template(template, image):
        # Add the image to all compute nodes

        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.indigo.Compute":
                node["capabilities"]["os"]["properties"]["image"] = image

        app.logger.debug(yaml.dump(template, default_flow_style=False))

        return template

    def add_auth_to_template(template, auth_data):
        # Add the auth_data ElasticCluster node

        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.ec3.ElasticCluster":
                if "properties" not in node:
                    node["properties"] = {}
                node["properties"]["im_auth"] = auth_data

        app.logger.debug(yaml.dump(template, default_flow_style=False))

        return template

    def add_record_name_to_template(template, replace_name):
        # Add a random name in the DNS record name

        for node in list(template['topology_template']['node_templates'].values()):
            if node["type"] == "tosca.nodes.ec3.DNSRegistry":
                node["properties"]["record_name"] = node["properties"]["record_name"].replace("*", replace_name)

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
                # Special case for ports, convert a comma separated list of ints
                # to a PortSpec map
                elif value["type"] == "map" and name == "ports":
                    ports = inputs[name].split(",")
                    ports_value = {}
                    for port in ports:
                        # Should we also open UDP?
                        remote_cidr = None
                        if "-" in port:
                            parts = port.split("-")
                            port_num = int(parts[1])
                            remote_cidr = parts[0]
                        else:
                            port_num = int(port)
                        ports_value["port_%s" % port] = {"protocol": "tcp", "source": port_num}
                        if remote_cidr:
                            ports_value["port_%s" % port]["remote_cidr"] = remote_cidr
                    value["default"] = ports_value
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

    def add_ssh_key_to_template(template):
        sshkey = ssh_key.get_ssh_key(session['userid'])
        if sshkey:
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
                template['topology_template']['node_templates']["dash_ssh_key_%s" % computer] = ssh_node

        return template

    @app.route('/submit', methods=['POST'])
    @authorized_with_valid_token
    def createdep():

        form_data = request.form.to_dict()

        app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

        cred_id = form_data['extra_opts.selectedCred']
        cred_data = cred.get_cred(cred_id, get_cred_id())
        access_token = oidc_blueprint.session.token['access_token']

        image = None
        priv_network_id = None
        pub_network_id = None
        if cred_data['type'] in ['fedcloud', 'OpenStack', 'OpenNebula', 'Linode', 'Orange', 'GCE']:
            if cred_data['type'] == 'fedcloud':
                site, _, vo = utils.get_site_info(cred_id, cred, get_cred_id())
                if "networks" in site and vo in site["networks"]:
                    if "private" in site["networks"][vo]:
                        priv_network_id = site["networks"][vo]["private"]
                    if "public" in site["networks"][vo]:
                        pub_network_id = site["networks"][vo]["public"]

            if form_data['extra_opts.selectedImage'] != "":
                image = "appdb://%s/%s?%s" % (site['name'], form_data['extra_opts.selectedImage'], vo)
            elif form_data['extra_opts.selectedSiteImage'] != "":
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

        with io.open(settings.toscaDir + request.args.get('template')) as stream:
            template = yaml.full_load(stream)

        if 'metadata' not in template:
            template['metadata'] = {}
        template['metadata']['filename'] = request.args.get('template')

        if priv_network_id and pub_network_id:
            template = add_network_id_to_template(template, priv_network_id, pub_network_id)

        template = add_image_to_template(template, image)

        template = add_auth_to_template(template, auth_data)

        template = add_ssh_key_to_template(template)

        # Specially added for OSCAR clusters
        template = add_record_name_to_template(template, utils.generate_random_name())

        inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

        app.logger.debug("Parameters: " + json.dumps(inputs))

        template = set_inputs_to_template(template, inputs)

        payload = yaml.dump(template, default_flow_style=False, sort_keys=False)

        try:
            response = im.create_inf(payload, auth_data)
            if not response.ok:
                raise Exception(response.text)

            try:
                inf_id = os.path.basename(response.text)
                infra.write_infra(inf_id, {"name": form_data['infra_name'],
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

        return render_template('service_creds.html', creds=creds)

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

            return render_template('modal_creds.html', creds=res, cred_id=cred_id, cred_type=cred_type)
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

    @app.route('/addresourcesform/<infid>')
    @authorized_with_valid_token
    def addresourcesform(infid=None):

        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
        try:
            response = im.get_inf_property(infid, 'radl', auth_data)
            if not response.ok:
                raise Exception(response.text)

            systems = []
            try:
                radl = radl_parse.parse_radl(response.text)
                systems = radl.systems
            except Exception as ex:
                flash("Error parsing RADL: \n%s" % str(ex), 'error')

            return render_template('addresource.html', infid=infid, systems=systems)
        except Exception as ex:
            flash("Error getting RADL: \n%s" % ex, 'error')
            return redirect(url_for('showinfrastructures'))

    @app.route('/addresources/<infid>', methods=['POST'])
    @authorized_with_valid_token
    def addresources(infid=None):

        access_token = oidc_blueprint.session.token['access_token']
        form_data = request.form.to_dict()

        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
        try:
            response = im.get_inf_property(infid, 'radl', auth_data)
        except Exception as ex:
            flash("Error: %s." % ex, 'error')

        if response.ok:
            radl = None
            try:
                radl = radl_parse.parse_radl(response.text)
                radl.deploys = []
                for system in radl.systems:
                    sys_dep = deploy(system.name, 0)
                    if "%s_num" % system.name in form_data:
                        vm_num = int(form_data["%s_num" % system.name])
                        if vm_num > 0:
                            sys_dep.vm_number = vm_num
                    radl.deploys.append(sys_dep)
            except Exception as ex:
                flash("Error parsing RADL: \n%s\n%s" % (str(ex), response.text), 'error')

            if radl:
                try:
                    response = im.addresource_inf(infid, str(radl), auth_data)
                    if not response.ok:
                        raise Exception(response.text)
                    num = len(response.json()["uri-list"])
                    flash("%d nodes added successfully" % num, 'success')
                except Exception as ex:
                    flash("Error adding nodes: \n%s\n%s" % (ex, response.text), 'error')

            return redirect(url_for('showinfrastructures'))
        else:
            flash("Error getting RADL: \n%s" % (response.text), 'error')
            return redirect(url_for('showinfrastructures'))

    @app.route('/manage_inf/<infid>/<op>', methods=['POST'])
    @authorized_with_valid_token
    def manage_inf(infid=None, op=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, get_cred_id())
        reload = None

        try:
            if op == "descr":
                form_data = request.form.to_dict()
                if 'description' in form_data and form_data['description'] != "":
                    try:
                        infra_data = infra.get_infra(infid)
                        infra_data["name"] = form_data['description']
                        infra.write_infra(infid, infra_data)
                    except Exception as uex:
                        flash("Error updating infrastructure description: %s" % str(uex), "error")
            elif op in ["start", "stop"]:
                response = im.manage_inf(op, infid, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("Operation '%s' successfully made on Infrastructure ID: %s" % (op, infid), 'success')
                reload = infid
            elif op in ["delete", "delete-recreate"]:
                form_data = request.form.to_dict()
                force = False
                if 'force' in form_data and form_data['force'] != "0":
                    force = True
                # Specially added for OSCAR clusters
                success, msg = utils.delete_dns_record(infid, im, auth_data)
                if not success:
                    app.logger.error('Error deleting DNS record: %s', (msg))
                else:
                    app.logger.info('%s DNS record successfully deleted.', (msg))
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

                if op == "delete-recreate":
                    return redirect(url_for('configure', inf_id=infid))

            elif op == "reconfigure":
                response = im.reconfigure_inf(infid, auth_data)
                if not response.ok:
                    raise Exception(response.text)
                flash("Reconfiguration process successfuly started.", "success")
            elif op == "change_user":
                form_data = request.form.to_dict()
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
        except Exception as ex:
            flash("Error in '%s' operation: %s." % (op, ex), 'error')

        return redirect(url_for('showinfrastructures', reload=reload))

    @app.route('/ssh_key')
    @authorized_with_valid_token
    def get_ssh_key():

        key = ssh_key.get_ssh_key(session['userid'])
        return render_template('ssh_keys.html', sshkey=key)

    @app.route('/delete_ssh_key')
    @authorized_with_valid_token
    def delete_ssh_key():

        try:
            ssh_key.delete_ssh_key(session['userid'])
            flash("SSH Key successfully deleted!", 'success')
        except Exception as ex:
            flash("Error deleting SSH Key %s!" % ex, 'error')

        return redirect(url_for('get_ssh_key'))

    @app.route('/write_ssh_key', methods=['POST'])
    @authorized_with_valid_token
    def write_ssh_key():

        key = request.form['sshkey']
        if key == "" or str(SSHKey.check_ssh_key(key.encode())) != "0":
            flash("Invaild SSH public key. Please insert a correct one.", 'warning')
            return redirect(url_for('get_ssh_key'))

        ssh_key.write_ssh_key(session['userid'], key)

        return redirect(url_for('get_ssh_key'))

    @app.route('/logout')
    def logout():
        session.clear()
        try:
            oidc_blueprint.session.get("/logout")
        except Exception as ex:
            app.logger.warn("Error in OIDC logout: %s" % ex)
        return redirect(url_for('login'))

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
        return render_template('error_pages/500.html', support_email=app.config.get('SUPPORT_EMAIL')), 500

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
            newToscaTemplates = utils.reLoadToscaTemplates(settings.toscaDir, toscaTemplates,
                                                           delay=settings.checkToscaChangesTime + 10)
            if newToscaTemplates:
                app.logger.info('Reloading TOSCA templates %s' % newToscaTemplates)
                for elem in newToscaTemplates:
                    if elem not in toscaTemplates:
                        toscaTemplates.append(elem)
                newToscaInfo = utils.extractToscaInfo(settings.toscaDir, settings.toscaParamsDir, newToscaTemplates)
                toscaInfo.update(newToscaInfo)

    def delete_infra(infid):
        infra.delete_infra(infid)
        scheduler.delete_job('delete_infra_%s' % infid)

    def get_cred_id():
        if settings.vault_url:
            return oidc_blueprint.session.token['access_token']
        else:
            return session['userid']

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0')
