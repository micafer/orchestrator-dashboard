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

import requests
import yaml
import io
import os
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.consumer import OAuth2ConsumerBlueprint
from app.settings import Settings
from app.cred import Credentials
from app.infra import Infrastructures
from app import utils, appdb
from oauthlib.oauth2.rfc6749.errors import InvalidTokenError, TokenExpiredError
from werkzeug.exceptions import Forbidden
from flask import Flask, json, render_template, request, redirect, url_for, flash, session, Markup, g
from functools import wraps
from urllib.parse import urlparse
from radl import radl_parse
from radl.radl import deploy


def create_app(oidc_blueprint=None):
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    app.secret_key = "8210f566-4981-11ea-92d1-f079596e599b"
    app.config.from_json('config.json')
    settings = Settings(app.config)
    cred = Credentials(settings.db_url)
    infra = Infrastructures(settings.db_url)

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

            try:
                if not oidc_blueprint.session.authorized or 'username' not in session:
                    return redirect(url_for('login'))

                if oidc_blueprint.session.token['expires_in'] < 20:
                    app.logger.debug("Force refresh token")
                    oidc_blueprint.session.get('/userinfo')
            except (InvalidTokenError, TokenExpiredError):
                flash("Token expired.", 'warning')
                return redirect(url_for('login'))

            return f(*args, **kwargs)

        return decorated_function

    @app.route('/settings')
    @authorized_with_valid_token
    def show_settings():
        return render_template('settings.html', oidc_url=settings.oidcUrl, im_url=settings.imUrl)

    @app.route('/login')
    def login():
        session.clear()
        return render_template('home.html', oidc_name=settings.oidcName)

    @app.route('/')
    def home():
        if not oidc_blueprint.session.authorized:
            return redirect(url_for('login'))

        try:
            account_info = oidc_blueprint.session.get(urlparse(settings.oidcUrl)[2] + "/userinfo")
        except (InvalidTokenError, TokenExpiredError):
            flash("Token expired.", 'warning')
            return redirect(url_for('login'))

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
                    app.logger.debug("No match on group membership. User group membership: " + json.dumps(user_groups))
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

            return render_template('portfolio.html', templates=toscaInfo)
        else:
            flash("Error getting User info: \n" + account_info.text, 'error')
            return render_template('home.html', oidc_name=settings.oidcName)

    @app.route('/vminfo/<infid>/<vmid>')
    @authorized_with_valid_token
    def showvminfo(infid=None, vmid=None):
        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data, "Accept": "application/json"}

        url = "%s/infrastructures/%s/vms/%s" % (settings.imUrl, infid, vmid)
        response = requests.get(url, headers=headers)

        vminfo = {}
        state = ""
        nets = ""
        deployment = ""
        if not response.ok:
            flash("Error retrieving VM info: \n" + response.text, 'error')
        else:
            app.logger.debug("VM Info: %s" % response.text)
            vminfo = utils.format_json_radl(response.json()["radl"])
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

            cont = 0
            while "net_interface.%s.ip" % cont in vminfo:
                if cont > 0:
                    nets += Markup('<br/>')
                nets += Markup('<i class="fa fa-network-wired"></i>')
                nets += " %s: %s" % (cont, vminfo["net_interface.%s.ip" % cont])
                del vminfo["net_interface.%s.ip" % cont]
                cont += 1

            cont = 0
            while "net_interface.%s.connection" % cont in vminfo:
                del vminfo["net_interface.%s.connection" % cont]
                cont += 1

            for elem in vminfo:
                if elem.endswith("size") and isinstance(vminfo[elem], int):
                    vminfo[elem] = "%d GB" % (vminfo[elem] / 1073741824)

        return render_template('vminfo.html', infid=infid, vmid=vmid, vminfo=vminfo,
                               state=state, nets=nets, deployment=deployment)

    @app.route('/managevm/<op>/<infid>/<vmid>')
    @authorized_with_valid_token
    def managevm(op=None, infid=None, vmid=None):
        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data, "Accept": "application/json"}

        op = op.lower()
        if op in ["stop", "start", "reboot"]:
            url = "%s/infrastructures/%s/vms/%s/%s" % (settings.imUrl, infid, vmid, op)
            response = requests.put(url, headers=headers)
        elif op == "terminate":
            url = "%s/infrastructures/%s/vms/%s" % (settings.imUrl, infid, vmid)
            response = requests.delete(url, headers=headers)
        else:
            flash("Error: invalid operation: %s." % op, 'error')
            return redirect(url_for('showinfrastructures'))

        if response.ok:
            flash("Operation '%s' successfully made on VM ID: %s" % (op, vmid), 'info')
        else:
            flash("Error making %s op on VM %s: \n%s" % (op, vmid, response.text), 'error')

        if op == "terminate":
            return redirect(url_for('showinfrastructures'))
        else:
            return redirect(url_for('showvminfo', infid=infid, vmid=vmid))

    @app.route('/infrastructures')
    @authorized_with_valid_token
    def showinfrastructures():
        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data, "Accept": "application/json"}

        url = "%s/infrastructures" % settings.imUrl
        response = requests.get(url, headers=headers)

        infrastructures = {}
        if not response.ok:
            flash("Error retrieving infrastructure list: \n" + response.text, 'error')
        else:
            app.logger.debug("Infrastructures: %s" % response.text)
            state_res = response.json()
            if "uri-list" in state_res:
                inf_id_list = [elem["uri"] for elem in state_res["uri-list"]]
            else:
                inf_id_list = []
            for inf_id in inf_id_list:
                url = "%s/state" % inf_id
                response = requests.get(url, headers=headers)
                if not response.ok:
                    flash("Error retrieving infrastructure %s state: \n%s" % (inf_id, response.text), 'warning')
                else:
                    inf_state = response.json()
                    infrastructures[os.path.basename(inf_id)] = inf_state['state']

                    try:
                        infra_name = infra.get_infra(os.path.basename(inf_id))["name"]
                    except Exception:
                        infra_name = ""

                    infrastructures[os.path.basename(inf_id)]['name'] = infra_name

        return render_template('infrastructures.html', infrastructures=infrastructures)

    @app.route('/reconfigure/<infid>')
    @authorized_with_valid_token
    def infreconfigure(infid=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s/reconfigure" % (settings.imUrl, infid)
        response = requests.put(url, headers=headers)

        if response.ok:
            flash("Infrastructure successfuly reconfigured.", "info")
        else:
            flash("Error reconfiguring Infrastructure: \n" + response.text, "error")

        return redirect(url_for('showinfrastructures'))

    @app.route('/template/<infid>')
    @authorized_with_valid_token
    def template(infid=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s/tosca" % (settings.imUrl, infid)
        response = requests.get(url, headers=headers)

        if not response.ok:
            flash("Error getting template: \n" + response.text, "error")
            template = ""
        else:
            template = response.text
        return render_template('deptemplate.html', template=template)

    @app.route('/log/<infid>')
    @authorized_with_valid_token
    def inflog(infid=None):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s/contmsg" % (settings.imUrl, infid)
        response = requests.get(url, headers=headers, verify=False)

        if not response.ok:
            log = "Not found"
        else:
            log = response.text
        return render_template('inflog.html', log=log)

    @app.route('/vmlog/<infid>/<vmid>')
    @authorized_with_valid_token
    def vmlog(infid=None, vmid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s/vms/%s/contmsg" % (settings.imUrl, infid, vmid)
        response = requests.get(url, headers=headers, verify=False)

        if not response.ok:
            log = "Not found"
        else:
            log = response.text
        return render_template('inflog.html', log=log, vmid=vmid)

    @app.route('/outputs/<infid>')
    @authorized_with_valid_token
    def infoutputs(infid=None):

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s/outputs" % (settings.imUrl, infid)
        response = requests.get(url, headers=headers, verify=False)

        if not response.ok:
            outputs = {}
        else:
            outputs = response.json()["outputs"]
            for elem in outputs:
                if isinstance(outputs[elem], str) and (outputs[elem].startswith('http://') or
                                                       outputs[elem].startswith('https://')):
                    outputs[elem] = Markup("<a href='%s' target='_blank'>%s</a>" % (outputs[elem], outputs[elem]))

        return render_template('outputs.html', infid=infid, outputs=outputs)

    @app.route('/delete/<infid>/<force>')
    @authorized_with_valid_token
    def infdel(infid=None, force=0):
        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data}

        url = "%s/infrastructures/%s?async=1" % (settings.imUrl, infid)
        if force:
            url += "&force=1"
        response = requests.delete(url, headers=headers)

        if not response.ok:
            flash("Error deleting infrastructure: " + response.text, "error")
        else:
            flash("Infrastructure '%s' successfuly deleted." % infid, "info")
            try:
                infra.delete_infra(infid)
            except Exception as ex:
                flash("Error deleting infrastructure name: %s" + str(ex), "warning")

        return redirect(url_for('showinfrastructures'))

    @app.route('/configure')
    @authorized_with_valid_token
    def configure():

        selected_tosca = request.args['selected_tosca']

        app.logger.debug("Template: " + json.dumps(toscaInfo[selected_tosca]))

        vos = utils.getStaticVOs()
        vos.extend(appdb.get_vo_list())
        vos = list(set(vos))
        if "vos" in session and session["vos"]:
            vos = [vo for vo in vos if vo in session["vos"]]

        return render_template('createdep.html',
                               template=toscaInfo[selected_tosca],
                               selectedTemplate=selected_tosca,
                               vos=vos)

    @app.route('/sites/<vo>')
    def getsites(vo=None):
        res = ""
        appdb_sites = appdb.get_sites(vo)
        for site_name, site in appdb_sites.items():
            if site["state"]:
                site["state"] = " (WARNING: %s state!)" % site["state"]
            res += '<option name="selectedSite" value=%s>%s%s</option>' % (site_name, site_name, site["state"])

        for site_name, _ in utils.getStaticSites(vo).items():
            # avoid site duplication
            if site_name not in appdb_sites:
                res += '<option name="selectedSite" value=%s>%s</option>' % (site_name, site_name)

        return res

    @app.route('/images/<site>/<vo>')
    @authorized_with_valid_token
    def getimages(site=None, vo=None):
        res = ""
        if vo == "local":
            access_token = oidc_blueprint.session.token['access_token']
            for image_name, image_id in utils.get_site_images(site, vo, access_token, cred, session["userid"]):
                res += '<option name="selectedSiteImage" value=%s>%s</option>' % (image_id, image_name)
        else:
            for image in appdb.get_images(site, vo):
                res += '<option name="selectedImage" value=%s>%s</option>' % (image, image)
        return res

    @app.route('/usage/<site>/<vo>')
    @authorized_with_valid_token
    def getusage(site=None, vo=None):
        try:
            access_token = oidc_blueprint.session.token['access_token']
            quotas_dict = utils.get_site_usage(site, vo, access_token, cred, session["userid"])
            return json.dumps(quotas_dict)
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

    def set_inputs_to_template(template, inputs):
        # Add the image to all compute nodes

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
                        ports_value["port_%s" % port] = {"protocol": "tcp", "source": int(port)}
                    value["default"] = ports_value
                else:
                    value["default"] = inputs[name]

        app.logger.debug(yaml.dump(template, default_flow_style=False))
        return template

    @app.route('/submit', methods=['POST'])
    @authorized_with_valid_token
    def createdep():

        form_data = request.form.to_dict()
        vo = form_data['extra_opts.selectedVO']
        site = form_data['extra_opts.selectedSite']

        access_token = oidc_blueprint.session.token['access_token']
        auth_data = utils.getUserAuthData(access_token, cred, session["userid"], vo, site)

        app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

        with io.open(settings.toscaDir + request.args.get('template')) as stream:
            template = yaml.full_load(stream)

            if form_data['extra_opts.selectedImage'] != "":
                image = "appdb://%s/%s?%s" % (form_data['extra_opts.selectedSite'],
                                              form_data['extra_opts.selectedImage'],
                                              form_data['extra_opts.selectedVO'])
            elif form_data['extra_opts.selectedSiteImage'] != "":
                site_url = utils.get_ost_image_url(form_data['extra_opts.selectedSite'])
                image = "ost://%s/%s" % (site_url, form_data['extra_opts.selectedSiteImage'])
            else:
                flash("No correct image selected.", "error")
                return redirect(url_for('showinfrastructures'))

            template = add_image_to_template(template, image)

            template = add_auth_to_template(template, auth_data)

            inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

            app.logger.debug("Parameters: " + json.dumps(inputs))

            template = set_inputs_to_template(template, inputs)

            payload = yaml.dump(template, default_flow_style=False, sort_keys=False)

        headers = {"Authorization": auth_data, "Content-Type": "text/yaml"}

        url = "%s/infrastructures?async=1" % settings.imUrl
        response = requests.post(url, headers=headers, data=payload)

        if not response.ok:
            flash("Error creating infrastrucrure: \n" + response.text, "error")
        else:
            try:
                inf_id = os.path.basename(response.text)
                infra.write_infra(inf_id, {"name": form_data['infra_name']})
            except Exception as ex:
                flash("Error storing Infrastructure name: %s" % str(ex), "warning")

        return redirect(url_for('showinfrastructures'))

    @app.route('/manage_creds')
    @authorized_with_valid_token
    def manage_creds():
        sites = {}

        try:
            sites = utils.getCachedSiteList()
        except Exception as e:
            flash("Error retrieving sites list: \n" + str(e), 'warning')

        return render_template('service_creds.html', sites=sites)

    @app.route('/write_creds', methods=['GET', 'POST'])
    @authorized_with_valid_token
    def write_creds():
        serviceid = request.args.get('service_id', "")
        servicename = request.args.get('service_name', "")
        app.logger.debug("service_id={}".format(serviceid))

        if request.method == 'GET':
            res = {}
            projects = {}
            try:
                res = cred.get_cred(servicename, session["userid"])
                projects = utils.getCachedProjectIDs(serviceid)
                app.logger.debug("projects={}".format(projects))

                if session["vos"]:
                    filter_projects = {}
                    for vo, project in projects.items():
                        if vo in session["vos"]:
                            filter_projects[vo] = project
                    projects = filter_projects
            except Exception as ex:
                flash("Error reading credentials %s!" % ex, 'error')

            return render_template('modal_creds.html', service_creds=res, service_id=serviceid,
                                   service_name=servicename, projects=projects)
        else:
            app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

            creds = request.form.to_dict()
            try:
                cred.write_creds(servicename, session["userid"], creds)
                flash("Credentials successfully written!", 'info')
            except Exception as ex:
                flash("Error writing credentials %s!" % ex, 'error')

            return redirect(url_for('manage_creds'))

    @app.route('/delete_creds')
    @authorized_with_valid_token
    def delete_creds():

        serviceid = request.args.get('service_id', "")
        try:
            cred.delete_cred(serviceid, session["userid"])
            flash("Credentials successfully deleted!", 'info')
        except Exception as ex:
            flash("Error deleting credentials %s!" % ex, 'error')

        return redirect(url_for('manage_creds'))

    @app.route('/addresourcesform/<infid>')
    @authorized_with_valid_token
    def addresourcesform(infid=None):

        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data, "Accept": "text/plain"}

        url = "%s/infrastructures/%s/radl" % (settings.imUrl, infid)
        response = requests.get(url, headers=headers)

        if response.ok:
            systems = []
            try:
                radl = radl_parse.parse_radl(response.text)
                systems = radl.systems
            except Exception as ex:
                flash("Error parsing RADL: \n%s" % str(ex), 'error')

            return render_template('addresource.html', infid=infid, systems=systems)
        else:
            flash("Error getting RADL: \n%s" % (response.text), 'error')
            return redirect(url_for('showinfrastructures'))

    @app.route('/addresources/<infid>', methods=['POST'])
    @authorized_with_valid_token
    def addresources(infid=None):

        access_token = oidc_blueprint.session.token['access_token']

        auth_data = utils.getUserAuthData(access_token, cred, session["userid"])
        headers = {"Authorization": auth_data, "Accept": "text/plain"}

        form_data = request.form.to_dict()

        url = "%s/infrastructures/%s/radl" % (settings.imUrl, infid)
        response = requests.get(url, headers=headers)

        if response.ok:
            radl = None
            try:
                radl = radl_parse.parse_radl(response.text)
                radl.deploys = []
                for system in radl.systems:
                    if "%s_num" % system.name in form_data:
                        vm_num = int(form_data["%s_num" % system.name])
                        if vm_num > 0:
                            radl.deploys.append(deploy(system.name, vm_num))
            except Exception as ex:
                flash("Error parsing RADL: \n%s\n%s" % (str(ex), response.text), 'error')

            if radl:
                headers = {"Authorization": auth_data, "Accept": "application/json"}
                url = "%s/infrastructures/%s" % (settings.imUrl, infid)
                response = requests.post(url, headers=headers, data=str(radl))

                if response.ok:
                    num = len(response.json()["uri-list"])
                    flash("%d nodes added successfully" % num, 'info')
                else:
                    flash("Error adding nodesL: \n%s" % (response.text), 'error')

            return redirect(url_for('showinfrastructures'))
        else:
            flash("Error getting RADL: \n%s" % (response.text), 'error')
            return redirect(url_for('showinfrastructures'))

    @app.route('/logout')
    def logout():
        session.clear()
        oidc_blueprint.session.get("/logout")
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

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0')
