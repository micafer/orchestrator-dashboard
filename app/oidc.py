#
# IM - Infrastructure Manager Dashboard
# Copyright (C) 2023 - GRyCAP - Universitat Politecnica de Valencia
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

import flask
import logging
from flask_dance.consumer import OAuth2ConsumerBlueprint, oauth_before_login
from flask import url_for, redirect

log = logging.getLogger(__name__)

class OAuth2WithURIConsumerBlueprint(OAuth2ConsumerBlueprint):
    """
    A subclass of :class:`OAuth2ConsumerBlueprint` that enables to set the redirect_uri.
    """

    def __init__(
        self,
        name,
        import_name,
        client_id=None,
        client_secret=None,
        scope=None,
        state=None,
        auto_refresh_url=None,
        base_url=None,
        authorization_url=None,
        token_url=None,
        token_url_params=None,
        redirect_url=None,
        redirect_to=None,
        redirect_uri=None
    ):
        OAuth2ConsumerBlueprint.__init__(
            self,
            name,
            import_name,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            auto_refresh_url=auto_refresh_url,
            base_url=base_url,
            authorization_url=authorization_url,
            token_url=token_url,
            token_url_params=token_url_params,
            redirect_url=redirect_url,
            redirect_to=redirect_to
        )
        self.redirect_uri = redirect_uri

    def login(self):
        log.debug("client_id = %s", self.client_id)
        if self.redirect_uri:
            self.session.redirect_uri = self.redirect_uri
        else:
            self.session.redirect_uri = url_for(".authorized", _external=True)
        url, state = self.session.authorization_url(
            self.authorization_url, state=self.state, **self.authorization_url_params
        )
        state_key = f"{self.name}_oauth_state"
        flask.session[state_key] = state
        log.debug("state = %s", state)
        log.debug("redirect URL = %s", url)
        oauth_before_login.send(self, url=url)
        return redirect(url)