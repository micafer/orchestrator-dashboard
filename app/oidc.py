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

import json
import flask
import logging
from flask_dance.consumer import OAuth2ConsumerBlueprint, oauth_before_login
from flask import request, url_for, redirect, current_app
from werkzeug.wrappers import Response
from oauthlib.oauth2 import MissingCodeError
from flask_dance.consumer.base import (
    oauth_authorized,
    oauth_before_login,
    oauth_error,
)

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

    def authorized(self):
        """
        This is the route/function that the user will be redirected to by
        the provider (e.g. Twitter) after the user has logged into the
        provider's website and authorized your app to access their account.
        """
        if self.redirect_url:
            next_url = self.redirect_url
        elif self.redirect_to:
            next_url = url_for(self.redirect_to)
        else:
            next_url = "/"
        log.debug("next_url = %s", next_url)

        # check for error in request args
        error = request.args.get("error")
        if error:
            error_desc = request.args.get("error_description")
            error_uri = request.args.get("error_uri")
            log.warning(
                "OAuth 2 authorization error: %s description: %s uri: %s",
                error,
                error_desc,
                error_uri,
            )
            oauth_error.send(
                self, error=error, error_description=error_desc, error_uri=error_uri
            )
            return redirect(next_url)

        state_key = f"{self.name}_oauth_state"
        if state_key not in flask.session:
            # can't validate state, so redirect back to login view
            log.info("state not found, redirecting user to login")
            return redirect(url_for(".login"))

        state = flask.session[state_key]
        log.debug("state = %s", state)
        self.session._state = state
        del flask.session[state_key]

        if self.redirect_uri:
            self.session.redirect_uri = self.redirect_uri
        else:
            self.session.redirect_uri = url_for(".authorized", _external=True)

        log.debug("client_id = %s", self.client_id)
        log.debug("client_secret = %s", self.client_secret)
        try:
            token = self.session.fetch_token(
                self.token_url,
                authorization_response=request.url,
                client_secret=self.client_secret,
                **self.token_url_params,
            )
        except MissingCodeError as e:
            e.args = (
                e.args[0],
                "The redirect request did not contain the expected parameters. Instead I got: {}".format(
                    json.dumps(request.args)
                ),
            )
            raise

        results = oauth_authorized.send(self, token=token) or []
        set_token = True
        for func, ret in results:
            if isinstance(ret, (Response, current_app.response_class)):
                return ret
            if ret == False:
                set_token = False

        if set_token:
            try:
                self.token = token
            except ValueError as error:
                log.warning("OAuth 2 authorization error: %s", str(error))
                oauth_error.send(self, error=error)
        return redirect(next_url)