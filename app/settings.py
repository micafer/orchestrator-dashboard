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
"""Settings Class."""


class Settings:
    def __init__(self, config):
        """Creator function."""
        self.toscaDir = config.get('TOSCA_TEMPLATES_DIR', '') + "/"
        self.toscaParamsDir = config.get('TOSCA_PARAMETERS_DIR', '') + "/"
        self.imUrl = config['IM_URL']
        self.oidcUrl = config['OIDC_BASE_URL']
        self.tempSlamUrl = config.get('SLAM_URL') if config.get('SLAM_URL') else ""
        self.imConf = {'im_url': config.get('IM_URL')}
        self.external_links = config.get('EXTERNAL_LINKS') if config.get('EXTERNAL_LINKS') else []
        self.oidcGroups = config.get('OIDC_GROUP_MEMBERSHIP')
        self.db_url = config.get('DB_URL')
        self.analytics_tag = config.get('ANALYTICS_TAG')
        self.static_sites = config.get('STATIC_SITES', [])
        self.static_sites_url = config.get('STATIC_SITES_URL', "")
