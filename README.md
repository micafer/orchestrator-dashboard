# im-dashboard

Infrastructure Manager - Simple Graphical UI (based on [INDIGO PaaS Orchestrator Dashboard](https://github.com/indigo-dc/orchestrator-dashboard))

Functionalities:

- OIDC authentication
- Display user's infrastructures
- Display infrastructure details, template and log
- Delete infrastructure
- Create new infrastructure

The im-dashboard is a Python application built with the [Flask](http://flask.pocoo.org/) microframework; [Flask-Dance](https://flask-dance.readthedocs.io/en/latest/) is used for Openid-Connect/OAuth2 integration.

The docker image uses [Gunicorn](https://gunicorn.org/) as WSGI HTTP server to serve the Flask Application.

## How to deploy the dashboard

Register a client in an OIDC server with the following properties:

- redirect uri: `https://<DASHBOARD_HOST>:<PORT>/login/oidc/authorized`
- scopes: 'openid', 'email', 'profile', 'offline_access' ('eduperson_entitlement' in EGI Check-In optional)
- introspection endpoint enabled

Create the `config.json` file (see the [example](app/config-sample.json)) setting the following variables:

| Parameter name  | Description | Mandatory (Y/N) | Default Value |
| --------------- | ----------- |---------------- |-------------- |
| OIDC_CLIENT_ID  | OIDC client ID | Y | N/A |
| OIDC_CLIENT_SECRET | OIDC client Secret | Y | N/A |
| OIDC_BASE_URL | OIDC service URL | Y | N/A |
| OIDC_GROUP_MEMBERSHIP | List of OIDC groups to be checked for allowing access | N | [] |
| OIDC_SCOPES | OIDC scopes | Y | N/A |
| TOSCA_TEMPLATES_DIR | Absolute path where the TOSCA templates are stored | Y | N/A |
| TOSCA_PARAMETERS_DIR | Absolute path where the TOSCA parameters are stored | Y | N/A |
| IM_URL | Infrastructure Manager service URL | Y | N/A |
| IM_TIMEOUT | Infrastructure Manager service calls timeout | N | 60 |
| SUPPORT_EMAIL | Email address that will be shown in case of errors | N | "" |
| EXTERNAL_LINKS | List of dictionaries ({ "url": "example.com" , "menu_item_name": "Example link"}) specifying links that will be shown under the "External Links" menu | N | [] |
| LOG_LEVEL | Set Logging level | N | info |
| DB_URL | URL to the DB to store dashboard data | N | sqlite:///creds.db |
| ANALYTICS_TAG | Google Analytic Tag | N | "" |
| STATIC_SITES | List of static sites added to the AppDB ones ([{"name": "static_site_name", "url": "static_site_url", "id": "static_id", "vos": {"vo": "stprojectid"}}]) | N | [] |
| STATIC_SITES_URL | URL of a JSON file with the list of static sites added to the AppDB ones | N | "" |
| APPDB_CACHE_TIMEOUT | AppDB cache TTL | N | 3600 |
| CHECK_TOSCA_CHANGES_TIME | Interval to look for changes in TOSCA templates | N | 120 |
| VAULT_URL | Vault service URL to store Cloud credentials | N | None |


You need to run the IM dashboard on HTTPS (otherwise you will get an error); you can choose between

- enabling the HTTPS support
- using an HTTPS proxy

Details are provided in the next paragraphs.

## Enabling Credentials encryption

To enable the encryption of the Cloud providers credentials (sensitive data), you have to set the `CREDS_KEY`
environment varible with a valid key used to encrypt/decrypt de data. To get a valid one you can use this 
python code (you will nedd [Cryptography](https://cryptography.io/) library):

```py
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())
```

## TOSCA Template Metadata

The IM dashboard can exploit some optional information provided in the TOSCA templates for rendering the cards describing the type of applications/services or virtual infrastructure that a user can deploy.

In particular, the following tags are supported:

| Tag name       | Description   |
| -------------- | ------------- |
| description | Used for showing the card description  |               |
| metadata.display_name | Used for the card title. If not pro  |               |
| metadata.icon . |  Used for showing the card image. If no image URL is provided, the dashboard will load this [icon](https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png). |
| metadata.display_name | Used for the card title. If not provided, the template name will be used   |               |
| metadata.tag | Used for the card ribbon (displayed on the right bottom corner)   |               |

Example of template metadata:

```yaml
tosca_definitions_version: tosca_simple_yaml_1_0

imports:
  - indigo_custom_types: https://raw.githubusercontent.com/indigo-dc/tosca-types/v4.0.0/custom_types.yaml

description: Deploy a Mesos Cluster (with Marathon and Chronos frameworks) on top of Virtual machines

metadata:
  display_name: Deploy a Mesos cluster
  icon: https://indigo-paas.cloud.ba.infn.it/public/images/apache-mesos-icon.png

topology_template:

....
```

### Enabling HTTPS

You would need to provide

- a pair certificate/key that the container will read from the container paths `/certs/cert.pem` and `/certs/key.pem`;
- the environment variable `ENABLE_HTTPS` set to `True`

Run the docker container:

```sh
docker run -d -p 443:5001 --name='im-dashboard' \
           -e ENABLE_HTTPS=True \
           -v $PWD/cert.pem:/certs/cert.pem \
           -v $PWD/key.pem:/certs/key.pem \
           -v $PWD/config.json:/app/app/config.json \
           -v $PWD/tosca-templates:/opt/tosca-templates \
           grycap/im-dashboard:latest
```

Access the dashboard at `https://<DASHBOARD_HOST>/`

### Using an HTTPS Proxy

Example of configuration for nginx:

```
server {
      listen         80;
      server_name    YOUR_SERVER_NAME;
      return         301 https://$server_name$request_uri;
}

server {
  listen        443 ssl;
  server_name   YOUR_SERVER_NAME;
  access_log    /var/log/nginx/proxy-paas.access.log  combined;

  ssl on;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_certificate           /etc/nginx/cert.pem;
  ssl_certificate_key       /etc/nginx/key.pem;
  ssl_trusted_certificate   /etc/nginx/trusted_ca_cert.pem;

  location / {
                # Pass the request to Gunicorn
                proxy_pass http://127.0.0.1:5001/;

                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto https;
                proxy_set_header        Host $http_host;
                proxy_redirect          http:// https://;
                proxy_buffering         off;
  }

}
```

Run the docker container:

```sh
docker run -d -p 5001:5001 --name='im-dashboard' \
           -v $PWD/config.json:/app/app/config.json \
           -v $PWD/tosca-templates:/opt/tosca-templates \
           grycap/im-dashboard:latest
```

:warning: Remember to update the redirect uri in the OIDC client to `https://<PROXY_HOST>/login/oidc/authorized`

Access the dashboard at `https://<PROXY_HOST>/`

### Performance tuning

You can change the number of gunicorn worker processes using the environment variable WORKERS.
E.g. if you want to use 2 workers, launch the container with the option `-e WORKERS=2`
Check the [documentation](http://docs.gunicorn.org/en/stable/design.html#how-many-workers) for ideas on tuning this parameter.
