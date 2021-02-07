import logging
from base64 import b64encode
from six.moves.urllib.parse import urlencode

import httplib2
from flask import redirect, Flask, request, g, current_app
from flask.helpers import get_env, get_debug_flag
from flask_oidc_ex import OpenIDConnect, _json_loads, discover_OP_information, retrieve_jwks
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy

from flaskoidc.config import BaseConfig, OIDCProvider
from flaskoidc.store import SessionCredentialStore

from .validation import validate_token

LOGGER = logging.getLogger(__name__)


class CustomOpenIDConnect(OpenIDConnect):
    def _get_token_info(self, token):
        validation_mode = current_app.config['OIDC_RESOURCE_SERVER_VALIDATION_MODE']
        clock_skew_seconds = current_app.config['OIDC_CLOCK_SKEW']

        if validation_mode == 'online':
            # We hardcode to use client_secret_post, because that's what the Google
            # oauth2client library defaults to
            request = {'token': token}
            headers = {'Content-type': 'application/x-www-form-urlencoded'}

            hint = current_app.config['OIDC_TOKEN_TYPE_HINT']
            if hint != 'none':
                request['token_type_hint'] = hint

            auth_method = current_app.config['OIDC_INTROSPECTION_AUTH_METHOD']
            if (auth_method == 'client_secret_basic'):
                basic_auth_string = '%s:%s' % (
                    self.client_secrets['client_id'], self.client_secrets['client_secret'])
                basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
                headers['Authorization'] = 'Basic %s' % b64encode(
                    basic_auth_bytes).decode('utf-8')
            elif (auth_method == 'bearer'):
                headers['Authorization'] = 'Bearer %s' % token
            elif (auth_method == 'client_secret_post'):
                request['client_id'] = self.client_secrets['client_id']
                if self.client_secrets['client_secret'] is not None:
                    request['client_secret'] = self.client_secrets['client_secret']

            resp, content = self.httpFactory().request(
                self.client_secrets['token_introspection_uri'], 'POST',
                urlencode(request), headers=headers)
            # TODO: Cache this reply
            return _json_loads(content)

        elif validation_mode == 'offline':
            issuer = current_app.config['OIDC_PROVIDER']
            if issuer is None:
                raise Exception('No \'op_uri\' defined in client_secrets or OIDC_PROVIDER set.')

            disco = discover_OP_information(issuer, self.httpFactory)
            jwks_uri = disco['jwks_uri']

            if jwks_uri is None:
                raise Exception('No \'jwks_uri\' available in the openid-configuration returned by the issuer.')

            jwks = retrieve_jwks(jwks_uri, self.httpFactory)

            if jwks is None:
                raise Exception('The {0} endpoint returned no valid JWKs' % jwks_uri)

            payload = validate_token(jwks, token, clock_skew_seconds)
            payload['active'] = True  # Fake introspection response

            return payload
        else:
            raise Exception(
                'OIDC_RESOURCE_SERVER_VALIDATION_MODE must be set to either \'online\' or \'offline\'')


class FlaskOIDC(Flask):
    def _before_request(self):
        # ToDo: Need to refactor and divide this method in functions.
        # Whitelisted Endpoints i.e., health checks and status url
        LOGGER.debug(f"Request Path: {request.path}")
        LOGGER.debug(f"Request Endpoint: {request.endpoint}")
        LOGGER.debug(f"Whitelisted Endpoint: {BaseConfig.WHITELISTED_ENDPOINTS}")

        if request.path.strip("/") in BaseConfig.WHITELISTED_ENDPOINTS.split(",") or \
                request.endpoint in BaseConfig.WHITELISTED_ENDPOINTS.split(","):
            return

        # If accepting token in the request headers
        token = None
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
            token = request.headers['Authorization'].split(None, 1)[1].strip()
        if 'access_token' in request.form:
            token = request.form['access_token']
        elif 'access_token' in request.args:
            token = request.args['access_token']

        if token:
            validity = self.oidc.validate_token(token)
            # This check True is required to make sure the validity is checked
            if validity is True:
                return

        # If not accepting a request, verify if the user is logged in
        with self.app_context():
            try:
                if self.oidc.user_loggedin:
                    access_token = self.oidc.get_access_token()
                    assert access_token
                    is_valid = self.oidc.validate_token(access_token)
                    assert is_valid is True
                return self.oidc.authenticate_or_redirect()
            except (AssertionError, AttributeError):
                # In case the session is forced logout from keycloak but still in
                # the cookie, remove from cookie and try to login again
                self.oidc.logout()
                return self.oidc.authenticate_or_redirect()

    def __init__(self, *args, **kwargs):
        super(FlaskOIDC, self).__init__(*args, **kwargs)

        # Setup Session Database
        _sql_db = SQLAlchemy(self)
        self.config["SESSION_SQLALCHEMY"] = _sql_db

        # Setup Session Store, that will hold the session information
        # in database. OIDC by default keep the sessions in memory
        _session = Session(self)
        _session.app.session_interface.db.create_all()

        # Initiate OpenIDConnect using the SQLAlchemy backed session store
        _oidc = CustomOpenIDConnect(self, SessionCredentialStore())
        self.oidc = _oidc

        # Register the before request function that will make sure each
        # request is authenticated before processing
        self.before_request(self._before_request)

        @self.route('/login')
        def login():
            return redirect('/')

        @self.route('/logout')
        def logout():
            """
            The logout function that logs user out from Keycloak.
            :return: Redirects to the Keycloak login page
            """
            _oidc.logout()
            redirect_url = request.url_root.strip('/')
            keycloak_issuer = _oidc.client_secrets.get('issuer')
            keycloak_logout_url = '{}/protocol/openid-connect/logout'. \
                format(keycloak_issuer)

            return redirect('{}?redirect_uri={}'.format(keycloak_logout_url,
                                                        redirect_url))

    def make_config(self, instance_relative=False):
        """
        Overriding the default `make_config` function in order to support
        Flask OIDC package and all of their settings.
        """
        root_path = self.root_path
        if instance_relative:
            root_path = self.instance_path
        defaults = dict(self.default_config)
        defaults['ENV'] = get_env()
        defaults['DEBUG'] = get_debug_flag()

        # Append all the configurations from the base config class.
        for key, value in BaseConfig.__dict__.items():
            if not key.startswith('__'):
                defaults[key] = value
        return self.config_class(root_path, defaults)
