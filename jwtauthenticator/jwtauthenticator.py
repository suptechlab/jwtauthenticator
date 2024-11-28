from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
import jwt
from tornado import (
    gen,
    web,
)
from traitlets import (
    Bool,
    List,
    Unicode,
)
from urllib import parse
import requests

class JSONWebTokenLoginHandler(BaseHandler):
    async def get(self):
        header_name = self.authenticator.header_name
        cookie_name = self.authenticator.cookie_name
        param_name = self.authenticator.param_name
        project_param_name = self.authenticator.project_param_name

        auth_header_content = self.request.headers.get(header_name, "") if header_name else None
        auth_cookie_content = self.get_cookie(cookie_name, "") if cookie_name else None
        auth_param_content = self.get_argument(param_name, default="") if param_name else None
        project_param_content = self.get_argument(param_name, default="") if project_param_name else None

        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        algorithms = self.authenticator.algorithms

        username_claim_field = self.authenticator.username_claim_field
        extract_username = self.authenticator.extract_username
        audience = self.authenticator.expected_audience

        user_api_url = self.authenticator.user_api_url
        groups_api_url = self.authenticator.groups_api_url

        auth_url = self.authenticator.auth_url
        retpath_param = self.authenticator.retpath_param

        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
            _url = next_url
            if param_name:
                auth_param_content = parse.parse_qs(parse.urlparse(next_url).query).get(param_name, "")
                if isinstance(auth_param_content, list):
                    auth_param_content = auth_param_content[0]

        if auth_url and retpath_param:
            auth_url += ("{prefix}{param}=https://{host}{url}".format(
                prefix='&' if '?' in auth_url else '?',
                param=retpath_param,
                host=self.request.host,
                url=_url,
            ))

        if bool(auth_header_content) + bool(auth_cookie_content) + bool(auth_param_content) > 1:
            raise web.HTTPError(400)
        elif auth_header_content:
            token = auth_header_content
        elif auth_cookie_content:
            token = auth_cookie_content
        elif auth_param_content:
            token = auth_param_content
        else:
            return self.auth_failed(auth_url)

        try:
            if secret:
                claims = self.verify_jwt_using_secret(token, secret, algorithms, audience, self.log)
            elif signing_certificate:
                claims = self.verify_jwt_with_claims(token, signing_certificate, algorithms, audience, self.log)
            else:
                return self.auth_failed(auth_url)
        except jwt.exceptions.InvalidTokenError:
            return self.auth_failed(auth_url)

        # First grab info directly from jwt
        username = self.retrieve_username(claims, username_claim_field, extract_username=extract_username)
        admin = self.retrieve_admin_status(claims)
        groups = []
        roles = []

        # Call the API if one is provided
        if (user_api_url):
            auth_header = "Bearer %s" % token
            headers = {"Authorization": auth_header}

            # See https://api-staging.datagym.org/docs/#/Users/get_users_self
            user_json_response = requests.get(user_api_url, headers=headers).json() 
            username = user_json_response['uuid']
            admin = 'role' in user_json_response and user_json_response['role'] == 'admin'
        
        # Access collaborative project if one is specified
        if (project_param_content):
            auth_header = "Bearer %s" % token
            headers = {"Authorization": auth_header}

            # See https://api-staging.datagym.org/docs/#/Projects/get_projects_
            projects_json_response = requests.get(groups_api_url, headers=headers).json()
            if projects_json_response and projects_json_response['items']:
                for project in projects_json_response['items']:

                    # Allow only owners and members of groups to join the group
                    if project['user_role'] and project['user_role'] in ['owner','member']:
                            
                            project_name = project['uuid']
                            
                            # create a JupyterHub user for each collaboration and assign the collaboration user to the collaboration group
                            collab_username = f"{project_name}-collab"
                            collab_user = await self.auth_to_user({'name': collab_username, 'admin': False, 'groups': ['collaborative']})

                            # create a role granting access to the collaboration user’s account
                            roles.append({
                                "name": f"collab-access-{project_name}",
                                "scopes": [
                                    f"access:servers!user={collab_username}",
                                    f"admin:servers!user={collab_username}",
                                    "admin-ui",
                                    f"list:users!user={collab_username}",
                                ],
                                "groups": [project_name],
                            })

                            # create a group for each collaboration
                            groups.append(project_name)

                # For non-admins, skip the home screen and redirect the user to spawn the collaboration notebook
                if not admin:
                    _url=url_path_join(self.hub.server.base_url, 'hub/spawn/', project_param_content, '-collab')
                            
        # assign the group to the role, so it has access to the account
        # assign members of the project to the collaboration group, so they have access to the project
        user = await self.auth_to_user({'name': username, 'admin': admin, 'groups': groups, 'roles': roles})
        self.set_login_cookie(user)

        self.redirect(_url)

    def auth_failed(self, redirect_url):
        if redirect_url:
            self.redirect(redirect_url)
        else:
            raise web.HTTPError(401)

    @staticmethod
    def verify_jwt_with_claims(token, signing_certificate, algorithms, audience, logger=None):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        with open(signing_certificate, 'r') as rsa_public_key_file:
            return jwt.decode(token, rsa_public_key_file.read(), audience=audience, algorithms=algorithms, options=opts)

    @staticmethod
    def verify_jwt_using_secret(json_web_token, secret, algorithms, audience, logger=None):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        opts['verify_signature'] = False
        #logger.warning("jwt: %s", json_web_token)
        #logger.warning("sec: %s", secret)
        #logger.warning("alg: %s", algorithms)
        #logger.warning("aud: %s", audience)
        #logger.warning("opt: %s", opts)
        return jwt.decode(json_web_token, secret, algorithms=algorithms, audience=audience, options=opts)

    @staticmethod
    def retrieve_username(claims, username_claim_field, extract_username):
        username = claims[username_claim_field]
        if extract_username:
            if "@" in username:
                return username.split("@")[0]
        return username
    
    @staticmethod
    def retrieve_admin_status(claims):
        role = claims["role"] # TODO: extract to config file similar to retrieve_username
        return (role and role == "admin")


class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """
    auth_url = Unicode(
        config=True,
        help="""URL for redirecting to in the case of invalid auth token""")

    retpath_param = Unicode(
        config=True,
        help="""Name of query param for auth_url to pass return URL""")

    header_name = Unicode(
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    cookie_name = Unicode(
        config=True,
        help="""The name of the cookie field used to specify the JWT token""")

    param_name = Unicode(
        config=True,
        help="""The name of the query parameter used to specify the JWT token""")
    
    project_param_name = Unicode(
        config=True,
        help="""The name of the query parameter used to specify the project for a collaborative gym""")

    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token. If defined, it overrides any setting for signing_certificate""")

    algorithms = List(
        default_value=['HS256'],
        config=True,
        help="""Specify which algorithms you would like to permit when validating the JWT""")

    username_claim_field = Unicode(
        default_value='username',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    extract_username = Bool(
        default_value=True,
        config=True,
        help="""
        Set to true to split username_claim_field and take the part before the first `@`
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    user_api_url = Unicode(
        default_value='',
        config=True,
        help="""URL for API to get additional user details after authentication."""
    )

    groups_api_url = Unicode(
        default_value='',
        config=True,
        help="""URL for API to get additional group details after authentication."""
    )

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass
