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
import re

class JSONWebTokenLoginHandler(BaseHandler):
    async def get(self):
        header_name = self.authenticator.header_name
        cookie_name = self.authenticator.cookie_name
        param_name = self.authenticator.param_name
        project_param_name = self.authenticator.project_param_name

        enable_rtc = self.authenticator.enable_rtc

        auth_header_content = self.request.headers.get(header_name, "") if header_name else None
        auth_cookie_content = self.get_cookie(cookie_name, "") if cookie_name else None
        auth_param_content = self.get_argument(param_name, default="") if param_name else None
        project_param_content = self.get_argument(project_param_name, default="") if project_param_name else None

        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        algorithms = self.authenticator.algorithms
        audience = self.authenticator.expected_audience
        jwt_param_id = self.authenticator.jwt_param_id
        jwt_param_name = self.authenticator.jwt_param_name
        jwt_param_role = self.authenticator.jwt_param_role
        user_admin_indicator = self.authenticator.user_admin_indicator

        user_api_url = self.authenticator.user_api_url
        user_api_param_id = self.authenticator.user_api_param_id
        user_api_param_name = self.authenticator.user_api_param_name
        user_api_param_role = self.authenticator.user_api_param_role
        
        groups_api_url = self.authenticator.groups_api_url
        groups_api_params_projects_key = self.authenticator.groups_api_params_projects_key
        groups_api_already_checks_membership = self.authenticator.groups_api_already_checks_membership
        groups_api_param_id = self.authenticator.groups_api_param_id
        groups_api_param_name = self.authenticator.groups_api_param_name

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
        username = f"{claims[jwt_param_name]} ({claims[jwt_param_id]})"
        admin = self.retrieve_admin_status(claims, jwt_param_role, user_admin_indicator)
        groups = []
        roles = []

        # Call the API if one is provided
        if (user_api_url):

            # See https://api-staging.datagym.org/docs/#/Users/get_users_self
            # See https://staging-api.govspace.io/docs#/Users/UsersController_getSelf
            auth_header = "Bearer %s" % token
            headers = {"Authorization": auth_header}
            user_json_response = requests.get(user_api_url, headers=headers).json() 

            # self.log.warning("res: %s", user_json_response)

            # Check that the response is successful
            if user_api_param_id not in user_json_response:
                raise web.HTTPError(400)

            # Parse additional user params from API
            username = user_json_response[user_api_param_id].lower().replace(' ', '-')
            username = re.sub(r'[^a-z0-9-]', '', username)

            # Check admin status in jwt
            def get_nested(d, path):
                for key in path.split('.'):
                    d = d.get(key) if isinstance(d, dict) else None
                    if d is None:
                        break
                return d
            admin = get_nested(user_json_response, user_api_param_role) == user_admin_indicator
        
        # Access collaborative project if one is specified or if there is only one
        if (enable_rtc):

            # See https://api-staging.datagym.org/docs/#/Projects/get_projects_
            # See https://staging-api.govspace.io/docs#/Spaces/SpacesController_findAllMembershipsForCurrentUser
            auth_header = "Bearer %s" % token
            headers = {"Authorization": auth_header}
            projects_json_response = requests.get(groups_api_url, headers=headers).json()

            self.log.warning("pres: %s", user_json_response)

            projects_array = projects_json_response
            if groups_api_params_projects_key:
                projects_json_response[groups_api_params_projects_key]

            self.log.warning("parr: %s", projects_array)
            
            # Create projects as collaborative groups
            if projects_array:

                spawn_redirect_username = ""

                for project in projects_array:
 
                    # Allow only owners, members of groups, and admins to join the group
                    # Note that some APIs (e.g., GovSpace) only return projects where the user has these roles
                    if groups_api_already_checks_membership or (project['user_role'] and project['user_role'] in ['owner','member']):
                            
                            # "HACKATHON" fix
                            # if no project_uuid is passed in with the request, and
                            # they have a redirection flag set with "rtc" in the flag, 
                            # automatically use the first project to redirect to
                            # TODO: check project flag to ensure it's a collab-enabled project
                            if not project_param_content:
                                redirect_without_project_id = ('redirect_hub_subdomain' in user_json_response) and user_json_response['redirect_hub_subdomain'] and ("rtc" in user_json_response['redirect_hub_subdomain'])
                                if redirect_without_project_id and 'uuid' in project:
                                    project_param_content = project['uuid']
                                else:
                                    raise web.HTTPError(400, "Please specify a collaborative project identifier")
                            
                            self.log.warning("proj: %s", project)

                            # name the project with name (to ensure human readability) and UUID (to ensure uniqueness) components
                            # name a pseudo-user with the project name with a suffix to indicate it is a "collaboration" user
                            project_uuid = project[groups_api_param_id]
                            project_name = f"{project[groups_api_param_name]} ({project_uuid})".lower().replace(' ', '-')
                            project_name = re.sub(r'[^a-z0-9-]', '', project_name)
                            collab_username = f"{project_name}-collab"

                            # create a JupyterHub user for each collaboration and assign the collaboration user to the collaborative group to track it
                            collab_user = await self.auth_to_user({'name': collab_username, 'admin': False, 'groups': ['collaborative']})
                            
                            # set up a role granting access for the real user to the collaboration user’s account
                            new_role = {
                                "name": f"collab-access-{project_uuid}",
                                "scopes": [
                                    "self",
                                    f"access:servers!user={collab_username}",
                                    f"admin:servers!user={collab_username}",
                                    "read:users", # provide access to the admin UI just for projects I have access to
                                    f"list:users!user={collab_username}", # list the collaborators in my project
                                ],
                                "groups": [project_name],
                            }

                            # add to the roles and groups that will be given to the user
                            roles.append(new_role)
                            groups.append(project_name)

                            # store the name if it's the project corresponding to the project specified by a uuid in the auth param
                            if project_uuid == project_param_content:
                                spawn_redirect_username = collab_username

                # For non-admins, skip the home screen and redirect the user to spawn the collaboration notebook
                if not admin and spawn_redirect_username:
                    _url=url_path_join(self.hub.server.base_url, 'spawn', spawn_redirect_username)
                            
        # assign the group to the role, so it has access to the account
        # assign members of the project to the collaboration group, so they have access to the project
        base_scopes = [
            "servers",
            "read:users:me",
        ]

        admin_scopes = [
            "admin:users",        # manage users
            "admin:servers",      # manage user servers
            "admin:groups",       # manage groups
            "admin:roles",        # manage roles
            "admin:ui",           # access admin UI
            "servers",            # access own server (redundant but safe)
            "read:users:me",      # read own info
        ]

        scopes = base_scopes + (admin_scopes if admin else [])

        user = await self.auth_to_user({
            'name': username,
            'admin': admin,
            'groups': groups,
            'roles': roles,
            'scopes': scopes,
        })
        
        print("Name:", user.name)
        print("Admin:", user.admin)
        print("Groups:", user.groups)
        print("Roles:", user.roles)
        print("Scopes:", user.scopes)

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
        # logger.warning("jwt: %s", json_web_token)
        # logger.warning("sec: %s", secret)
        # logger.warning("alg: %s", algorithms)
        # logger.warning("aud: %s", audience)
        # logger.warning("opt: %s", opts)
        return jwt.decode(json_web_token, secret, algorithms=algorithms, audience=audience, options=opts)

    @staticmethod
    def retrieve_admin_status(claims, user_admin_indicator_key, user_admin_indicator_value):
        role = claims[user_admin_indicator_key]
        return (role and role == user_admin_indicator_value)


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

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    jwt_param_id = Unicode(
        default_value='user_id',
        config=True,
        help="""Key from jwt payload that indicates the user id."""
    )

    jwt_param_name = Unicode(
        default_value='name',
        config=True,
        help="""Key from jwt payload that indicates the user name."""
    )

    jwt_param_role = Unicode(
        default_value='role',
        config=True,
        help="""Key from jwt payload that indicates the user role."""
    )

    user_api_url = Unicode(
        default_value='',
        config=True,
        help="""URL for API to get additional user details after authentication."""
    )

    user_api_param_id = Unicode(
        default_value='uuid',
        config=True,
        help="""Key for unique identifier returned by the user_api_url after authentication."""
    )

    user_api_param_name = Unicode(
        default_value='name',
        config=True,
        help="""Key for user's name returned by the user_api_url after authentication."""
    )

    user_api_param_role = Unicode(
        default_value='role',
        config=True,
        help="""Key for user's role (e.g., admin) returned by the user_api_url after authentication."""
    )

    user_admin_indicator = Unicode(
        default_value='admin',
        config=True,
        help="""Value of user's role that indicates admin, in both the jwt payload and the user_api_url response after authentication."""
    )

    groups_api_url = Unicode(
        default_value='',
        config=True,
        help="""URL for API to get additional group details after authentication."""
    )

    groups_api_params_projects_key = Unicode(
        default_value='items',
        config=True,
        help="""Key for groups_api_url response that points to the array of projects."""
    )

    groups_api_already_checks_membership = Bool(
        default_value=False,
        config=True,
        help="""Flag to indicate whether the groups API only includes projects available to the user."""
    )

    groups_api_param_id = Unicode(
        default_value='uuid',
        config=True,
        help="""Key for unique identifier returned by the groups_api_url."""
    )

    groups_api_param_name = Unicode(
        default_value='name',
        config=True,
        help="""Key for project name returned by the groups_api_url."""
    )

    enable_rtc = Bool(
        default_value=False,
        config=True,
        help="""Flag to determine whether to enable real time collaboration logic."""
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
