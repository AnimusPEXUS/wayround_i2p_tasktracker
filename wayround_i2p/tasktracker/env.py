
import os.path
import urllib.parse
import datetime
import difflib

import wayround_i2p.utils.file
import wayround_i2p.utils.http

import wayround_i2p.http.cookies

import wayround_i2p.carafe.carafe
import wayround_i2p.wsgi.server


from wayround_i2p.utils.list import (
    list_strip_remove_empty_remove_duplicated_lines
    )

import wayround_i2p.softengine.rtenv

MIME_HTML = wayround_i2p.carafe.carafe.MIME_HTML


class Session:

    def __init__(self):
        self.session_cookie = None
        self.pkey = None
        self.site_role = None
        self.project_roles = {}
        self.session_valid_till = None
        return


class PageAction:

    def __init__(self, title, href):
        self.title = title
        self.href = href
        return


class Environment:

    def __init__(
            self,
            rtenv,
            host='localhost',
            port=8080,
            admin_pkey=None
            ):

        self.ttm = 'wayround_i2p_tasktracker_modules_TaskTracker'

        self.session_cookie_name = 'wayround_i2p_tasktracker_session_cookie'

        self._bot = None

        self.admin_pkey = admin_pkey

        self.rtenv = rtenv

        # self.host = host
        # self.port = port

        self.carafe_app = \
            wayround_i2p.carafe.carafe.Carafe(self.router_entry)

        self.wsgi_server = \
            wayround_i2p.wsgi.server.CompleteServer(
                self.carafe_app.target_for_wsgi_server,
                address=(host, port)
                )

        self.router = \
            wayround_i2p.carafe.carafe.Router(self.default_router_target)

        self.router.add(
            'GET',
            [('=', 'index')
             ],
            self.index
            )  # this rule is for empty path or foe root dir. not tested
        # probably invalid

        self.router.add(
            'GET',
            [
                ('=', 'js'),
                ('fm', '*', 'filename')
                ],
            self.js
            )

        self.router.add(
            'GET',
            [
                ('=', 'css'),
                ('fm', '*', 'filename')
                ],
            self.css
            )

        self.router.add(
            'GET',
            [
                ('=', 'settings')
                ],
            self.site_settings
            )

        self.router.add(
            'POST',
            [
                ('=', 'settings')
                ],
            self.site_settings_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'roles')
                ],
            self.site_roles
            )

        self.router.add(
            'POST',
            [
                ('=', 'roles')
                ],
            self.site_roles_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'logout')
                ],
            self.logout
            )

        self.router.add(
            'GET',
            [
                ('=', 'new_project')
                ],
            self.new_project
            )

        self.router.add(
            'POST',
            [
                ('=', 'new_project')
                ],
            self.new_project_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name')
                ],
            self.project_view
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'issues')
                ],
            self.project_issues
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'activities')
                ],
            self.project_activities
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'settings')
                ],
            self.edit_project
            )

        self.router.add(
            'POST',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'settings')
                ],
            self.edit_project_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'roles')
                ],
            self.project_roles
            )

        self.router.add(
            'POST',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'roles')
                ],
            self.project_roles_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'new_issue')
                ],
            self.new_issue
            )

        self.router.add(
            'POST',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('=', 'new_issue')
                ],
            self.new_issue_post
            )

        self.router.add(
            'GET',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('re', '\d+')
                ],
            self.view_issue
            )

        self.router.add(
            'POST',
            [
                ('=', 'project'),
                ('fm', '*', 'project_name'),
                ('re', '\d+')
                ],
            self.edit_issue_post
            )
        return

    def set_bot(self, bot):
        self._bot = bot
        return

    def router_entry(self, wsgi_environment, response_start):
        return self.router.wsgi_server_target(wsgi_environment, response_start)

    def start(self):
        self.wsgi_server.start()
        return

    def stop(self):
        self.wsgi_server.stop()
        return

    def default_router_target(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        response_start(
            '404',
            [('Content-Type', 'text/plain; charset=UTF-8')]
            )
        ret = '404: not found'
        return ret

    def css(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        filename = route_result['filename']
        filename = self.rtenv.modules[self.ttm].js(filename)
        # TODO: replace with smart StaticFile object
        ret = open(filename, 'rb')
        response_start(
            '200',
            [('Content-Type', 'text/css')]
            )
        '''
        ret = wayround_i2p.carafe.carafe.static_file(
            response_start,
            os.path.basename(filename),
            os.path.dirname(filename)
            )
        '''
        return ret

    def js(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        filename = route_result['filename']
        filename = self.rtenv.modules[self.ttm].js(filename)
        # TODO: replace with smart StaticFile object
        ret = open(filename, 'rb')
        response_start(
            '200',
            [('Content-Type', 'application/javascript')]
            )
        '''
        ret = wayround_i2p.carafe.carafe.static_file(
            response_start,
            os.path.basename(filename),
            root=os.path.dirname(filename)
            )
        '''
        return ret

    def get_page_actions(
            self,
            mode=None,
            rts_object=None,
            project_name=None,
            issue_id=None
            ):

        if not isinstance(rts_object, Session):
            raise TypeError("rts_object must be a Session object")

        lst = []

        lst.append(PageAction('Project List', '/index'))

        if mode == 'index' and rts_object.site_role == 'admin':
            lst.append(PageAction('New Project', '/new_project'))

        if project_name:

            lst.append(
                PageAction(
                    'Project',
                    '/project/{}'.format(urllib.parse.quote(project_name))
                    )
                )

            lst.append(
                PageAction(
                    'All Issues',
                    '/project/{}/issues'.format(
                        urllib.parse.quote(project_name)
                        )
                    )
                )

            lst.append(
                PageAction(
                    'Activities',
                    '/project/{}/activities'.format(
                        urllib.parse.quote(project_name)
                        )
                    )
                )

            lst.append(
                PageAction(
                    'New Issue',
                    '/project/{}/new_issue'.format(
                        urllib.parse.quote(project_name)
                        )
                    )
                )

        if issue_id:
            lst.append(
                PageAction(
                    'This Issue',
                    '/project/{}/{}'.format(
                        urllib.parse.quote(project_name),
                        urllib.parse.quote(str(issue_id))
                        )
                    )
                )

        if project_name:
            if (rts_object.site_role == 'admin' or
                (project_name in rts_object.project_roles and
                 rts_object.project_roles[project_name] == 'admin')):

                lst.append(
                    PageAction(
                        'Project Settings',
                        '/project/{}/settings'.format(
                            urllib.request.quote(project_name)
                            )
                        )
                    )
                lst.append(
                    PageAction(
                        'Project Roles',
                        '/project/{}/roles'.format(
                            urllib.request.quote(project_name)
                            )
                        )
                    )

        if rts_object.site_role == 'admin':
            lst.append(PageAction('Site Settings', '/settings'))
            lst.append(PageAction('Site Roles', '/roles'))

        ret = self.rtenv.modules[self.ttm].actions_tpl(
            lst,
            session_actions=self.rtenv.modules[self.ttm].session_tpl(
                rts_object=rts_object
                )
            )

        return ret

    def generate_rts_object(self, wsgi_request):
        """
        rts - run time session
        """

        s = None

        cookies = wayround_i2p.http.cookies.Cookies.new_from_wsgi_request(
            wsgi_request
            )

        cookies = cookies.cookiesYAML

        if self.session_cookie_name in cookies:
            print(
                'cookie {}'.format(cookies[self.session_cookie_name].value)
                )

            s = self.rtenv.modules[self.ttm].get_session_by_cookie(
                cookies[self.session_cookie_name].value
                )

        if s is None:
            print(
                "cookie not provided({}) or s is None({})".format(
                    self.session_cookie_name in cookies,
                    s is None
                    )
                )
            s = self.rtenv.modules[self.ttm].new_session()

        ret = Session()
        ret.session_cookie = s.session_cookie
        ret.pkey = s.pkey
        ret.session_valid_till = s.session_valid_till

        roles = self.get_site_roles_for_pkey(s.pkey)

        ret.project_roles = roles['project_roles']
        ret.site_role = roles['site_role']

        return ret

    def render_output_session_cookie(self, session, lst):
        if not isinstance(session, Session):
            raise TypeError("`session' must be of Session type")

        cookies = wayround_i2p.http.cookies.CookiesYAML()
        cookies.add_from_values(
            self.session_cookie_name,
            session.session_cookie
            )
        cookies = cookies.cookies

        cookies.append_to_s2c_field_tuple_list(lst)

        return

    def get_site_roles_for_pkey(self, pkey=None, all_site_projects=False):

        ret = {}

        ret['project_roles'] = {}

        if all_site_projects:
            all_projects = self.rtenv.modules[self.ttm].get_projects()

            for i in all_projects:
                ret['project_roles'][i.name] = 'guest'

        ret['project_roles'].update(
            self.rtenv.modules[self.ttm].get_project_roles_of_pkey_dict(
                pkey
                )
            )

        ret['site_role'] = 'guest'

        if pkey == self.admin_pkey:
            ret['site_role'] = 'admin'
        else:
            site_role = self.rtenv.modules[self.ttm].get_site_role(pkey)

            if site_role is None:
                ret['site_role'] = 'guest'
            else:
                if not site_role.role in ['admin', 'user', 'blocked']:
                    ret['site_role'] = 'guest'
                else:
                    ret['site_role'] = site_role.role

        if ret['site_role'] in ['admin', 'moder', 'blocked', 'guest']:
            for i in ret['project_roles'].keys():
                ret['project_roles'][i] = ret['site_role']

        return ret

    def index(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        projects = self.rtenv.modules[self.ttm].get_projects()

        project_list = self.rtenv.modules[self.ttm].project_list_tpl(
            projects,
            rts_object=rts
            )

        actions = self.get_page_actions(
            mode='index',
            rts_object=rts
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title=self.rtenv.modules[self.ttm].get_site_setting(
                'site_title',
                'Not titled'
                ),
            actions=actions,
            body=project_list
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return ret

    def site_settings_access_check(self, rts):

        if rts.site_role != 'admin':
            raise wayround_i2p.carafe.carafe.HTTPError("403 Not Allowed")

        return

    def site_settings(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.site_settings_access_check(rts)

        actions = self.get_page_actions(
            mode='settings',
            rts_object=rts
            )

        site_title = self.rtenv.modules[self.ttm].get_site_setting(
            'site_title',
            'Not titled'
            )

        site_description = self.rtenv.modules[self.ttm].get_site_setting(
            'site_description',
            'None'
            )

        user_can_register_self = self.rtenv.modules[self.ttm].get_site_setting(
            'user_can_register_self',
            False
            ) == '1'

        user_can_create_projects = \
            self.rtenv.modules[self.ttm].get_site_setting(
                'user_can_create_projects',
                False
                ) == '1'

        settings_page = self.rtenv.modules[self.ttm].site_settings_tpl(
            site_title,
            site_description,
            user_can_register_self,
            user_can_create_projects
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change site settings",
            actions=actions,
            body=settings_page
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return ret

    def site_settings_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.site_settings_access_check(rts)

        for i in [
                'site_title',
                'site_description',
                ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        wayround_i2p.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
                'user_can_register_self',
                'user_can_create_projects'
            ]
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'site_title',
            decoded_params['site_title']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'site_description',
            decoded_params['site_description']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'user_can_register_self',
            decoded_params['user_can_register_self']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'user_can_create_projects',
            decoded_params['user_can_create_projects']
            )

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return

    site_roles_access_check = site_settings_access_check

    def site_roles(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.site_roles_access_check(rts)

        actions = self.get_page_actions(
            mode='settings',
            rts_object=rts
            )

        roles = self.rtenv.modules[self.ttm].get_site_roles_dict()

        admins = []
        moders = []
        users = []
        blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                admins.append(i)

            if roles[i] == 'moder':
                moders.append(i)

            if roles[i] == 'user':
                users.append(i)

            if roles[i] == 'blocked':
                blocked.append(i)

        admins.sort()
        moders.sort()
        users.sort()
        blocked.sort()

        roles_page = self.rtenv.modules[self.ttm].site_roles_tpl(
            admins='\n'.join(admins),
            moders='\n'.join(moders),
            users='\n'.join(users),
            blocked='\n'.join(blocked)
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change site roles",
            actions=actions,
            body=roles_page
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def site_roles_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.site_roles_access_check(rts)

        for i in [
                'admins',
                'moders',
                'users',
                'blocked'
                ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        admins = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['admins'].splitlines()
            )

        moders = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['moders'].splitlines()
            )

        users = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['users'].splitlines()
            )

        blocked = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['blocked'].splitlines()
            )

        roles = {}

        for i in admins:
            roles[i] = 'admin'

        del admins

        for i in moders:
            roles[i] = 'moder'

        del moders

        for i in users:
            roles[i] = 'user'

        del users

        for i in blocked:
            roles[i] = 'blocked'

        del blocked

        roles = self.rtenv.modules[self.ttm].set_site_roles(roles)

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return

    def new_project_access_check(self, rts):

        if (rts.site_role != 'admin' and
            self.rtenv.modules[self.ttm].get_site_setting(
                        'user_can_create_projects',
                        False
                        ) != '1'
            ):
            raise wayround_i2p.carafe.carafe.HTTPError(403, "Not Allowed")

        return

    def new_project(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.new_project_access_check(rts)

        actions = self.get_page_actions(
            mode='edit_project',
            rts_object=rts
            )

        edit_project_tpl = self.rtenv.modules[self.ttm].edit_project_tpl(
            mode='new'
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Create new project",
            actions=actions,
            body=edit_project_tpl
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def new_project_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        rts = self.generate_rts_object(wsgi_environment)

        self.new_project_access_check(rts)

        for i in ['name', 'title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        wayround_i2p.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
                'guests_access_allowed'
            ]
            )

        name = decoded_params['name']

        self.rtenv.modules[self.ttm].new_project(
            name,
            decoded_params['title'],
            decoded_params['description'],
            decoded_params['guests_access_allowed']
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Project creation result",
            actions='',
            body=''
            )

        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/project/{}'.format(urllib.parse.quote(name))
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def edit_project_access_check(self, rts, project_record):

        allowed = False

        if rts.site_role == 'admin':
            allowed = True

        if project_record.name in rts.project_roles \
                and rts.project_roles[project_record.name] == 'admin':
            allowed = True

        if not allowed:
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def edit_project(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        rts = self.generate_rts_object(wsgi_environment)

        ret = ''

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.edit_project_access_check(rts, p)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='edit_project',
                rts_object=rts,
                project_name=project_name
                )

            edit_project_tpl = self.rtenv.modules[self.ttm].edit_project_tpl(
                mode='edit',
                name=project_name,
                title=p.title,
                description=p.description,
                guests_access_allowed=p.guests_access_allowed
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="Edit project",
                actions=actions,
                body=edit_project_tpl
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def edit_project_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        rts = self.generate_rts_object(wsgi_environment)

        for i in ['title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        wayround_i2p.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
                'guests_access_allowed'
            ]
            )

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.edit_project_access_check(rts, p)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        p = self.rtenv.modules[self.ttm].edit_project(
            project_name,
            decoded_params['title'],
            decoded_params['description'],
            decoded_params['guests_access_allowed']
            )

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/project/{}'.format(urllib.parse.quote(project_name))
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return

    project_roles_access_check = edit_project_access_check

    def project_roles(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.project_roles_access_check(rts, p)

        del p

        actions = self.get_page_actions(
            mode='project_roles',
            rts_object=rts,
            project_name=project_name
            )

        roles = self.rtenv.modules[self.ttm].get_site_roles_dict()

        site_admins = []
        site_moders = []
        site_users = []
        site_blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                site_admins.append(i)

            if roles[i] == 'moder':
                site_moders.append(i)

            if roles[i] == 'user':
                site_users.append(i)

            if roles[i] == 'blocked':
                site_blocked.append(i)

        site_admins.sort()
        site_moders.sort()
        site_users.sort()
        site_blocked.sort()

        roles = self.rtenv.modules[self.ttm].get_project_roles_dict(
            project_name
            )

        admins = []
        moders = []
        users = []
        blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                admins.append(i)

            if roles[i] == 'moder':
                moders.append(i)

            if roles[i] == 'user':
                users.append(i)

            if roles[i] == 'blocked':
                blocked.append(i)

        admins.sort()
        moders.sort()
        users.sort()
        blocked.sort()

        roles_page = self.rtenv.modules[self.ttm].project_roles_tpl(
            admins='\n'.join(admins),
            moders='\n'.join(moders),
            users='\n'.join(users),
            blocked='\n'.join(blocked),
            site_admins='\n'.join(site_admins),
            site_moders='\n'.join(site_moders),
            site_users='\n'.join(site_users),
            site_blocked='\n'.join(site_blocked),
            god=self.admin_pkey
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change project roles",
            actions=actions,
            body=roles_page
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return ret

    def project_roles_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        rts = self.generate_rts_object(wsgi_environment)

        self.project_roles_access_check(rts)

        for i in [
                'admins',
                'moders',
                'users',
                'blocked'
                ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        admins = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['admins'].splitlines()
            )

        moders = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['moders'].splitlines()
            )

        users = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['users'].splitlines()
            )

        blocked = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['blocked'].splitlines()
            )

        roles = {}

        for i in admins:
            roles[i] = 'admin'

        del admins

        for i in moders:
            roles[i] = 'moder'

        del moders

        for i in users:
            roles[i] = 'user'

        del users

        for i in blocked:
            roles[i] = 'blocked'

        del blocked

        roles = self.rtenv.modules[self.ttm].set_site_roles(roles)

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return

    def login_access_check(self, pkey):

        ret = True

        role = self.rtenv.modules[self.ttm].get_site_role(pkey)

        if not role or role.role == 'blocked':
            ret = False

        return ret

    def register_access_check(self, pkey):

        ret = True

        role = self.rtenv.modules[self.ttm].get_site_role(pkey)

        if role or not self.rtenv.modules[self.ttm].get_site_setting(
                'user_can_register_self',
                False
                ):

            ret = False

        return ret

    def logout(self):
        bottle.response.delete_cookie(self.session_cookie_name)
        bottle.response.status = 303
        bottle.response.set_header('Location', '/')
#        bottle.response.set_header('Cache-Control', 'no-cache')
#        bottle.redirect('/', code=200)
        return

    def redirect_to_project_view(self, project_name):
        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/project/{}'.format(urllib.parse.quote(project_name))
            )
        return

    def project_view_access_check(self, rts, project_record):

        allowed = False

        if rts.site_role == 'admin':
            allowed = True

        if project_record.name in rts.project_roles:

            if rts.project_roles[project_record.project_name] != 'blocked':
                allowed = True

        else:

            if project_record.guests_access_allowed:
                allowed = True

        if not allowed:
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def project_view(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        ret = ''

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            self.project_view_access_check(rts, p)

            actions = self.get_page_actions(
                mode='project',
                project_name=project_name,
                rts_object=rts
                )

            opened = self.rtenv.modules[self.ttm].get_project_issues(
                project_name, 'open', 0, 100
                )

            closed = self.rtenv.modules[self.ttm].get_project_issues(
                project_name, 'closed', 0, 100
                )

            deleted = self.rtenv.modules[self.ttm].get_project_issues(
                project_name, 'deleted', 0, 100
                )

            open_table = self.rtenv.modules[self.ttm].\
                issue_teaser_table_tpl(opened)

            closed_table = self.rtenv.modules[self.ttm].issue_teaser_table_tpl(
                closed
                )

            deleted_table = self.rtenv.modules[self.ttm].\
                issue_teaser_table_tpl(
                    deleted
                    )

            project_page = self.rtenv.modules[self.ttm].project_page_tpl(
                project_name=project_name,
                open_issue_table=open_table,
                closed_issue_table=closed_table,
                deleted_issue_table=deleted_table
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' issues".format(p.title),
                actions=actions,
                body=project_page
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def project_issues(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        ret = ''

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.project_view_access_check(rts, p)

        decoded_params = bottle.request.params.decode('utf-8')

        if not 'page' in decoded_params:
            decoded_params['page'] = '0'

        if not 'count' in decoded_params:
            decoded_params['count'] = '100'

        if not 'status' in decoded_params:
            decoded_params['status'] = 'open'

        if (not decoded_params['status']
                in self.rtenv.modules[self.ttm].statuses):
            raise bottle.HTTPError(400, body="invalid status")

        try:
            page = int(decoded_params['page'])
            count = int(decoded_params['count'])
        except:
            raise bottle.HTTPError(400, body="invalid numbers")

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='project_activities',
                project_name=project_name,
                rts_object=rts
                )

            issue_records = self.rtenv.modules[self.ttm].get_project_issues(
                project_name,
                decoded_params['status'],
                page * count,
                (page * count) + count
                )

            issue_page = self.rtenv.modules[self.ttm].project_issues_page_tpl(
                issue_records=issue_records,
                status=decoded_params['status'],
                page=page,
                count=count
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' {} issues".format(
                    p.title,
                    decoded_params['status']
                    ),
                actions=actions,
                body=issue_page
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def project_activities(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        ret = ''

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.project_view_access_check(rts, p)

        decoded_params = bottle.request.params.decode('utf-8')

        if not 'page' in decoded_params:
            decoded_params['page'] = '0'

        if not 'count' in decoded_params:
            decoded_params['count'] = '100'

        try:
            page = int(decoded_params['page'])
            count = int(decoded_params['count'])
        except:
            raise bottle.HTTPError(400, body="invalid numbers")

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='project_activities',
                project_name=project_name,
                rts_object=rts
                )

            project_updates = self.rtenv.modules[self.ttm].get_project_updates(
                project_name, page * count, ((page * count) + count)
                )

            activities_table = self.rtenv.modules[self.ttm].\
                project_activity_table_tpl(
                    activities=project_updates, page=page, count=count
                    )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' activities".format(p.title),
                actions=actions,
                body=activities_table
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def new_issue_access_check(self, rts, project_record):

        allowed = False

        if rts.site_role == 'admin':
            allowed = True

        if project_record.name in rts.project_roles:

            if rts.project_roles[project_record.project_name] != 'blocked':
                allowed = True

        if not allowed:
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def new_issue(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        ret = ''

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.new_issue_access_check(rts, p)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='issue',
                rts_object=rts,
                project_name=project_name
                )

            edit_issue_tpl = self.rtenv.modules[self.ttm].edit_issue_tpl(
                mode='new',
                project_name=p.name,
                project_title=p.title
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="Create new issue",
                actions=actions,
                body=edit_issue_tpl
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret

    def new_issue_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']

        rts = self.generate_rts_object(wsgi_environment)

        p = self.rtenv.modules[self.ttm].get_project(project_name)

        self.new_issue_access_check(rts, p)

        for i in [
                'title',
                'priority',
                'status',
                'resolution',
                'description',
                'assigned_to',
                'watchers',
                'submit_type'
                ]:
            if not i in bottle.request.params:
                print("MEMFILE_MAX {}".format(bottle.request.MEMFILE_MAX))
                raise KeyError("parameter `{}' must be passed".format(i))
            else:
                print("param {} == {}".format(i, bottle.request.params[i]))

        decoded_params = bottle.request.params.decode('utf-8')

        if decoded_params['submit_type'] != 'issue_edit':
            raise bottle.HTTPError(400, "Wrong editing mode")

        current_date = datetime.datetime.now()

        issue = self.rtenv.modules[self.ttm].new_issue(
            project_name=project_name,
            title=decoded_params['title'],
            priority=decoded_params['priority'],
            status=decoded_params['status'],
            resolution=decoded_params['resolution'],
            description=decoded_params['description'],
            creation_date=current_date
            )

        people = self.rtenv.modules[self.ttm].issue_get_roles(issue.issue_id)

        self.make_issue_update(
            rts,
            issue.project_name,
            issue.issue_id,
            author_pkey=rts.pkey,
            title_old='',
            title=decoded_params['title'],
            priority_old='',
            priority=decoded_params['priority'],
            status_old='',
            status=decoded_params['status'],
            resolution_old='',
            resolution=decoded_params['resolution'],
            description_old='',
            description=decoded_params['description'],
            current_issue_people=people,
            assigned_to_text=decoded_params['assigned_to'],
            watchers_text=decoded_params['watchers'],
            comment='New issue created',
            date=current_date
            )

        ret = ''

        people = {
            'worker': list_strip_remove_empty_remove_duplicated_lines(
                decoded_params['assigned_to'].splitlines()
                ),
            'watcher': list_strip_remove_empty_remove_duplicated_lines(
                decoded_params['watchers'].splitlines()
                )
            }

        self.rtenv.modules[self.ttm].issue_set_roles(issue.issue_id, people)

        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/project/{}/{}'.format(
                urllib.parse.quote(project_name),
                urllib.parse.quote(str(issue.issue_id))
                )
            )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return ret

    view_issue_access_check = project_view_access_check

    def view_issue(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']
        issue_id = route_result['issue_id']

        ret = ''

        rts = self.generate_rts_object(wsgi_environment)

        project = self.rtenv.modules[self.ttm].get_project(project_name)

        self.view_issue_access_check(rts, project)

        issue = self.rtenv.modules[self.ttm].get_issue(issue_id)

        if not project:
            raise bottle.HTTPError(404, body="Project not found")

        elif not issue:
            raise bottle.HTTPError(404, body="Issue not found")

        elif project_name != issue.project_name:
            raise bottle.HTTPError(
                404,
                body="Selected issue is not belongings to selected project"
                )

        else:

            actions = self.get_page_actions(
                mode='edit_issue',
                project_name=project_name,
                issue_id=issue_id,
                rts_object=rts
                )

            updates = self.rtenv.modules[self.ttm].get_issue_updates(issue_id)

            updates_table = self.rtenv.modules[self.ttm].\
                issue_update_table_tpl(updates)

            people = self.rtenv.modules[self.ttm].issue_get_roles(issue_id)

            edit_issue_tpl = self.rtenv.modules[self.ttm].edit_issue_tpl(
                mode='view',
                issue_id=issue.issue_id,
                project_name=issue.project_name,
                project_title=project.title,
                title=issue.title,
                priority=issue.priority,
                status=issue.status,
                resolution=issue.resolution,
                description=issue.description,
                assigned_to='\n'.join(people['worker']),
                watchers='\n'.join(people['watcher']),
                created_date=issue.creation_date,
                updated_date=issue.updation_date,
                comments=updates_table,
                comment='',
                relations=self.rtenv.modules[self.ttm].issue_get_relations(
                    issue_id
                    )
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="Issue #{ide}: {title}".format(
                    ide=issue_id,
                    title=issue.title
                    ),
                actions=actions,
                body=edit_issue_tpl
                )

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)

        return ret

    def make_issue_update(
            self,
            rts,
            project_name,
            issue_id,
            author_pkey,
            title_old,
            title,
            priority_old,
            priority,
            status_old,
            status,
            resolution_old,
            resolution,
            description_old,
            description,

            current_issue_people,

            assigned_to_text,
            watchers_text,

            comment,
            date
            ):

        _t = list_strip_remove_empty_remove_duplicated_lines(
            assigned_to_text.splitlines()
            )

        _t.sort()
        corrected_workers = '\n'.join(_t)

        _t = list_strip_remove_empty_remove_duplicated_lines(
            watchers_text.splitlines()
            )
        _t.sort()
        corrected_watchers = '\n'.join(_t)

        descr_diff = 'None'
        if description_old != description:
            descr_diff = '\n'.join(difflib.ndiff(
                description_old.splitlines(),
                description.splitlines()
                ))

        assigned_diff = 'None'
        _t = '\n'.join(current_issue_people['worker'])
        if _t != corrected_workers:
            print("{}\n!={}".format(repr(_t), repr(corrected_workers)))
            assigned_diff = '\n'.join(difflib.ndiff(
                _t.splitlines(),
                corrected_workers.splitlines()
                ))

        watchers_diff = 'None'
        _t = '\n'.join(current_issue_people['watcher'])
        if _t != corrected_watchers:
            print("{}\n!={}".format(repr(_t), repr(corrected_watchers)))
            watchers_diff = '\n'.join(difflib.ndiff(
                _t.splitlines(),
                corrected_watchers.splitlines()
                ))

        self.rtenv.modules[self.ttm].make_issue_update(
            project_name=project_name,
            issue_id=issue_id,
            author_pkey=author_pkey,
            title_old=title_old,
            title=title,
            priority_old=priority_old,
            priority=priority,
            status_old=status_old,
            status=status,
            resolution_old=resolution_old,
            resolution=resolution,
            description_diff=descr_diff,
            assigned_to_diff=assigned_diff,
            watchers_diff=watchers_diff,
            comment=comment,
            date=date
            )

        return

    edit_issue_post_access_check = new_issue_access_check

    def edit_issue_post(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        project_name = route_result['project_name']
        issue_id = route_result['issue_id']

        ret = None

        if not 'submit_type' in bottle.request.params:
            raise KeyError("parameter `submit_type' must be passed")

        if bottle.request.params['submit_type'] == 'issue_edit':

            for i in [
                    'issue_id',
                    'title',
                    'priority',
                    'status',
                    'resolution',
                    'description',
                    'assigned_to',
                    'watchers',
                    'comment',
                    ]:
                if not i in bottle.request.params:
                    raise KeyError("parameter `{}' must be passed".format(i))

            decoded_params = bottle.request.params.decode('utf-8')

            rts = self.generate_rts_object()

            project = self.rtenv.modules[self.ttm].get_project(project_name)

            self.edit_issue_post_access_check(rts, project)

            issue = self.rtenv.modules[self.ttm].get_issue(issue_id)

            if not project:
                raise bottle.HTTPError(404, body="Project not found")

            elif not issue:
                raise bottle.HTTPError(404, body="Issue not found")

            elif project_name != issue.project_name:
                raise bottle.HTTPError(
                    404,
                    body="Selected issue does not belongs to selected project"
                    )

            else:

                current_date = datetime.datetime.now()

                people = self.rtenv.modules[self.ttm].issue_get_roles(issue_id)

                self.make_issue_update(
                    rts,
                    issue.project_name,
                    issue.issue_id,
                    author_pkey=rts.pkey,
                    title_old=issue.title,
                    title=decoded_params['title'],
                    priority_old=issue.priority,
                    priority=decoded_params['priority'],
                    status_old=issue.status,
                    status=decoded_params['status'],
                    resolution_old=issue.resolution,
                    resolution=decoded_params['resolution'],
                    description_old=issue.description,
                    description=decoded_params['description'],
                    current_issue_people=people,
                    assigned_to_text=decoded_params['assigned_to'],
                    watchers_text=decoded_params['watchers'],
                    comment=decoded_params['comment'],
                    date=current_date
                    )

                ret = self.rtenv.modules[self.ttm].edit_issue(
                    issue_id=issue_id,
                    title=decoded_params['title'],
                    priority=decoded_params['priority'],
                    status=decoded_params['status'],
                    resolution=decoded_params['resolution'],
                    description=decoded_params['description'],
                    updation_date=current_date
                    )

                people = {
                    'worker': list_strip_remove_empty_remove_duplicated_lines(
                        decoded_params['assigned_to'].splitlines()
                        ),
                    'watcher': list_strip_remove_empty_remove_duplicated_lines(
                        decoded_params['watchers'].splitlines()
                        )
                    }

                self.rtenv.modules[self.ttm].issue_set_roles(issue_id, people)

            bottle.response.status = 303
            bottle.response.set_header(
                'Location', '/project/{}/{}'.format(
                    urllib.parse.quote(project_name),
                    urllib.parse.quote(str(issue_id))
                    )
                )

        elif bottle.request.params['submit_type'] == 'relations_edit':

            for i in [
                    'issue_id'
                    ]:
                if not i in bottle.request.params:
                    raise KeyError("parameter `{}' must be passed".format(i))

            decoded_params = bottle.request.params.decode('utf-8')

            rts = self.generate_rts_object()

            project = self.rtenv.modules[self.ttm].get_project(project_name)

            self.edit_issue_post_access_check(rts, project)

            issue = self.rtenv.modules[self.ttm].get_issue(issue_id)

            if not project:
                raise bottle.HTTPError(404, body="Project not found")

            elif not issue:
                raise bottle.HTTPError(404, body="Issue not found")

            elif project_name != issue.project_name:
                raise bottle.HTTPError(
                    404,
                    body="Selected issue does not belongs to selected project"
                    )

            else:

                self.rtenv.modules[self.ttm].issue_del_relations(issue_id)

                delete_relation_list = decoded_params.dict.get(
                    'delete_relation[]', []
                    )

                for i in range(
                        len(decoded_params.dict.get('relation_type[]', []))
                        ):

                    rti = decoded_params.dict['relation_target_id[]'][i]
                    try:
                        rti = int(rti)
                    except:
                        rti = 0

                    if rti == int(issue_id):
                        continue

                    issu = self.rtenv.modules[self.ttm].get_issue(rti)

                    if not issu:
                        continue

                    if issu and not issu.project_name == project_name:
                        continue

                    rt = decoded_params.dict['relation_type[]'][i]
                    if not rt.isidentifier():
                        rt = 'relates'

                    if not str(rti) in delete_relation_list:

                        self.rtenv.modules[self.ttm].issue_add_relation(
                            int(issue_id),
                            rti,
                            rt
                            )

            bottle.response.status = 303
            bottle.response.set_header(
                'Location', '/project/{}/{}'.format(
                    urllib.parse.quote(project_name),
                    urllib.parse.quote(str(issue_id))
                    )
                )

        else:
            pass

        http_header = [
            ('Content-Type', MIME_HTML)
            ]

        self.render_output_session_cookie(rts, http_header)

        response_start(200, http_header)


        return ret


def install_launcher(path):

    if not os.path.exists(path):
        os.makedirs(path)

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'site'))
    dst_dir = path

    wayround_i2p.utils.file.copytree(
        src_dir,
        dst_dir,
        overwrite_files=True,
        clear_before_copy=False,
        dst_must_be_empty=False
        )
