
import os.path
import urllib.parse

import bottle

import org.wayround.utils.file

import org.wayround.softengine.rtenv

ttm = 'org_wayround_tasktracker_modules_TaskTracker'
session_cookie_name = 'org_wayround_tasktracker_session_cookie'
session_lifetime = 24 * 60 * 60

class PageAction:

    def __init__(self, title, href):

        self.title = title
        self.href = href

class Environment:


    def __init__(
        self, rtenv, host='localhost',
        port=8080, admin_jid='example@ex.nonexisting'
        ):

        self.admin_jid = admin_jid

        self.rtenv = rtenv

        self.host = host
        self.port = port

        self.app = bottle.Bottle()

        self.app.route('/', 'GET', self.root_view)

        self.app.route('/login', 'GET', self.login)
        self.app.route('/login', 'POST', self.login_post)
        self.app.route('/logout', 'GET', self.logout)

        self.app.route('/new_project', 'GET', self.new_project)
        self.app.route('/new_project', 'POST', self.new_project_post)
        self.app.route('/edit_project', 'GET', self.edit_project)
        self.app.route('/edit_project', 'POST', self.edit_project_post)

        self.app.route('/project/<project_name>', 'GET', self.project_view)
        self.app.route('/project/<project_name>/', 'GET', self.redirect_to_project_view)

        self.app.route('/project/<project_name>/new_issue', 'GET', self.new_issue)
        self.app.route('/project/<project_name>/new_issue', 'POST', self.new_issue_post)
        self.app.route('/project/<project_name>/edit_issue', 'GET', self.edit_issue)
        self.app.route('/project/<project_name>/edit_issue', 'POST', self.edit_issue_post)

    def get_actions(self, mode=None, project_name=None):

        lst = []

        if mode == 'index':
            lst.append(PageAction('New Project', 'new_project'))

        if mode == 'edit_project':
            lst.append(PageAction('Project List', '/'))

        if mode == 'project':
            lst.append(PageAction('Project List', '/'))
            lst.append(PageAction('New Issue', '{}/new_issue'.format(project_name)))

        if mode == 'issue':
            lst.append(PageAction('Project List', '/'))
            lst.append(PageAction('Issue List', '.'))

        return lst

    def start(self):
        bottle.run(self.app, host=self.host, port=self.port)

    def session_check(self):

        s = None

        if not session_cookie_name in bottle.request.cookies:
            s = self.rtenv.modules[ttm].new_session()
            bottle.response.set_cookie(session_cookie_name, s.session_cookie)
        else:
            s = self.rtenv.modules[ttm].get_session_by_cookie(
                bottle.request.cookies.get(session_cookie_name, None)
                )
            self.rtenv.modules[ttm].renew_session(s)

        return s

    def session_status(self, session=None):

        ret = ''

        if session == None or session.jid == None:
            ret = self.rtenv.modules[ttm].session_tpl(
                status='anonymous',
                jid='',
                session_cookie=session.session_cookie,
                session_valid_till=session.session_valid_till
                )
        else:

            ret = self.rtenv.modules[ttm].session_tpl(
                status='authenticated',
                jid=session.jid,
                session_cookie=session.session_cookie,
                session_valid_till=session.session_valid_till
                )

        return ret

    def determine_site_role(self, session=None):

        ret = None

        if session.jid == self.admin_jid:
            ret = 'admin'
        else:
            pass

        return ret

    def login(self):

        actions = self.rtenv.modules[ttm].actions_tpl(
            self.get_actions(mode='login')
            )

        ret = self.rtenv.modules[ttm].html_tpl(
            title="Login",
            actions=actions,
            body=self.rtenv.modules[ttm].login_tpl()
            )

        return ret

    def login_post(self):

        for i in ['jid']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        jid = bottle.request.params['jid']

        #        if jid == self.admin_jid:

        s = self.rtenv.modules[ttm].get_session_by_cookie(
            bottle.request.cookies.get(session_cookie_name, None)
            )

        self.rtenv.modules[ttm].assign_jid_to_session(s, jid)

        bottle.response.status = 301
        bottle.response.set_header('Location', '/')

        return

    def logout(self):
        bottle.response.delete_cookie(session_cookie_name)
        bottle.response.status = 301
        bottle.response.set_header('Location', '/')
#        bottle.redirect('/', code=200)

    def root_view(self):

        session = self.session_check()

        projects = self.rtenv.modules[ttm].get_projects()

#        print("Projects found: {}:".format(len(projects)))
#        for i in projects:
#            print("   {}".format(repr(i)))

        project_list = self.rtenv.modules[ttm].project_list_tpl(
            projects
            )

        actions = self.rtenv.modules[ttm].actions_tpl(
            self.get_actions(mode='index')
            )

        ret = self.rtenv.modules[ttm].html_tpl(
            title="Test title",
            actions=actions,
            session=self.session_status(session),
            body=project_list
            )

        return ret

    def new_project(self):

        actions = self.rtenv.modules[ttm].actions_tpl(
            self.get_actions(mode='edit_project')
            )

        edit_project_tpl = self.rtenv.modules[ttm].edit_project_tpl(
            mode='new'
            )

        ret = self.rtenv.modules[ttm].html_tpl(
            title="Create new project",
            actions=actions,
            body=edit_project_tpl
            )

        return ret

    def new_project_post(self):

        for i in ['name', 'title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']
        title = bottle.request.params['title']
        description = bottle.request.params['description']


        self.rtenv.modules[ttm].new_project(
            name, title, description
            )

        ret = self.rtenv.modules[ttm].html_tpl(
            title="Project creation result",
            actions='',
            body=''
            )

        bottle.redirect('/project/{}'.format(name))

        return ret

    def edit_project(self):

        ret = ''

        for i in ['name']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']

        p = self.rtenv.modules[ttm].get_project(name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:
            actions = self.rtenv.modules[ttm].actions_tpl(
                self.get_actions(mode='edit_project')
                )

            edit_project_tpl = self.rtenv.modules[ttm].edit_project_tpl(
                mode='edit',
                name=name,
                title=p.title,
                description=p.description
                )

            ret = self.rtenv.modules[ttm].html_tpl(
                title="Edit project",
                actions=actions,
                body=edit_project_tpl
                )

        return ret

    def edit_project_post(self):

        ret = ''

        for i in ['name', 'title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']
        title = bottle.request.params['title']
        description = bottle.request.params['description']

        p = self.rtenv.modules[ttm].get_project(name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            p.title = title
            p.description = description

            self.rtenv.db.sess.commit()

        return ret

    def redirect_to_project_view(self, project_name):
        bottle.redirect('/project/{}'.format(urllib.parse.quote(project_name)))

    def project_view(self, project_name):

        ret = ''

        p = self.rtenv.modules[ttm].get_project(project_name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.rtenv.modules[ttm].actions_tpl(
                self.get_actions(mode='project', project_name=project_name)
                )

            issues = self.rtenv.modules[ttm].get_project_issues(project_name)

            issue_list = self.rtenv.modules[ttm].issue_list_tpl(issues)

            ret = self.rtenv.modules[ttm].html_tpl(
                title="`{}' issues".format(p.title),
                actions=actions,
                body=issue_list
                )

        return ret

    def new_issue(self, project_name):

        ret = ''

        p = self.rtenv.modules[ttm].get_project(project_name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.rtenv.modules[ttm].actions_tpl(
                self.get_actions(mode='issue')
                )

            edit_issue_tpl = self.rtenv.modules[ttm].edit_issue_tpl(
                mode='new',
                project_name=p.name,
                project_title=p.title
                )

            ret = self.rtenv.modules[ttm].html_tpl(
                title="Create new issue",
                actions=actions,
                body=edit_issue_tpl
                )

        return ret

    def new_issue_post(self):

        for i in [
            'issue_id',
            'project_name',
            'project_title',
            'title',
            'priority',
            'status',
            'resolution',
            'description'
            ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']
        title = bottle.request.params['title']
        description = bottle.request.params['description']


        self.rtenv.modules[ttm].new_issue(
            name, title, description
            )

        ret = self.rtenv.modules[ttm].html_tpl(
            title="Project creation result",
            actions='',
            body=''
            )

        return ret

    def edit_issue(self):

        ret = ''

        for i in ['name']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']

        p = self.rtenv.modules[ttm].get_issue(name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:
            actions = self.rtenv.modules[ttm].actions_tpl(
                self.get_actions(mode='index')
                )

            edit_issue_tpl = self.rtenv.modules[ttm].edit_issue_tpl(
                mode='edit',
                name=name,
                title=p.title,
                description=p.description
                )

            ret = self.rtenv.modules[ttm].html_tpl(
                title="Edit issue",
                actions=actions,
                body=edit_issue_tpl
                )

        return ret

    def edit_issue_post(self):

        ret = ''

        for i in ['name', 'title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        name = bottle.request.params['name']
        title = bottle.request.params['title']
        description = bottle.request.params['description']

        p = self.rtenv.modules[ttm].get_issue(name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            p.title = title
            p.description = description

            self.rtenv.db.sess.commit()

        return ret



def install_launcher(path):

    if not os.path.exists(path):
        os.makedirs(path)

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'site'))
    dst_dir = path

    org.wayround.utils.file.copytree(
        src_dir,
        dst_dir,
        overwrite_files=True,
        clear_before_copy=False,
        dst_must_be_empty=False
        )
