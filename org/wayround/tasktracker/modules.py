
import os.path
import random
import hashlib
import datetime

import bottle

import sqlalchemy
import sqlalchemy.orm.exc

from mako.template import Template

import org.wayround.softengine.rtenv
import org.wayround.tasktracker.env

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

class WrongPageAction(Exception): pass
class CreatingAlreadyExistingProject(Exception): pass
class EditingNotExistingProject(Exception): pass

class TaskTracker(org.wayround.softengine.rtenv.ModulePrototype):

    def __init__(self, rtenv):

        self.module_name = 'org_wayround_tasktracker_modules_TaskTracker'

        self.rtenv = rtenv

        self.rtenv.modules[self.module_name] = self

        class User(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Users'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            registered = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
                )

            blocked = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=True
                )

        class Session(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Sessions'

            sid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            session_cookie = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            session_valid_till = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

        class Project(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Projects'

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Name not set'
                )

            creation_date = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

            description = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Name not set'
                )

        class Issue(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Issues'

            issue_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            project_name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Title not set'
                )

            priority = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            status = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            resolution = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            description = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            creation_date = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

            updation_date = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

        class SiteRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_SiteRoles'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True,
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )


        class ProjectRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_ProjectRoles'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True,
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            project_name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

        class IssueRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_IssueRoles'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True,
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            issue_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                nullable=False,
                default=0
                )

        self.rtenv.models[self.module_name] = {
            'User': User,
            'Issue': Issue,
            'IssueRole': IssueRole,
            'Project': Project,
            'ProjectRole': ProjectRole,
            'Session': Session,
            }

        self.rtenv.templates[self.module_name] = {}

        for i in [
            'html',
            'register',
            'login',
            'admin',
            'project_page',
            'project_list',
            'issue_teaser',
            'issue_teaser_table',
            'edit_issue',
            'edit_project',
            'issue_comments',
            'actions',
            'session',
            'issue_teaser',
            'selector_priority',
            'selector_status',
            'selector_resolution'
            ]:
            self.rtenv.templates[self.module_name][i] = Template(
                filename=os.path.join(template_dir, '{}.html'.format(i)),
                format_exceptions=True
                )

    def html_tpl(self, title, actions, body, session=''):
        return self.rtenv.templates[self.module_name]['html'].render(
            title=title, session=session, actions=actions, body=body
            )

    def register_tpl(self):
        return self.rtenv.templates[self.module_name]['register'].render()

    def issue_teaser_tpl(self, project_name='', ide='', caption='', resolution='', assigned=''):
        return self.rtenv.templates[self.module_name]['issue_teaser'].render(
            project_name=project_name, ide=ide, caption=caption,
            resolution=resolution, assigned=assigned
            )

    def issue_teaser_table_tpl(self, issue_records):

        teasers = []

        for i in issue_records:

            assigned = ''

            issue_roles = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['IssueRole']
                ).filter_by(issue_id=i.issue_id).all()

            if len(issue_roles) == 0:
                assigned = 'No one'
            elif len(issue_roles) == 1:
                assigned = issue_roles[0].jid
            else:
                assigned = "{} people".format(len(issue_roles))

            teasers.append(
                self.issue_teaser_tpl(
                    project_name=i.project_name,
                    ide=i.issue_id,
                    caption=i.title,
                    resolution=i.resolution,
                    assigned=assigned
                    )
                )

        ret = self.rtenv.templates[self.module_name]['issue_teaser_table'].render(
            teasers=teasers
            )

        return ret

    def login_tpl(self):
        return self.rtenv.templates[self.module_name]['login'].render()

    def project_page_tpl(
        self,
        open_issue_table='',
        closed_issue_table='',
        deleted_issue_table=''
        ):
        return self.rtenv.templates[self.module_name]['project_page'].render(
            open_issue_table=open_issue_table,
            closed_issue_table=closed_issue_table,
            deleted_issue_table=deleted_issue_table
            )

    def project_list_tpl(self, projects):
        return self.rtenv.templates[self.module_name]['project_list'].render(
            projects=projects
            )

    def issue_list_tpl(self, issues):
        return self.rtenv.templates[self.module_name]['issue_list'].render(
            issues=issues
            )

    def actions_tpl(self, actions):

        for i in actions:
            if not isinstance(i, org.wayround.tasktracker.env.PageAction):
                raise WrongPageAction("Wrong page action type")

        return self.rtenv.templates[self.module_name]['actions'].render(
            actions=actions
            )

    def session_tpl(
        self, status='', jid='', session_cookie='', session_valid_till=''
        ):

        if not status in ['authenticated', 'anonymous']:
            raise ValueError("Wrong session `status' parameter value")

        return self.rtenv.templates[self.module_name]['session'].render(
            status=status,
            jid=jid,
            session_cookie=session_cookie,
            session_valid_till=session_valid_till
            )

    def edit_project_tpl(self, mode, name='', title='', description=''):

        if not mode in ['new', 'edit']:
            raise ValueError("Wrong mode value: `{}'".format(mode))

        return self.rtenv.templates[self.module_name]['edit_project'].render(
            mode=mode, name=name, title=title, description=description
            )

    def issue_priority_selector_tpl(self, select):

        if not select in org.wayround.tasktracker.env.PRIORITIES:
            raise ValueError("Wrong priority `select' value")

        return self.rtenv.templates[self.module_name]['selector_priority'].render(
            selected=select,
            options=org.wayround.tasktracker.env.PRIORITIES
            )

    def issue_status_selector_tpl(self, selected):

        if not selected in org.wayround.tasktracker.env.STATUSES:
            raise ValueError("Wrong status `selected' value")

        return self.rtenv.templates[self.module_name]['selector_status'].render(
            selected=selected,
            options=org.wayround.tasktracker.env.STATUSES
            )

    def issue_resolution_selector_tpl(self, selected):

        if not selected in org.wayround.tasktracker.env.RESOLUTIONS:
            raise ValueError("Wrong resolution `selected' value")

        return self.rtenv.templates[self.module_name]['selector_resolution'].render(
            selected=selected,
            options=org.wayround.tasktracker.env.RESOLUTIONS
            )

    def edit_issue_tpl(
            self,
            mode='new',
            issue_id=0,
            project_name='',
            project_title='',
            title='',
            priority='5',
            status='open',
            resolution='None',
            description='',
            assigned_to='',
            watchers='',
            created_date='',
            updated_date='',
            comments='',
            comment=''
            ):

        if not mode in ['new', 'view']:
            raise ValueError("Wrong mode value: `{}'".format(mode))

        return self.rtenv.templates[self.module_name]['edit_issue'].render(
            mode=mode,
            issue_id=issue_id,
            project_name=project_name,
            project_title=project_title,
            title=title,
            priority_selector=self.issue_priority_selector_tpl(priority),
            status_selector=self.issue_status_selector_tpl(status),
            resolution_selector=self.issue_resolution_selector_tpl(resolution),
            description=description,
            assigned_to=assigned_to,
            watchers=watchers,
            priority=priority,
            status=status,
            resolution=resolution,
            created_date=created_date,
            updated_date=updated_date,
            comments=comments,
            comment=comment
            )

    def get_random_bytes(self):

        ret = []
        pool = range(256)

        random.seed()

        i = 0
        while i != 512:
            ret.append(random.choice(pool))
            i += 1

        return bytes(ret)

    def hash_for_get_random_bytes(self, buffer):
        h = hashlib.sha512()
        h.update(buffer)
        ret = h.hexdigest()
        return ret

    def get_random_hash(self):
        return self.hash_for_get_random_bytes(self.get_random_bytes())

    def _get_session_by_x(self, data, what='jid'):

        if not what in ['jid', 'cookie']:
            raise ValueError("Wrong `what' parameter")

        self.cleanup_sessions()

        s = None

        try:
            if what == 'cookie':
                s = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(session_cookie=data).one()

            if what == 'jid':
                s = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(jid=data).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            if s.session_cookie == None or s.session_valid_till == None:
                s = None

        return s


    def get_session_by_cookie(self, cookie):
        return self._get_session_by_x(cookie, 'cookie')

    def get_session_by_jid(self, jid):
        return self._get_session_by_x(jid, 'jid')

    def new_session(self):

        new_hash = self.get_random_hash()

        while self.get_session_by_cookie(new_hash) != None:
            new_hash = self.get_random_hash()

        s = self.rtenv.models[self.module_name]['Session']()
        s.session_cookie = new_hash

        self.rtenv.db.sess.add(s)
        self.rtenv.db.sess.commit()
        self.renew_session(s)

        return s

    def renew_session(self, session):
        """
        Keeps alive already existing session
        """

        if not isinstance(
            session, self.rtenv.models[self.module_name]['Session']
            ):
            raise TypeError(
                "`session' parameter must be of type `{}', but it is `{}'".format(
                    type(
                        self.rtenv.models[self.module_name]['Session']
                        ),
                    session
                    )
                )

        session.session_valid_till = (
            datetime.datetime.now() +
            datetime.timedelta(seconds=org.wayround.tasktracker.env.session_lifetime)
            )

        self.rtenv.db.sess.commit()

        return

    def assign_jid_to_session(self, session, jid):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        if session in sessions:
            sessions.remove(session)

        for i in sessions:
            self.rtenv.db.sess.delete(i)

        session.jid = jid

        self.rtenv.db.sess.commit()

        return

    def cleanup_sessions(self):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        for i in sessions[:]:
            if i.session_valid_till == None:
                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        for i in sessions[:]:
            if i.session_valid_till < datetime.datetime.now():
                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        for i in sessions[:]:
            if i.session_valid_till > (
                datetime.datetime.now() +
                datetime.timedelta(
                    seconds=org.wayround.tasktracker.env.session_lifetime
                    )
                ):

                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        for i in sessions[:]:
            if i.session_cookie == None or i.session_valid_till == None:
                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        self.rtenv.db.sess.commit()

        return

    def get_projects(self):
        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Project']
            ).all()

    def get_project(self, name):
        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return p

    def get_project_issues(self, name):

        i = None

        try:
            self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            try:
                i = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Issue']
                    ).filter_by(project_name=name).all()
            except:
                pass

        return i

    def get_issue(self, issue_id):
        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Issue']
                ).filter_by(issue_id=issue_id).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return p

    def new_project(self, name, title, description):

        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            p = self.rtenv.models[self.module_name]['Project']()
            p.name = name
            p.title = title
            p.description = description
            self.rtenv.db.sess.add(p)

        else:
            raise CreatingAlreadyExistingProject(
                "Trying to create already existing project"
                )

        self.rtenv.db.sess.commit()

        return p

    def edit_project(self, name, title, description):

        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            raise EditingNotExistingProject(
                "Trying to edit non-existing project"
                )

        else:
            p.title = title
            p.description = description

        self.rtenv.db.sess.commit()

        return p

    def new_issue(
        self,
        project_name,
        title,
        priority,
        status,
        resolution,
        description
        ):

        try:
            self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=project_name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise bottle.HTTPError(400, "Corresponding project not found")

        date = datetime.datetime.now()

        issue = self.rtenv.models[self.module_name]['Issue']()
        issue.project_name = project_name
        issue.title = title
        issue.priority = priority
        issue.status = status
        issue.resolution = resolution
        issue.description = description
        issue.creation_date = date
        issue.updation_date = None

        self.rtenv.db.sess.add(issue)

        self.rtenv.db.sess.commit()

        return issue

    def edit_issue(self, name, title, description):

        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            raise EditingNotExistingProject(
                "Trying to edit not existing issue"
                )

        else:
            p.title = title
            p.description = description

        self.rtenv.db.sess.commit()

        return

