
import datetime
import hashlib
import os.path
import random

import bottle
from mako.template import Template
import sqlalchemy
import sqlalchemy.orm.exc

import org.wayround.softengine.rtenv
import org.wayround.tasktracker.env


class WrongPageAction(Exception):
    pass


class CreatingAlreadyExistingProject(Exception):
    pass


class EditingNotExistingProject(Exception):
    pass


class TaskTracker(org.wayround.softengine.rtenv.ModulePrototype):

    def __init__(self, rtenv):

        self.module_name = 'org_wayround_tasktracker_modules_TaskTracker'

        self.session_lifetime = 24 * 60 * 60

        self.site_roles = [
            'admin', 'moder', 'user', 'guest'
            ]

        self.project_roles = [
            'admin', 'moder', 'user', 'guest'
            ]

        self.priorities = list('123456789')

        self.statuses = ['open', 'closed', 'deleted']

        self.resolutions = [
            'None',
            'Assist Required',
            'Resolved',
            'Wrong',
            'Wont Fix',
            'Duplicated',
            'Duplicates',
            'Paused'
            ]

        self.relation_types = [
            'relates',
            'duplicates',
            'duplicated',
            'blocks',
            'blocked',
            'precedes',
            'follows'
            ]

        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.css_dir = os.path.join(os.path.dirname(__file__), 'css')
        self.js_dir = os.path.join(os.path.dirname(__file__), 'js')

        self.rtenv = rtenv

        self.rtenv.modules[self.module_name] = self

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

            guests_access_allowed = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
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

        class IssueUpdate(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_IssueUpdates'

            update_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            project_name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            issue_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                nullable=False,
                default=0
                )

            author_jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            title_old = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Title not set'
                )

            title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Title not set'
                )

            priority_old = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            priority = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            status_old = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            status = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            resolution_old = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            resolution = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            description_diff = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            assigned_to_diff = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            watchers_diff = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            comment = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

            date = sqlalchemy.Column(
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
                nullable=False,
                default='user'
                )

        class ProjectRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_ProjectRoles'

            prid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
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

            irid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
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

        class SiteSetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_SiteSettings'

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            value = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

        class IssueRelation(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_IssueRelations'

            irid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            issue_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                nullable=False,
                default=0
                )

            target_issue_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                nullable=False,
                default=0
                )

            typ = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='relates'
                )

        self.rtenv.models[self.module_name] = {
            'Issue':         Issue,
            'Project':       Project,
            'SiteRole':      SiteRole,
            'IssueRole':     IssueRole,
            'ProjectRole':   ProjectRole,
            'Session':       Session,
            'IssueUpdate':   IssueUpdate,
            'SiteSetting':   SiteSetting,
            'IssueRelation': IssueRelation
            }

        self.rtenv.templates[self.module_name] = {}

        for i in [
            'html',
            'admin',
            'project_page',
            'project_list',
            'project_roles',
            'issue_teaser',
            'issue_teaser_table',
            'edit_issue',
            'edit_project',
            'actions',
            'session',
            'issue_teaser',
            'selector_priority',
            'selector_status',
            'selector_resolution',
            'issue_update_row',
            'issue_update_table',
            'site_settings',
            'site_roles',
            'project_activity_pager',
            'project_activity_table',
            'project_activity_row',
            'project_issues_pager',
            'project_issues_page',
            ]:
            self.rtenv.templates[self.module_name][i] = Template(
                filename=os.path.join(self.template_dir, '{}.html'.format(i)),
                format_exceptions=False
                )

    def html_tpl(self, title, actions, body, session=''):
        return self.rtenv.templates[self.module_name]['html'].render(
            title=title, session=session, actions=actions, body=body, js=[], css=['default.css']
            )

    def project_issues_page_tpl(
        self,
        issue_records,
        status,
        page,
        count
        ):

        pager = self.project_issues_pager_tpl(
            page, count, status
            )

        teaser_table = self.issue_teaser_table_tpl(issue_records)

        return self.rtenv.templates[self.module_name]['project_issues_page'].render(
            pager=pager,
            teaser_table=teaser_table
            )

    def project_issues_pager_tpl(
        self,
        page=0,
        count=100,
        status='open'
        ):

        if not isinstance(page, int):
            raise TypeError("`page' must be int")

        if not isinstance(count, int):
            raise TypeError("`count' must be int")

        status_selector = self.issue_status_selector_tpl(status)

        return self.rtenv.templates[self.module_name]['project_issues_pager'].render(
            page=page,
            count=count,
            status_selector=status_selector
            )

    def project_activity_pager_tpl(
        self,
        page=0,
        count=100
        ):

        if not isinstance(page, int):
            raise TypeError("`page' must be int")

        if not isinstance(count, int):
            raise TypeError("`count' must be int")

        return self.rtenv.templates[self.module_name]['project_activity_pager'].render(
            page=page,
            count=count
            )

    def project_activity_table_tpl(
        self, activities, page, count
        ):

        rows = []

        pager = self.project_activity_pager_tpl(page, count)

        for i in activities:

            issue = self.get_issue(i.issue_id)

            rows.append(
                self.project_activity_row_tpl(
                    project_name=i.project_name,
                    issue_id=i.issue_id,
                    issue_title=issue.title,
                    title_old=i.title_old,
                    title=i.title,
                    priority_old=i.priority_old,
                    priority=i.priority,
                    status_old=i.status_old,
                    status=i.status,
                    resolution_old=i.resolution_old,
                    resolution=i.resolution,
                    description_diff=i.description_diff,
                    assigned_to_diff=i.assigned_to_diff,
                    watchers_diff=i.watchers_diff,
                    comment=i.comment,
                    date=i.date,
                    author_jid=i.author_jid
                    )
                )

        return self.rtenv.templates[self.module_name]['project_activity_table'].render(
            rows=rows,
            pager=pager
            )

    def project_activity_row_tpl(
            self,
            project_name='',
            issue_id='',
            issue_title='',
            title_old='',
            title='',
            priority_old='',
            priority='',
            status_old='',
            status='',
            resolution_old='',
            resolution='',
            description_diff='',
            assigned_to_diff='',
            watchers_diff='',
            comment='',
            date='',
            author_jid=''
            ):

        return self.rtenv.templates[self.module_name]['project_activity_row'].render(
            project_name=project_name,
            issue_id=issue_id,
            issue_title=issue_title,
            title_old=title_old,
            title=title,
            priority_old=priority_old,
            priority=priority,
            status_old=status_old,
            status=status,
            resolution_old=resolution_old,
            resolution=resolution,
            description_diff=description_diff,
            assigned_to_diff=assigned_to_diff,
            watchers_diff=watchers_diff,
            comment=comment,
            date=date,
            jid=author_jid
            )

    def site_roles_tpl(
        self,
        admins,
        moders,
        users,
        blocked
        ):
        return self.rtenv.templates[self.module_name]['site_roles'].render(
            admins=admins,
            moders=moders,
            users=users,
            blocked=blocked
            )

    def project_roles_tpl(
        self,
        admins,
        moders,
        users,
        blocked,
        site_admins,
        site_moders,
        site_users,
        site_blocked,
        god
        ):
        return self.rtenv.templates[self.module_name]['project_roles'].render(
            admins=admins,
            moders=moders,
            users=users,
            blocked=blocked,
            site_admins=site_admins,
            site_moders=site_moders,
            site_users=site_users,
            site_blocked=site_blocked,
            god=god
            )

    def site_settings_tpl(
        self,
        site_title,
        site_description,
        user_can_register_self,
        user_can_create_projects
        ):
        return self.rtenv.templates[self.module_name]['site_settings'].render(
            site_title=site_title,
            site_description=site_description,
            user_can_register_self=user_can_register_self,
            user_can_create_projects=user_can_create_projects
            )

    def register_tpl(self):
        return self.rtenv.templates[self.module_name]['register'].render()

    def issue_teaser_tpl(
        self,
        project_name='',
        ide='',
        caption='',
        resolution='',
        updated='',
        assigned='',
        priority=''
        ):

        return self.rtenv.templates[self.module_name]['issue_teaser'].render(
            project_name=project_name, ide=ide, caption=caption,
            resolution=resolution, updated=updated, assigned=assigned,
            priority=priority
            )

    def issue_teaser_table_tpl(self, issue_records):

        teasers = []

        for i in issue_records:

            updated = ''

            if i.updation_date:
                updated = str(i.updation_date)
            else:
                updated = str(i.creation_date)

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
                    updated=updated,
                    assigned=assigned,
                    priority=str(i.priority)
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
        project_name,
        open_issue_table='',
        closed_issue_table='',
        deleted_issue_table=''
        ):
        return self.rtenv.templates[self.module_name]['project_page'].render(
            project_name=project_name,
            open_issue_table=open_issue_table,
            closed_issue_table=closed_issue_table,
            deleted_issue_table=deleted_issue_table
            )

    def project_list_tpl(self, projects, rts_object):
        return self.rtenv.templates[self.module_name]['project_list'].render(
            projects=projects,
            rts_object=rts_object
            )

    def issue_list_tpl(self, issues):
        return self.rtenv.templates[self.module_name]['issue_list'].render(
            issues=issues
            )

    def actions_tpl(self, actions, session_actions):

        for i in actions:
            if not isinstance(i, org.wayround.tasktracker.env.PageAction):
                raise WrongPageAction("Wrong page action type")

        return self.rtenv.templates[self.module_name]['actions'].render(
            actions=actions,
            session_actions=session_actions
            )

    def session_tpl(
        self,
        rts_object=None
        ):

        if not  isinstance(rts_object, org.wayround.tasktracker.env.Session):
            raise ValueError(
                "rts_object must be of type org.wayround.tasktracker.env.Session"
                )

        return self.rtenv.templates[self.module_name]['session'].render(
            rts_object=rts_object
            )

    def edit_project_tpl(
        self,
        mode,
        name='',
        title='',
        description='',
        guests_access_allowed=False
        ):

        if not mode in ['new', 'edit']:
            raise ValueError("Wrong mode value: `{}'".format(mode))

        return self.rtenv.templates[self.module_name]['edit_project'].render(
            mode=mode,
            name=name,
            title=title,
            description=description,
            guests_access_allowed=guests_access_allowed
            )

    def issue_priority_selector_tpl(self, select):

        if not select in self.priorities:
            raise ValueError("Wrong priority `select' value")

        return self.rtenv.templates[self.module_name]['selector_priority'].render(
            selected=select,
            options=self.priorities
            )

    def issue_status_selector_tpl(self, selected):

        if not selected in self.statuses:
            raise ValueError("Wrong status `selected' value")

        return self.rtenv.templates[self.module_name]['selector_status'].render(
            selected=selected,
            options=self.statuses
            )

    def issue_resolution_selector_tpl(self, selected):

        if not selected in self.resolutions:
            raise ValueError("Wrong resolution `selected' value")

        return self.rtenv.templates[self.module_name]['selector_resolution'].render(
            selected=selected,
            options=self.resolutions
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
            comment='',
            relations=None
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
            comment=comment,
            relations=relations,
            relation_types=self.relation_types,
            get_issue=self.get_issue
            )

    def issue_update_row_tpl(
            self,
            title_old='',
            title='',
            priority_old='',
            priority='',
            status_old='',
            status='',
            resolution_old='',
            resolution='',
            description_diff='',
            assigned_to_diff='',
            watchers_diff='',
            comment='',
            date='',
            author_jid=''
            ):

        return self.rtenv.templates[self.module_name]['issue_update_row'].render(
            title_old=title_old,
            title=title,
            priority_old=priority_old,
            priority=priority,
            status_old=status_old,
            status=status,
            resolution_old=resolution_old,
            resolution=resolution,
            description_diff=description_diff,
            assigned_to_diff=assigned_to_diff,
            watchers_diff=watchers_diff,
            comment=comment,
            date=date,
            jid=author_jid
            )

    def issue_update_table_tpl(self, issue_updates):

        rows = []

        for i in issue_updates:
            rows.append(
                self.issue_update_row_tpl(
                    title_old=i.title_old,
                    title=i.title,
                    priority_old=i.priority_old,
                    priority=i.priority,
                    status_old=i.status_old,
                    status=i.status,
                    resolution_old=i.resolution_old,
                    resolution=i.resolution,
                    description_diff=i.description_diff,
                    assigned_to_diff=i.assigned_to_diff,
                    watchers_diff=i.watchers_diff,
                    comment=i.comment,
                    date=i.date,
                    author_jid=i.author_jid
                    )
                )

        return self.rtenv.templates[self.module_name]['issue_update_table'].render(
            rows=rows
            )

    def css(self, filename):
        return bottle.static_file(filename, root=self.css_dir)

    def js(self, filename):
        return bottle.static_file(filename, root=self.js_dir)

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

    def _get_session_by_x(self, data, what):

        if not what in ['jid', 'cookie']:
            raise ValueError("Wrong `what' parameter")

        self.cleanup_sessions()

        ret = None

        try:
            if what == 'cookie':
                ret = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(session_cookie=data).one()

            if what == 'jid':
                ret = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(jid=data).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            if ret.session_cookie == None or ret.session_valid_till == None:
                ret = None

        return ret

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
            datetime.timedelta(seconds=self.session_lifetime)
            )

        self.rtenv.db.sess.commit()

        return

    def assign_jid_to_session(self, session, jid):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        for i in sessions:
            if i.jid == jid:
                self.rtenv.db.sess.delete(i)

        session.jid = jid

        self.rtenv.db.sess.commit()

        return

    def cleanup_sessions(self):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        for i in sessions[:]:
            if i.session_cookie == None or i.session_valid_till == None:
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
                    seconds=self.session_lifetime
                    )
                ):

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

    def get_project_issues_count(self, name, status):

        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Issue']
            ).filter_by(
                project_name=name,
                status=status
                ).count()

    def get_project_issues(self, name, status, start, stop):

        i = None

        try:
            self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            i = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Issue']
                ).filter_by(
                    project_name=name,
                    status=status
                    ).order_by(
                        self.rtenv.models[self.module_name]['Issue'].priority.asc(),
                        self.rtenv.models[self.module_name]['Issue'].updation_date.desc()
                        ).slice(start, stop).all()

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

    def new_project(self, name, title, description, guests_access_allowed):

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
            p.guests_access_allowed = guests_access_allowed
            self.rtenv.db.sess.add(p)

        else:
            raise CreatingAlreadyExistingProject(
                "Trying to create already existing project"
                )

        self.rtenv.db.sess.commit()

        return p

    def edit_project(self, name, title, description, guests_access_allowed):

        p = None
        try:
            p = self.get_project(name)

        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            raise EditingNotExistingProject(
                "Trying to edit non-existing project"
                )

        else:
            p.title = title
            p.description = description
            p.guests_access_allowed = guests_access_allowed

        self.rtenv.db.sess.commit()

        return p

    def new_issue(
        self,
        project_name,
        title,
        priority,
        status,
        resolution,
        description,
        creation_date
        ):

        try:
            self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=project_name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            raise bottle.HTTPError(400, "Corresponding project not found")

        issue = self.rtenv.models[self.module_name]['Issue']()
        issue.project_name = project_name
        issue.title = title
        issue.priority = priority
        issue.status = status
        issue.resolution = resolution
        issue.description = description
        issue.creation_date = creation_date
        issue.updation_date = creation_date

        self.rtenv.db.sess.add(issue)

        self.rtenv.db.sess.commit()

        return issue

    def edit_issue(
        self,
        issue_id,
        title,
        priority,
        status,
        resolution,
        description,
        updation_date
        ):

        issue = None
        try:
            issue = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Issue']
                ).filter_by(issue_id=issue_id).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not issue:
            raise EditingNotExistingProject(
                "Trying to edit not existing issue"
                )

        else:
            issue.title = title
            issue.priority = priority
            issue.status = status
            issue.resolution = resolution
            issue.description = description
            issue.updation_date = updation_date

        self.rtenv.db.sess.commit()

        return

    def issue_get_roles(self, issue_id):

        roles = {}

        for i in ['worker', 'watcher']:

            t = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['IssueRole']
                ).filter_by(issue_id=issue_id, role=i).all()

            roles[i] = []

            for j in t:
                roles[i].append(j.jid)

            roles[i].sort()

        return roles

    def issue_get_title(self, issue_id):

        i = self.get_issue(issue_id)

        ret = '{{SOME ERROR}}'

        if i:
            ret = i.title

        return ret

    def issue_set_roles(self, issue_id, roles):

        """
        `roles' must be a dict of lists
        """

        for i in ['worker', 'watcher']:

            if i in roles:

                roles[i].sort()

                t = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['IssueRole']
                    ).filter_by(issue_id=issue_id, role=i).all()

                for j in t:
                    if j.jid not in roles[i]:
                        self.rtenv.db.sess.delete(j)

                for j in roles[i]:
                    h_found = False

                    for k in t:
                        if k.jid == j:
                            h_found = True
                            break

                    if not h_found:
                        new_role = self.rtenv.models[self.module_name]['IssueRole']()
                        new_role.jid = j
                        new_role.role = i
                        new_role.issue_id = issue_id
                        self.rtenv.db.sess.add(new_role)

        self.rtenv.db.sess.commit()

        return

    def make_issue_update(
        self,
        project_name,
        issue_id,
        author_jid,
        title_old,
        title,
        priority_old,
        priority,
        status_old,
        status,
        resolution_old,
        resolution,
        description_diff,
        assigned_to_diff,
        watchers_diff,
        comment,
        date
        ):

        issueup = self.rtenv.models[self.module_name]['IssueUpdate']()

        issueup.project_name = project_name
        issueup.issue_id = issue_id
        issueup.author_jid = author_jid
        issueup.title_old = title_old
        issueup.title = title
        issueup.priority_old = priority_old
        issueup.priority = priority
        issueup.status_old = status_old
        issueup.status = status
        issueup.resolution_old = resolution_old
        issueup.resolution = resolution
        issueup.description_diff = description_diff
        issueup.assigned_to_diff = assigned_to_diff
        issueup.watchers_diff = watchers_diff
        issueup.comment = comment
        issueup.date = date

        self.rtenv.db.sess.add(issueup)
        self.rtenv.db.sess.commit()

        return issueup

    def get_issue_updates(self, issue_id):

        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueUpdate']
            ).filter_by(issue_id=issue_id).all()

    def get_project_updates_count(self, project_name):

        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueUpdate']
            ).filter_by(
                project_name=project_name
                ).count()

    def get_project_updates(self, project_name, start=0, stop=100):

        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueUpdate']
            ).filter_by(
                project_name=project_name
                ).order_by(
                    self.rtenv.models[self.module_name]['IssueUpdate'].date.desc()
                    ).slice(start, stop).all()

    def get_site_role(self, jid):

        ret = None

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteRole']
                ).filter_by(jid=jid).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res

            if not ret.role in self.site_roles:

                self.rtenv.db.sess.delete(ret)

                ret = None

                self.rtenv.db.sess.commit()

        return ret

    def get_site_roles(self):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['SiteRole']
            ).all()

        for i in ret[:]:
            if not i.role in self.site_roles:

                self.rtenv.db.sess.delete(i)

                while i in ret:
                    ret.remove(i)

        self.rtenv.db.sess.commit()

        return ret

    def get_site_roles_dict(self):

        ret = {}

        res = self.get_site_roles()

        for i in res:
            ret[i.jid] = i.role

        return ret

    def set_site_roles(self, roles):

        old_roles = self.get_site_roles()

        for i in old_roles:
            if not i.jid in roles.keys():
                self.rtenv.db.sess.delete(i)

        for i in roles.keys():

            role_found = False

            for j in old_roles:

                if j.jid == i:
                    role_found = j
                    break

            if role_found == False:

                role = self.rtenv.models[self.module_name]['SiteRole']()

                role.jid = i
                role.role = roles[i]

                self.rtenv.db.sess.add(role)

            else:

                role = role_found

                role.role = roles[i]

        self.rtenv.db.sess.commit()

        return

    def add_site_role(self, jid, role='user'):

        siterole = self.rtenv.models[self.module_name]['SiteRole']()

        siterole.jid = jid
        siterole.role = role

        self.rtenv.db.sess.add(siterole)

        self.rtenv.db.sess.commit()

        return

    def get_project_role(self, jid, project_name):

        ret = None

        try:
            ret = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['ProjectRole']
                ).filter_by(jid=jid, project_name=project_name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return ret

    def get_project_roles_of_jid(self, jid):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['ProjectRole']
            ).filter_by(jid=jid).all()

        return ret

    def get_project_roles_of_jid_dict(self, jid):

        roles = self.get_project_roles_of_jid(jid)

        ret = {}

        for i in roles:
            ret[i.project_name] = i.role

        return ret

    def get_project_roles(self, project_name):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['ProjectRole']
            ).filter_by(project_name=project_name).all()

        for i in ret[:]:
            if not i.role in self.project_roles:

                self.rtenv.db.sess.delete(i)

                while i in ret:
                    ret.remove(i)

        self.rtenv.db.sess.commit()

        return ret

    def get_project_roles_dict(self, project_name):

        roles = self.get_project_roles(project_name)

        ret = {}

        for i in roles:
            ret[i.jid] = i.role

        return ret

    def set_project_roles(self, project_name, roles):

        old_roles = self.get_project_roles(project_name)

        for i in old_roles:
            if not i.jid in roles.keys():
                self.rtenv.db.sess.delete(i)

        for i in roles.keys():

            role_found = False

            for j in old_roles:

                if j.jid == i:
                    role_found = j
                    break

            if role_found == False:

                role = self.rtenv.models[self.module_name]['ProjectRole']()

                role.jid = i
                role.role = roles[i]
                role.project_name = project_name

                self.rtenv.db.sess.add(role)

            else:

                role = role_found

                role.role = roles[i]

        self.rtenv.db.sess.commit()

        return

    def get_site_setting(self, name, default=None):

        ret = default

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteSetting']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res.value

        return ret

    def set_site_setting(self, name, value):

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteSetting']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if res == None:
            res = self.rtenv.models[self.module_name]['SiteSetting']()
            res.name = name
            res.value = value

            self.rtenv.db.sess.add(res)
        else:
            res.value = value

        self.rtenv.db.sess.commit()

        return

    def relation_spec_converter_to_db(self, issue_relation_record):

        ret = None

        if issue_relation_record.typ in ['duplicates', 'blocks', 'follows']:

            ret = self.rtenv.models[self.module_name]['IssueRelation']()

            ret.issue_id = issue_relation_record.target_issue_id
            ret.target_issue_id = issue_relation_record.issue_id

            if issue_relation_record.typ == 'duplicates':
                ret.typ = 'duplicated'

            if issue_relation_record.typ == 'blocks':
                ret.typ = 'blocked'

            if issue_relation_record.typ == 'follows':
                ret.typ = 'precedes'
        else:
            ret = issue_relation_record

        return ret

    def relation_spec_converter_from_db(self, issue_relation_record):

        ret = None

        if issue_relation_record.typ in [
            'duplicated', 'blocked', 'precedes', 'relates'
            ]:

            ret = self.rtenv.models[self.module_name]['IssueRelation']()

            ret.issue_id = issue_relation_record.target_issue_id
            ret.target_issue_id = issue_relation_record.issue_id

            if issue_relation_record.typ == 'duplicated':
                ret.typ = 'duplicates'

            if issue_relation_record.typ == 'blocked':
                ret.typ = 'blocks'

            if issue_relation_record.typ == 'precedes':
                ret.typ = 'follows'

            if issue_relation_record.typ == 'relates':
                ret.typ = 'relates'

        else:
            ret = issue_relation_record

        return ret

    def issue_get_relations(self, issue_id):

        by_ii = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueRelation']
            ).filter_by(issue_id=issue_id).all()

        by_tii = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueRelation']
            ).filter_by(target_issue_id=issue_id).all()

        by_tii2 = []
        for i in by_tii:
            by_tii2.append(self.relation_spec_converter_from_db(i))

        s = set(by_ii) | set(by_tii2)

        return s

    def issue_add_relation(self, issue_id, target_issue_id, typ):

        ret = None

        ir = self.rtenv.models[self.module_name]['IssueRelation']()
        ir.issue_id = issue_id
        ir.target_issue_id = target_issue_id
        ir.typ = typ

        ir = self.relation_spec_converter_to_db(ir)

        res = None
        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['IssueRelation']
                ).filter_by(
                    issue_id=issue_id, target_issue_id=target_issue_id, typ=typ
                    ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if res == None:
            self.rtenv.db.sess.add(ir)
            self.rtenv.db.sess.commit()

            ret = ir

        else:
            ret = res

        return ret

    def issue_del_relation_by_irid(self, irid):

        self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueRelation']
            ).filter_by(
                irid=irid
                ).delete()

        self.rtenv.db.sess.commit()

        return

    def issue_del_relations(self, issue_id):

        self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueRelation']
            ).filter_by(issue_id=issue_id).delete()

        self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['IssueRelation']
            ).filter_by(target_issue_id=issue_id).delete()

        self.rtenv.db.sess.commit()

        return
