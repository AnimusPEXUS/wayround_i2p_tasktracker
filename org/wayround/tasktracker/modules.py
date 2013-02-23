
import sqlalchemy

import org.wayround.softengine.rtenv

class TaskTracker(org.wayround.softengine.rtenv.ModulePrototype):

    def __init__(self, rtenv):

        self.module_name = 'org.wayround.tasktracker.modules.TaskTracker'

        self.rtenv = rtenv

        self.rtenv.modules[self.module_name] = self

        class Project(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '.Project'

            project_id = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            project_title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Name not set'
                )

        class Roles(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '.Roles'

            uid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )


        self.rtenv.models[self.module_name] = {
            'Project': Project,
            'Roles': Roles
            }


