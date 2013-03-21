#!python3.3

import os.path
import org.wayround.tasktracker.starter

wd = os.path.abspath(os.path.dirname(__file__))

exit(
    org.wayround.tasktracker.starter.main(
        db_config='sqlite:///{}/db/database.sqlite'.format(wd),
        db_echo=False
        )
     )
