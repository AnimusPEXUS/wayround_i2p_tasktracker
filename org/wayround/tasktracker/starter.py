
import getopt
import logging
import os.path
import sys

import org.wayround.softengine.modules

import org.wayround.tasktracker.modules
import org.wayround.tasktracker.env


def main(db_config, db_echo):

    for i in [
        (logging.CRITICAL, '-c-'),
        (logging.ERROR   , '-e-'),
        (logging.WARN    , '-w-'),
        (logging.WARNING , '-w-'),
        (logging.INFO    , '-i-'),
        (logging.DEBUG   , '-d-')
        ]:
        logging.addLevelName(i[0], i[1])
    del i

    ret = 0

    opts, args = getopt.gnu_getopt(
        sys.argv, '', longopts=['help', 'version', 'verbose']
        )

    opts_d = dict(opts)

    log_level = 'warning'
    if '--verbose' in opts_d:
        log_level = 'info'

    log_level = log_level.upper()

    logging.basicConfig(
        format="%(levelname)s %(message)s",
        level=log_level
        )

    db = org.wayround.softengine.rtenv.DB(
        db_config,
        echo=db_echo
        )

    rtenv = org.wayround.softengine.rtenv.RuntimeEnvironment(db)

    org.wayround.tasktracker.modules.TaskTracker(rtenv)

    rtenv.init()

    rtenv.db.create_all()

    env = org.wayround.tasktracker.env.Environment(
        rtenv,
        admin_jid='animus@wayround.org'
        )

    env.start()

    return ret
