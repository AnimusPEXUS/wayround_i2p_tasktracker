
import threading
import getopt
import logging
import os.path
import sys

import org.wayround.softengine.modules

import org.wayround.tasktracker.modules
import org.wayround.tasktracker.env
import org.wayround.tasktracker.bot


def main(
    db_config,
    db_echo,
    host,
    port,
    jid=None,
    main_admin=None,
    xmpp_connection_info=None,
    xmpp_auth_info=None
    ):

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
        echo=db_echo,
        # FIXME: this is unsafe?
        connect_args={'check_same_thread':False}
        )

    rtenv = org.wayround.softengine.rtenv.RuntimeEnvironment(db)

    org.wayround.tasktracker.modules.TaskTracker(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    rtenv.db.create_all()

    bot = org.wayround.tasktracker.bot.Bot()

    env = org.wayround.tasktracker.env.Environment(
        rtenv,
        host=host,
        port=port,
        admin_jid=main_admin
        )

    threading.Thread(
        name="Site Thread",
        target=env.start
        ).start()

    bot.set_site(env)
    env.set_bot(bot)

    threading.Thread(
        name="Bot Thread",
        target=bot.start,
        args=(jid, xmpp_connection_info, xmpp_auth_info,),
        kwargs={'exit_event':exit_event}
        ).start()

    try:
        exit_event.wait()
    except KeyboardInterrupt:
        logging.info("exiting now")
    except:
        logging.exception("Some error while waiting for exit event")

    exit_event.set()

    logging.debug("starting bot stop")
    bot.stop()
    logging.debug("starting site stop")
    env.stop()
    logging.debug("all things stopped")

    logging.debug("MainThread exiting")

    return ret
