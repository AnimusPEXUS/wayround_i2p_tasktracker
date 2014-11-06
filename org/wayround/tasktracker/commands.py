
import logging
import threading

import org.wayround.softengine.rtenv
import org.wayround.tasktracker.jabber_commands
import org.wayround.tasktracker.modules
import org.wayround.xmpp.client_bot
import org.wayround.xmpp.core


def commands():
    return dict(
        start=site_start
        )


def site_start(comm, opts, args, adds):

    ret = 0

    db_config = adds['db_config']
    db_echo = adds['db_echo']
    host = adds['host']
    port = adds['port']
    main_admin = adds['main_admin']

    jid = adds['jid']
    xmpp_connection_info = adds['xmpp_connection_info']
    xmpp_auth_info = adds['xmpp_auth_info']

    db = org.wayround.softengine.rtenv.DB_SQLAlchemy(
        db_config,
        echo=db_echo,
        # FIXME: this is unsafe?
        connect_args={'check_same_thread': False}
        )

    rtenv = org.wayround.softengine.rtenv.RuntimeEnvironment(db)

    org.wayround.tasktracker.modules.TaskTracker(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    rtenv.db.create_all()

    commands = org.wayround.tasktracker.jabber_commands.JabberCommands()

    bot = org.wayround.xmpp.client_bot.Bot()

    environ = org.wayround.tasktracker.env.Environment(
        rtenv,
        host=host,
        port=port,
        admin_jid=main_admin
        )

    threading.Thread(
        name="Site Thread",
        target=environ.start
        ).start()

    commands.set_environ(environ)

    bot.set_commands(commands.commands_dict())
    environ.set_bot(bot)

    threading.Thread(
        name="Bot Thread",
        target=bot.connect,
        args=(jid, xmpp_connection_info, xmpp_auth_info,),
        ).start()

    try:
        exit_event.wait()
    except KeyboardInterrupt:
        logging.info("exiting now")
    except:
        logging.exception("Some error while waiting for exit event")

    exit_event.set()

    logging.debug("starting bot stop")
    bot.disconnect()
    logging.debug("starting environ stop")
    environ.stop()
    logging.debug("all things stopped")

    logging.debug("MainThread exiting")

    return ret
