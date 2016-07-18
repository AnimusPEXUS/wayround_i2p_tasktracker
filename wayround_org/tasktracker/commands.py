
import logging
import threading

import wayround_org.softengine.rtenv
import wayround_org.tasktracker.jabber_commands
import wayround_org.tasktracker.modules
import wayround_org.toxcorebot.bot


def commands():
    return dict(
        run=site_run
        )


def site_run(comm, opts, args, adds):
    """
    Start and continue running service - no background separation.
    """

    ret = 0

    db_config = adds['db_config']
    db_echo = adds['db_echo']
    host = adds['host']
    port = adds['port']
    main_admin = adds['main_admin']

    db = wayround_org.softengine.rtenv.DB_SQLAlchemy(
        db_config,
        echo=db_echo,
        # FIXME: this is unsafe?
        connect_args={'check_same_thread': False}
        )

    rtenv = wayround_org.softengine.rtenv.RuntimeEnvironment(db)

    wayround_org.tasktracker.modules.TaskTracker(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    rtenv.db.create_all()

    bot_commands = wayround_org.tasktracker.bot_commands.BotCommands()

    bot = wayround_org.xmpp.client_bot.Bot()

    environ = wayround_org.tasktracker.env.Environment(
        rtenv,
        host=host,
        port=port,
        admin_jid=main_admin
        )

    threading.Thread(
        name="Site Thread",
        target=environ.start
        ).start()

    bot_commands.set_environ(environ)

    bot.set_commands(bot_commands.commands_dict())
    environ.set_bot(bot)

    threading.Thread(
        name="Bot Thread",
        target=bot.start
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
