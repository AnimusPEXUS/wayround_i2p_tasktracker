
import os.path
import logging
import threading
import yaml

import wayround_org.softengine.rtenv

import wayround_org.toxcorebot.bot

import wayround_org.tasktracker.bot_commands
import wayround_org.tasktracker.modules


def commands():
    return dict(
        run=site_run
        )


def site_run(comm, opts, args, adds):
    """
    Start and continue running service - no background separation.
    """

    ret = 0

    len_args = len(args)

    if len_args == 0:
        cwd = os.getcwd()

    elif len_args == 1:
        cwd = args[0]

    else:
        raise Exception("Invalid argument number")

    config_file_path = os.path.join(cwd, 'config.yaml')

    try:
        with open(config_file_path) as f:
            cfg = yaml.load(f.read())
    except:
        print(
            "Can't load config file: {}".format(config_file_path)
            )
        raise

    if (not 'control_info' in cfg
            or cfg['control_info'] != 'TaskTracker config file'):
        raise Exception("config file invalid format")

    db_config = cfg.get('db_config', None)
    db_echo = cfg.get('db_echo', False)
    host = cfg.get('host', 'localhost')
    port = cfg.get('port', 8080)
    admin_pkey = cfg.get('admin_pkey', None)
    bot_save_state_file = cfg.get('bot_save_state_file', 'savedate.bin')

    if not db_config.startswith('sqlite://'):
        db_config = 'sqlite:///{}'.format(os.path.join(cwd, db_config))

    if not bot_save_state_file.startswith('/'):
        bot_save_state_file = os.path.join(cwd, bot_save_state_file)

    print("""\
TaskTracker Configuration Summary:
    Server configured to listen on:
        {2}:{3}
    DB configuration uri is:
        {0}
    DB echo:
        {1}
    Administrative TOX public key is:
        {4}
    Bot state save into file:
        {5}\
""".format(
        db_config,
        db_echo,
        host,
        port,
        admin_pkey,
        bot_save_state_file
        )
        )

    try:
        db = wayround_org.softengine.rtenv.DB_SQLAlchemy(
            db_config,
            echo=db_echo,
            # FIXME: this is unsafe?
            connect_args={'check_same_thread': False}
            )
    except:
        print("Can't start DB engine")
        raise

    rtenv = wayround_org.softengine.rtenv.RuntimeEnvironment(db)

    wayround_org.tasktracker.modules.TaskTracker(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    rtenv.db.create_all()

    bot_commands = wayround_org.tasktracker.bot_commands.BotCommands()

    bot = wayround_org.toxcorebot.bot.Bot(
        bot_commands,
        bot_save_state_file
        )

    environ = wayround_org.tasktracker.env.Environment(
        rtenv,
        host=host,
        port=port,
        admin_pkey=admin_pkey
        )

    threading.Thread(
        name="Site Thread",
        target=environ.start
        ).start()

    bot_commands.set_environ(environ)

    # bot.set_commands(bot_commands.commands_dict())

    environ.set_bot(bot)

    threading.Thread(
        name="Bot Thread",
        target=start_bot,
        args=(bot,)
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
    logging.debug("starting environ stop")
    environ.stop()
    logging.debug("all things stopped")

    logging.debug("MainThread exiting")

    return ret


def start_bot(bot):
    bot.start()
    print("""\
    TOX bot public key (address) determined to be:
        {}\
""".format(
        bot.get_address().hex().upper()
        )
    )
    return
