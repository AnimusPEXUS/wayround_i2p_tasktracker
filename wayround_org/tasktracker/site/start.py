#!/usr/bin/python3

import os.path
import sys

import wayround_org.utils.program
import wayround_org.tasktracker.commands


wayround_org.utils.program.logging_setup('info')

wd = os.path.abspath(os.path.dirname(__file__))

adds = {}
adds['db_config'] = 'sqlite:///{}/db/database.sqlite'.format(wd)
adds['db_echo'] = False
adds['bot_state_file'] = os.path.join(wd, 'bot_state.bin')
adds['host'] = 'localhost'
adds['port'] = 8080
adds['main_admin'] = 'animus@wayround.org'

commands = wayround_org.tasktracker.commands.commands()

command_name = os.path.basename(sys.argv[0])

ret = wayround_org.utils.program.program(command_name, commands, adds)

exit(ret)
