#!/usr/bin/python3

import os.path
import sys

import org.wayround.utils.program

import org.wayround.tasktracker.commands

import org.wayround.xmpp.core


org.wayround.utils.program.logging_setup('info')

wd = os.path.abspath(os.path.dirname(__file__))

jid = org.wayround.xmpp.core.JID(
    user='tasktracker',
    domain='wayround.org',
    resource='home'
    )

connection_info = org.wayround.xmpp.core.C2SConnectionInfo(
    host='wayround.org',
    port=5222,
    )

auth_info = org.wayround.xmpp.core.Authentication(
    service='xmpp',
    hostname='wayround.org',
    authid='tasktracker',
    authzid='',
    realm='wayround.org',
    password=''
    )

adds = {}
adds['jid'] = jid
adds['xmpp_connection_info'] = connection_info
adds['xmpp_auth_info'] = auth_info
adds['db_config'] = 'sqlite:///{}/db/database.sqlite'.format(wd)
adds['db_echo'] = False
adds['host'] = 'localhost'
adds['port'] = 8080
adds['main_admin'] = 'animus@wayround.org'

commands = org.wayround.tasktracker.commands.commands()

command_name = os.path.basename(sys.argv[0])

ret = org.wayround.utils.program.program(command_name, commands, adds)

exit(ret)
