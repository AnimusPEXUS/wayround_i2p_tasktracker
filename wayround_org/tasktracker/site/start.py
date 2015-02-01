#!/usr/bin/python3

import os.path
import sys

import wayround_org.utils.program

import wayround_org.tasktracker.commands

import wayround_org.xmpp.core


wayround_org.utils.program.logging_setup('info')

wd = os.path.abspath(os.path.dirname(__file__))

jid = wayround_org.xmpp.core.JID(
    user='tasktracker',
    domain='wayround.org',
    resource='home'
    )

connection_info = wayround_org.xmpp.core.C2SConnectionInfo(
    host='wayround.org',
    port=5222,
    )

auth_info = wayround_org.xmpp.core.Authentication(
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

commands = wayround_org.tasktracker.commands.commands()

command_name = os.path.basename(sys.argv[0])

ret = wayround_org.utils.program.program(command_name, commands, adds)

exit(ret)
