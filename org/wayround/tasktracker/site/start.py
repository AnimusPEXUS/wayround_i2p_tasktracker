#!/usr/bin/python3

import os.path
import org.wayround.tasktracker.starter

#logging.basicConfig(level='DEBUG', format="%(levelname)s :: %(threadName)s :: %(message)s")


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


exit(
    org.wayround.tasktracker.starter.main(
        db_config='sqlite:///{}/db/database.sqlite'.format(wd),
        db_echo=False,
        host='localhost',
        port=8080,
        main_admin='animus@wayround.org',
        jid=jid,
        xmpp_connection_info=connection_info,
        xmpp_auth_info=auth_info
        )
     )
