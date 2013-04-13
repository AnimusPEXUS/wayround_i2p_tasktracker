
"""
TaskTracker XMPP bot of WayRound.ORG
"""

import logging
import lxml.etree
import socket
import threading
import xml.sax.saxutils

import org.wayround.gsasl.gsasl

import org.wayround.xmpp.core
import org.wayround.xmpp.stanza_elements
import org.wayround.xmpp.client

import org.wayround.utils.getopt
import org.wayround.utils.file
import org.wayround.utils.shlex


class AuthLocalDriver:

    def __init__(self, real_client):

        self.real_client = real_client

        self._result_ready = threading.Event()
        self._result_ready.clear()

        self.result = 'clean'

        self._simple_gsasl = None

    def start(self):

        if not self._simple_gsasl:
            self._simple_gsasl = org.wayround.gsasl.gsasl.GSASLSimple(
                mechanism='DIGEST-MD5',
                callback=self._gsasl_cb
                )

    def wait(self):

        self._result_ready.wait()

        return self.result

    def wait_abort(self):
        self.result = 'error'
        self._result_ready.set()
        return

    def mech_select(self, mechanisms):

        ret = None

        if 'DIGEST-MD5' in mechanisms:
            ret = 'DIGEST-MD5'

        return ret

    def auth(self, mechanism):
        pass

    def response(self, text):
        pass

    def challenge(self, text):

        res = self._simple_gsasl.step64(text)

        if res[0] == org.wayround.gsasl.gsasl.GSASL_OK:
            pass
        elif res[0] == org.wayround.gsasl.gsasl.GSASL_NEEDS_MORE:
            pass
        else:
            raise Exception(
                "step64 returned error: {}".format(
                    org.wayround.gsasl.gsasl.strerror_name(res[0])
                    )
                )

        ret = str(res[1], 'utf-8')

        return ret

    def success(self, text):

        self.result = 'success'
        self._result_ready.set()

    def failure(self, name, text):

        self.result = 'failure'
        self._result_ready.set()


    def text(self):
        pass

    def _gsasl_cb(self, context, session, prop):
        ret = org.wayround.gsasl.gsasl.GSASL_OK

        logging.debug(
            "SASL client requested for: {} ({}) {}".format(
                org.wayround.gsasl.gsasl.strproperty_name(prop),
                prop,
                org.wayround.gsasl.gsasl.strproperty(prop)
                )
            )

        if prop == org.wayround.gsasl.gsasl.GSASL_QOP:

            server_allowed_qops = str(
                session.property_get(
                    org.wayround.gsasl.gsasl.GSASL_QOPS
                    ),
                'utf-8'
                ).split(',')

            value = ''
            if not 'qop-auth' in server_allowed_qops:
                value = ''
            else:
                value = 'qop-auth'

            session.property_set(
                org.wayround.gsasl.gsasl.GSASL_QOP,
                bytes(value, 'utf-8')
                )

        elif prop == org.wayround.gsasl.gsasl.GSASL_AUTHID:

            value = None
            if self.real_client.auth_info.authid:
                value = bytes(self.real_client.auth_info.authid, 'utf-8')

            session.property_set(prop, value)

        elif prop == org.wayround.gsasl.gsasl.GSASL_SERVICE:

            value = None
            if self.real_client.auth_info.service:
                value = bytes(self.real_client.auth_info.service, 'utf-8')

            session.property_set(prop, value)

        elif prop == org.wayround.gsasl.gsasl.GSASL_HOSTNAME:

            value = None
            if self.real_client.auth_info.hostname:
                value = bytes(self.real_client.auth_info.hostname, 'utf-8')

            session.property_set(prop, value)

        elif prop == org.wayround.gsasl.gsasl.GSASL_REALM:

            value = None
            if self.real_client.auth_info.realm:
                value = bytes(self.real_client.auth_info.realm, 'utf-8')

            session.property_set(prop, value)

        elif prop == org.wayround.gsasl.gsasl.GSASL_AUTHZID:

            value = None
            if self.real_client.auth_info.authzid:
                value = bytes(self.real_client.auth_info.authzid, 'utf-8')

            session.property_set(prop, value)

        elif prop == org.wayround.gsasl.gsasl.GSASL_PASSWORD:

            value = None
            if self.real_client.auth_info.password:
                value = bytes(self.real_client.auth_info.password, 'utf-8')

            session.property_set(prop, value)

        else:
            logging.error("Requested SASL property not available")
            ret = 1


        return ret

class Bot:

    def __init__(self):

        self._clean(init=True)

    def set_site(self, site):

        self._site = site

    def _clean(self, init=False):

        self.connection = False

        self._driven = False
        self._stream_in = False
        self._stream_out = False
        self._features_recieved = threading.Event()
        self._stop_flag = False

        self._stopping = False
        self._starting = False

    def start(self, jid, connection_info, auth_info, exit_event=None):

        if not self._stopping and not self._starting:

            self._starting = True

            self.exit_event = exit_event

            self.jid = jid

            self.connection_info = connection_info

            self.auth_info = auth_info

            self.sock = socket.create_connection(
                (
                 self.connection_info.host,
                 self.connection_info.port
                 )
                )


            logging.debug("Starting socket watcher")

            self.client = org.wayround.xmpp.client.XMPPC2SClient(
                self.sock
                )

            self.reset_hubs()

            self.client.start()

            self.client.wait('working')

            self.stanza_processor = org.wayround.xmpp.core.StanzaProcessor()
            self.stanza_processor.connect_input_object_stream_hub(
                self.client.input_stream_objects_hub
                )
            self.stanza_processor.connect_io_machine(self.client.io_machine)

            self._driven = True

            while True:

                if self._features_recieved.wait(200):
                    break

                if self._stop_flag:
                    break

            self._features_recieved.clear()

            if not self._stop_flag:

                res = org.wayround.xmpp.client.client_starttls(
                    self.client,
                    self.jid,
                    self.connection_info,
                    self._last_features
                    )

                if res != 'success':
                    self._stop_flag = True
                else:

                    while True:

                        if self._features_recieved.wait(200):
                            break

                        if self._stop_flag:
                            break

                    self._features_recieved.clear()

                    if not self._stop_flag:

                        local_auth = AuthLocalDriver(self)
                        local_auth.start()

                        res = org.wayround.xmpp.client.client_sasl_auth(
                            self.client,
                            local_auth.mech_select,
                            local_auth.auth,
                            local_auth.response,
                            local_auth.challenge,
                            local_auth.success,
                            local_auth.failure,
                            local_auth.text,
                            self.jid,
                            self.connection_info,
                            self._last_features
                            )

                        if res != 'success':
                            self._stop_flag = True
                        else:

                            while True:

                                if self._features_recieved.wait(200):
                                    break

                                if self._stop_flag:
                                    break

                            self._features_recieved.clear()

                            if not self._stop_flag:

                                res = org.wayround.xmpp.client.client_resource_bind(
                                    self.client,
                                    self.jid,
                                    self.connection_info,
                                    self._last_features,
                                    self.stanza_processor
                                    )


                                if res != 'success':
                                    self._stop_flag = True
                                else:

                                    if not self._stop_flag:

                                        res = org.wayround.xmpp.client.client_session_start(
                                            self.client,
                                            self.jid,
                                            self.connection_info,
                                            self._last_features,
                                            self.stanza_processor
                                            )


                                        if res != 'success':
                                            self._stop_flag = True
                                        else:

                                            self._driven = False

                                            logging.debug("Connecting bot inbound stanza processor")

                                            self.stanza_processor.stanza_hub.set_waiter(
                                                'tasktracker_bot',
                                                self._inbound_stanzas
                                                )

                                            self.stanza_processor.send(
                                                org.wayround.xmpp.core.Stanza(
                                                    kind='presence',
                                                    jid_from=self.jid.full(),
                                                    body='<show>online</show><status>online</status>'
                                                    )
                                                )

                                            self.stanza_processor.send(
                                                org.wayround.xmpp.core.Stanza(
                                                    kind='message',
                                                    typ='chat',
                                                    jid_from=self.jid.full(),
                                                    jid_to='animus@wayround.org',
                                                    body='<body>TaskTracker bot is now online</body><subject>WOW!</subject>'
                                                    )
                                                )

# TODO: move to self.stop()
#                                            try:
#                                                exit_event.wait()
#                                            except KeyboardInterrupt:
#                                                logging.info("Stroke. exiting")
#                                            except:
#                                                logging.exception("Error")
#
#            self._driven = False
#
#
#            if self.sock:
#                try:
#                    self.sock.shutdown(socket.SHUT_RDWR)
#                except:
#                    print("Socket shutdown error. maybe it's closed already")
#
#                try:
#                    self.sock.close()
#                except:
#                    print("Socket close error")
#
#            logging.debug(
#                "Reached the end. socket is {} {}".format(
#                    self.client.socket,
#                    self.client.socket._closed
#                    )
#                )
#
#            print("Threads alive:")
#            for i in threading.enumerate():
#                print("    {}".format(repr(i)))
#

            self._driven = False

            self._starting = False

            if self._stop_flag:
                self.stop()

        return 0

    def stop(self):

        if not self._stopping and not self._starting:

            self._stopping = True

            self._driven = False

            self._stop_flag = True

            self.client.stop()

            self.exit_event.set()

            self._stopping = False


    def reset_hubs(self):

        self.client.connection_events_hub.clear()
        self.client.input_stream_events_hub.clear()
        self.client.input_stream_objects_hub.clear()
        self.client.output_stream_events_hub.clear()

        self.client.connection_events_hub.set_waiter(
            'main', self._on_connection_event,
            )

        self.client.input_stream_events_hub.set_waiter(
            'main', self._on_stream_in_event,
            )

        self.client.input_stream_objects_hub.set_waiter(
            'main', self._on_stream_object,
            )

        self.client.output_stream_events_hub.set_waiter(
            'main', self._on_stream_out_event,
            )

    def _inbound_stanzas(self, obj):

        if obj.kind == 'message' and obj.typ == 'chat':

            cmd_line = org.wayround.utils.shlex.split(
                obj.body.find('{jabber:client}body').text.splitlines()[0]
                )

            if len(cmd_line) == 0:
                pass
            else:

                messages = []

                ret_stanza = org.wayround.xmpp.core.Stanza(
                    jid_from=self.jid.bare(),
                    jid_to=obj.jid_from,
                    kind='message',
                    typ='chat',
                    body=[
                        org.wayround.xmpp.stanza_elements.Body(
                            text=''
                            )
                        ]
                    )

                asker_jid = org.wayround.xmpp.core.jid_from_string(
                    obj.jid_from
                    ).bare()

                roles = self._site.get_site_roles_for_jid(asker_jid)

                cmd = cmd_line[0]

                opts, args = org.wayround.utils.getopt.getopt(cmd_line[1:])

                if cmd == 'status':

                    error = False

                    jid_to_know = asker_jid

                    len_args = len(args)

                    if len_args == 0:
                        pass

                    elif len_args == 1:

                        if roles['site_role'] == 'admin':

                            jid_to_know = args[0]

                            jfs = org.wayround.xmpp.core.jid_from_string(
                                jid_to_know
                                )

                            if not jfs:

                                messages.append(
                                    {'type': 'error',
                                     'text': "Invalid JID supplied"
                                     }
                                    )

                                error = True

                        else:

                            messages.append(
                                {'type': 'error',
                                 'text': "You are not admin"}
                                )

                            error = True

                    else:

                        messages.append(
                            {'type': 'error',
                             'text': "Too many arguments"}
                            )

                        error = True

                    if not error:

                        roles_to_print = roles

                        if roles['site_role'] == 'admin':
                            roles_to_print = self._site.get_site_roles_for_jid(
                                jid_to_know,
                                all_site_projects=True
                                )

                        text = """
{jid} site role: {site_role}

{jid} project roles:
""".format(
        site_role=roles_to_print['site_role'],
        jid=jid_to_know
        )

                        projects = list(roles_to_print['project_roles'].keys())
                        projects.sort()

                        for i in projects:

                            text += '    {}: {}\n'.format(
                                i,
                                roles_to_print['project_roles'][i]
                                )

                        text += '\n'

                        ret_stanza.body = [
                            org.wayround.xmpp.stanza_elements.Body(
                                text=text
                                )
                            ]

                elif cmd == 'register':

                    error = False

                    role = 'user'
                    jid_to_reg = asker_jid

                    if roles['site_role'] == 'admin':
                        if '-r' in opts:
                            role = opts['-r']

                        if len(args) == 1:
                            jid_to_reg = args[0]

                            if org.wayround.xmpp.core.jid_from_string(
                                jid_to_reg
                                ) == None:
                                messages.append(
                                    {'type':'error',
                                     'text':"Can't parse supplied JID"}
                                    )
                                error = True

                    else:
                        if '-r' in opts:
                            messages.append(
                                {'type':'error',
                                 'text':"You are not admin and can't use -r option"}
                                )
                            error = True

                        if len(args) != 0:
                            messages.append(
                                {'type':'error',
                                 'text':"You are not admin and can't use arguments"}
                                )
                            error = True

                    if error:
                        pass
                    else:

                        registrant_role = self._site.rtenv.modules[
                            self._site.ttm
                            ].get_site_role(
                            jid_to_reg
                            )

                        if (asker_jid == jid_to_reg
                            and roles['site_role'] != 'guest'):

                            messages.append(
                                {'type':'error',
                                 'text':'You already registered'}
                                )

                        elif registrant_role != None:

                            messages.append(
                                {'type':'error',
                                 'text':'{} already have role: {}'.format(
                                    jid_to_reg,
                                    registrant_role.role
                                    )
                                 }
                                )

                        else:

                            if ((roles['site_role'] == 'admin') or
                                (roles['site_role'] != 'admin' and
                                 self._site.register_access_check(asker_jid))):

                                try:
                                    self._site.rtenv.modules[self._site.ttm].add_site_role(
                                        jid_to_reg,
                                        role
                                        )
                                except:
                                    messages.append(
                                        {'type':'error',
                                         'text':"can't add role. is already registered?"}
                                        )
                                else:
                                    messages.append(
                                        {'type':'info',
                                         'text':'registration successful'}
                                        )
                            else:
                                messages.append(
                                    {'type':'error',
                                     'text':"registration not allowed"}
                                    )


                elif cmd == 'login':

                    cookie = None

                    error = False

                    if len(args) != 1:
                        messages.append(
                            {'type': 'error',
                             'text':"Cookie is required parameter"}
                            )
                        error = True
                    else:
                        cookie = args[0]

                    if error:
                        pass
                    else:

                        if roles['site_role'] == 'guest':
                            messages.append(
                                {'type': 'error',
                                 'text': "You are not registered"}
                                )
                        else:

                            session = (
                                self._site.rtenv.modules[self._site.ttm].get_session_by_cookie(
                                    cookie
                                    )
                                )

                            if not session:
                                messages.append(
                                    {'type': 'error',
                                     'text':"Invalid session cookie"}
                                    )
                            else:

                                if ((roles['site_role'] == 'admin') or
                                    (roles['site_role'] != 'admin' and
                                     self._site.login_access_check(asker_jid))):

                                    self._site.rtenv.modules[self._site.ttm].assign_jid_to_session(
                                        session,
                                        asker_jid
                                        )

                                    messages.append(
                                        {'type': 'info',
                                         'text': "Logged in"}
                                        )

                                else:

                                    messages.append(
                                        {'type': 'errlr',
                                         'text': "Loggin forbidden"}
                                        )


                elif cmd == 'help':

                    text = """
help                          this command

status [JID]                  JID roles on site. defaults to asker. Only admin
                              can define JID

register [-r=ROLE] [JID]      register [self] or [somebody else](only admin can
                              do this) on site.

                              possible roles: 'admin', 'moder', 'user',
                                              'blocked'

                              default role is 'user'

                              already registered user can not be registered
                              again

                              non registered user has role 'guest'

                              when user registers self, he can not use -r
                              parameter, and -r will always be 'user'.

                              register will succeed only if it is not prohibited
                              on site.

login SESSION_COOKIE          make user with named SESSION_COOKIE logged in on
                              site
                              (only registered user can be logged in)

"""
                    ret_stanza.body = [
                        org.wayround.xmpp.stanza_elements.Body(
                            text=text
                            )
                        ]

                else:

                    ret_stanza.body = [
                        org.wayround.xmpp.stanza_elements.Body(
                            text='{}: command not found\n'.format(cmd)
                            )
                        ]

#                if asker_jid == self._site.admin_jid:
#
#                    ret_stanza.body = (
#                        '<body>Authorized.\n\nProvided cmd line was{}</body>'.format(
#                            xml.sax.saxutils.escape(repr(cmd_line))
#                            )
#                        )

                messages_text = ''

                for i in messages:

                    typ = i['type']
                    text = i['text']

                    messages_text += '[{typ}]: {text}\n'.format(
                        typ=typ,
                        text=text
                        )

                for i in ret_stanza.body:

                    if isinstance(i, org.wayround.xmpp.stanza_elements.Body):
                        i.text = messages_text + i.text
                        break

                self.stanza_processor.send(ret_stanza)

    def _on_connection_event(self, event, sock):

        if not self._driven:

            logging.debug("_on_connection_event `{}', `{}'".format(event, sock))

            if event == 'start':
                print("Connection started")

                self.connection = True

                self.client.wait('working')

                logging.debug("Ended waiting for connection. Opening output stream")


                self.client.io_machine.send(
                    org.wayround.xmpp.core.start_stream(
                        jid_from=self.jid.bare(),
                        jid_to=self.connection_info.host
                        )
                    )

                logging.debug("Stream opening tag was started")

            elif event == 'stop':
                print("Connection stopped")
                self.connection = False
                self.stop()

            elif event == 'error':
                print("Connection error")
                self.connection = False
                self.stop()


    def _on_stream_in_event(self, event, attrs=None):

        if not self._driven:

            logging.debug("Stream in event `{}' : `{}'".format(event, attrs))

            if event == 'start':

                self._stream_in = True

            elif event == 'stop':
                self._stream_in = False
                self.stop()

            elif event == 'error':
                self._stream_in = False
                self.stop()

    def _on_stream_out_event(self, event, attrs=None):

        if not self._driven:

            logging.debug("Stream out event `{}' : `{}'".format(event, attrs))

            if event == 'start':

                self._stream_out = True

            elif event == 'stop':
                self._stream_out = False
                self.stop()

            elif event == 'error':
                self._stream_out = False
                self.stop()

    def _on_stream_object(self, obj):

        logging.debug("_on_stream_object (first 255 bytes):`{}'".format(repr(lxml.etree.tostring(obj)[:255])))

        if obj.tag == '{http://etherx.jabber.org/streams}features':

            self._last_features = obj

            self._features_recieved.set()


