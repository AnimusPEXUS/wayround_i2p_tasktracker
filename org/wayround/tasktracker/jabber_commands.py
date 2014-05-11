
import org.wayround.xmpp.core


class JabberCommands:

    def __init__(self):
        self._site = None

    def set_site(self, site):

        self._site = site

    def commands_dict(self):
        return dict(
            site=dict(
                register=self.register,
                login=self.login,
                help=self.help
                ),
            me=dict(
                status=self.status
                )
            )

    def status(self, comm, opts, args, adds):

        if not self._site:
            raise ValueError("use set_site() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']
        ret_stanza = adds['ret_stanza']

        roles = self._site.get_site_roles_for_jid(asker_jid)

        error = False

        jid_to_know = asker_jid

        len_args = len(args)

        if len_args == 0:
            pass

        elif len_args == 1:

            if roles['site_role'] == 'admin':

                jid_to_know = args[0]

                try:
                    org.wayround.xmpp.core.JID.new_from_str(jid_to_know)
                except:

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
                org.wayround.xmpp.core.MessageBody(
                    text=text
                    )
                ]

        return ret

    def register(self, comm, opts, args, adds):

        if not self._site:
            raise ValueError("use set_site() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']

        roles = self._site.get_site_roles_for_jid(asker_jid)

        error = False

        role = 'user'
        jid_to_reg = asker_jid

        if roles['site_role'] == 'admin':
            if '-r' in opts:
                role = opts['-r']

            if len(args) == 1:
                jid_to_reg = args[0]

                try:
                    org.wayround.xmpp.core.JID.new_from_str(jid_to_reg)
                except:
                    messages.append(
                        {'type': 'error',
                         'text': "Can't parse supplied JID"}
                        )
                    error = True

        else:
            if '-r' in opts:
                messages.append(
                    {'type': 'error',
                     'text': "You are not admin and can't use -r option"}
                    )
                error = True

            if len(args) != 0:
                messages.append(
                    {'type': 'error',
                     'text': "You are not admin and can't use arguments"}
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
                    {'type': 'error',
                     'text': 'You already registered'}
                    )

            elif registrant_role != None:

                messages.append(
                    {'type': 'error',
                     'text': '{} already have role: {}'.format(
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
                            {'type': 'error',
                             'text': "can't add role. is already registered?"}
                            )
                    else:
                        messages.append(
                            {'type': 'info',
                             'text': 'registration successful'}
                            )
                else:
                    messages.append(
                        {'type': 'error',
                         'text': "registration not allowed"}
                        )

        return ret

    def login(self, comm, opts, args, adds):

        if not self._site:
            raise ValueError("use set_site() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']

        roles = self._site.get_site_roles_for_jid(asker_jid)

        cookie = None

        error = False

        if len(args) != 1:
            messages.append(
                {'type': 'error',
                 'text': "Cookie is required parameter"}
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
                    self._site.rtenv.modules[self._site.ttm].\
                        get_session_by_cookie(
                            cookie
                            )
                    )

                if not session:
                    messages.append(
                        {'type': 'error',
                         'text': "Invalid session cookie"}
                        )
                else:

                    if ((roles['site_role'] == 'admin') or
                        (roles['site_role'] != 'admin' and
                         self._site.login_access_check(asker_jid))):

                        self._site.rtenv.modules[self._site.ttm].\
                            assign_jid_to_session(
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

        return ret

    def help(self, comm, opts, args, adds):

        if not self._site:
            raise ValueError("use set_site() method")

        ret = 0
        ret_stanza = adds['ret_stanza']

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

                              register will succeed only if it is not
                              prohibited on site.

login SESSION_COOKIE          make user with named SESSION_COOKIE logged in on
                              site
                              (only registered user can be logged in)

"""
        ret_stanza.body = [
            org.wayround.xmpp.core.MessageBody(
                text=text
                )
            ]

        return ret
