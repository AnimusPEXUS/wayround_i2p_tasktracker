
import wayround_i2p.toxcorebind.tox


class BotCommands:

    def __init__(self):
        self._environ = None
        return

    def set_environ(self, environ):
        self._environ = environ
        return

    def commands_dict(self):
        ret = dict(
            site=dict(
                register=self.register,
                login=self.login,
                help=self.help
                ),
            me=dict(
                status=self.status
                )
            )
        return ret

    def status(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_pkey = adds['asker_pkey']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_pkey(asker_pkey)

        error = False

        pkey_to_know = asker_pkey

        len_args = len(args)

        if len_args == 0:
            pass

        elif len_args == 1:

            if roles['site_role'] == 'admin':

                pkey_to_know = args[0]
                

                try:
                    wayround_i2p.toxcorebind.tox.public_key_check(pkey_to_know)
                except ToxPublicKeyInvalidFormat:

                    messages.append(
                        {'type': 'error',
                         'text': "Invalid PKey supplied"
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
                roles_to_print = self._environ.get_site_roles_for_pkey(
                    pkey_to_know,
                    all_site_projects=True
                    )

            text = """\
{pkey} site role: {site_role}

{pkey} project roles:
""".format(
    site_role=roles_to_print['site_role'],
    pkey=pkey_to_know
    )

            projects = list(roles_to_print['project_roles'].keys())
            projects.sort()

            for i in projects:

                text += '    {}: {}\n'.format(
                    i,
                    roles_to_print['project_roles'][i]
                    )

            text += '\n'

            messages.append(
                {'type': 'text',
                 'text': text}
                )

        return ret

    def register(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_pkey = adds['asker_pkey']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_pkey(asker_pkey)

        error = False

        role = 'user'
        pkey_to_reg = asker_pkey

        if roles['site_role'] == 'admin':
            if '-r' in opts:
                role = opts['-r']

            if len(args) == 1:
                pkey_to_reg = args[0]

                try:
                    wayround_i2p.xmpp.core.pkey.new_from_str(pkey_to_reg)
                except:
                    messages.append(
                        {'type': 'error',
                         'text': "Can't parse supplied pkey"}
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

            registrant_role = self._environ.rtenv.modules[
                self._environ.ttm
                ].get_site_role(
                pkey_to_reg
                )

            if (asker_pkey == pkey_to_reg
                and roles['site_role'] != 'guest'):

                messages.append(
                    {'type': 'error',
                     'text': 'You already registered'}
                    )

            elif registrant_role != None:

                messages.append(
                    {'type': 'error',
                     'text': '{} already have role: {}'.format(
                        pkey_to_reg,
                        registrant_role.role
                        )
                     }
                    )

            else:

                if ((roles['site_role'] == 'admin') or
                    (roles['site_role'] != 'admin' and
                     self._environ.register_access_check(asker_pkey))):

                    try:
                        self._environ.rtenv.modules[self._environ.ttm].add_site_role(
                            pkey_to_reg,
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

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_pkey = adds['asker_pkey']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_pkey(asker_pkey)

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
                    self._environ.rtenv.modules[self._environ.ttm].\
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
                         self._environ.login_access_check(asker_pkey))):

                        self._environ.rtenv.modules[self._environ.ttm].\
                            assign_pkey_to_session(
                                session,
                                asker_pkey
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

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        ret_stanza = adds['ret_stanza']

        text = """
help                          this command

status [pkey]                 pkey roles on site. defaults to asker. Only admin
                              can define pkey

register [-r=ROLE] [pkey]     register [self] or [somebody else](only admin can
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
            wayround_i2p.xmpp.core.MessageBody(
                text=text
                )
            ]

        return ret
