
import os.path

import bottle

import org.wayround.utils.file

import org.wayround.softengine.rtenv


class Environment:


    def __init__(self, rtenv, host='localhost', port=8080,):

        self.rt_env = rtenv

        self.host = host
        self.port = port

        self.app = bottle.Bottle()

        self.app.route('/auth', 'GET', self.auth_get)

    def start(self):
        bottle.run(self.app, host=self.host, port=self.port)

    def auth_get(self):
        return 'Hi!'

    def auth_set(self):

        cookies = bottle.request.cookies()

        if 'auth' in cookies:
            pass



def install_launcher(path):

    if not os.path.exists(path):
        os.makedirs(path)

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'site'))
    dst_dir = path

    org.wayround.utils.file.copytree(
        src_dir,
        dst_dir,
        overwrite_files=True,
        clear_before_copy=False,
        dst_must_be_empty=False
        )
