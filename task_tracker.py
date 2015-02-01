#!python3.3

import getopt
import logging
import os.path
import sys

import wayround_org.tasktracker.env


def print_help():
    print("""
usage: {} path


Make new tracker
""".format(os.path.basename(__file__)))


def main():

    for i in [
        (logging.CRITICAL, '-c-'),
        (logging.ERROR   , '-e-'),
        (logging.WARN    , '-w-'),
        (logging.WARNING , '-w-'),
        (logging.INFO    , '-i-'),
        (logging.DEBUG   , '-d-')
        ]:
        logging.addLevelName(i[0], i[1])
    del i

    ret = 0

    opts, args = getopt.gnu_getopt(
        sys.argv, '', longopts=['help', 'version', 'verbose']
        )

    opts_d = dict(opts)

    log_level = 'warning'
    if '--verbose' in opts_d:
        log_level = 'info'

    log_level = log_level.upper()

    logging.basicConfig(
        format="%(levelname)s %(message)s",
        level=log_level
        )

    if '--help' in opts_d:
        print_help()

    elif '--version' in opts_d:
        print("1")

    else:

        if len(args) != 2:
            logging.error("Path not supplied")
            ret = 1
        else:
            install_path = args[1]
            logging.info("Installing to `{}'".format(install_path))
            ret = wayround_org.tasktracker.env.install_launcher(install_path)

    return ret

exit(main())
