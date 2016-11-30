#!/usr/bin/python3


import wayround_i2p.utils.program

import wayround_i2p.tasktracker.commands


main = wayround_i2p.utils.program.MainScript(
    wayround_i2p.tasktracker.commands,
    'wro-tasktracker',
    'INFO'
    ).main

if __name__ == '__main__':
    exit(main())
