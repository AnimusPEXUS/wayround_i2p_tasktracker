#!/usr/bin/python3


import wayround_org.utils.program

import wayround_org.tasktracker.commands


main = wayround_org.utils.program.MainScript(
    wayround_org.tasktracker.commands,
    'wro-tasktracker',
    'INFO'
    ).main

if __name__ == '__main__':
    exit(main())
