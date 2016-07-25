#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_org_tasktracker',
    version='0.1',
    description='simple usual http based task tracker',
    author='Alexey V Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_org_tasktracker',
    packages=[
        'wayround_org.tasktracker'
        ],
    install_requires=[
        'wayround_org_utils',
        'wayround_org_toxcorebot',
        'wayround_org_carafe',
        ],
    entry_points={
        'console_scripts':
        'wro-tasktracker = wayround_org.tasktracker.main:main'
        }
    )
