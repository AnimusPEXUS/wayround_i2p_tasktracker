#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_i2p_tasktracker',
    version='0.1',
    description='simple usual http based task tracker',
    author='Alexey V Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_i2p_tasktracker',
    packages=[
        'wayround_i2p.tasktracker'
        ],
    install_requires=[
        'wayround_i2p_utils',
        'wayround_i2p_http',
        'wayround_i2p_toxcorebot',
        'wayround_i2p_carafe',
        ],
    entry_points={
        'console_scripts':
        'wro-tasktracker = wayround_i2p.tasktracker.main:main'
        }
    )
