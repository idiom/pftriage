#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'Click>=6.0',
    'pefile',
    'python-magic'
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='pftriage',
    version='0.1.0',
    description="pftriage is a tool to help analyze files during malware analysis.",
    long_description=readme + '\n\n' + history,
    author="sean",
    author_email='sean@idiom.ca',
    url='https://github.com/idiom/pftriage',
    packages=[
        'pftriage',
    ],
    package_dir={'pftriage':
                 'pftriage'},
    entry_points={
        'console_scripts': [
            'pftriage=pftriage.cli:cli'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="",
    zip_safe=False,
    keywords='pftriage',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
