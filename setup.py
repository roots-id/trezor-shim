#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/

Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/
"""


from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages
from setuptools import setup

setup(
    name='trezor-shim',
    version='0.0.1',  # also change in src/keria/__init__.py
    license='Apache Software License 2.0',
    description='Google Cloud KSM Signify HSM Integration Module',
    long_description="Google Cloud KSM Signify HSM Integration Module.",
    author='Rodolfo Miranda',
    author_email='rodolfo.miranda@rootsid.com',
    url='https://github.com/roots-id/trezor-shim',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        # 'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Issue Tracker': 'https://github.com/roots-id/trezor-shim/issues',
    },
    keywords=[
        "secure attribution",
        "authentic data",
        "discovery",
        "resolver",
        "trezor"
    ],
    python_requires='>=3.10.4',
    install_requires=[
        'hio>=0.6.9',
        'keri @ git+https://git@github.com/WebOfTrust/keripy.git',
        'cryptography>=39.0.2',
        'crcmod>=1.7',
        'bech32>=1.2.0',
        'cryptography>=3.4.6',
        'docutils>=0.14',
        'python-daemon>=2.3.0',
        'wheel>=0.32.3',
        'backports.shutil_which>=3.5.1',
        'python-daemon>=2.1.2',
        'ecdsa>=0.13',
        'pynacl>=1.4.0',
        'pymsgbox>=1.0.6',
        'semver>=2.2',
        'unidecode>=0.4.20',
    ],
    extras_require={
    },
    tests_require=[
        'coverage>=5.5',
        'pytest>=6.2.4',
    ],
    setup_requires=[
    ],
    entry_points={
    },
)
