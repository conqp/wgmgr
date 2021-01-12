#! /usr/bin/env python


from setuptools import setup


setup(
    name='wgmgr',
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    install_requires=['wgtools'],
    author='Richard Neumann',
    author_email='mail@richard-neumann.de',
    python_requires='>=3.8',
    packages=['wgmgr'],
    entry_points={'console_scripts': ['wgmgr = wgmgr:main']},
    url='https://gitlab.com/coNQP/wgmgr',
    license='GPLv3',
    description='A wireguard PKI management tool.',
    keywords='wireguard manager'
)
