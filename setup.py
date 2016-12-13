from setuptools import setup

__author__ = 'netanelrevah'

main_namespace = {}
with open('cap/version.py') as version_file:
    exec(version_file.read(), main_namespace)
version = main_namespace['__version__']

REQUIREMENTS = ['typing', 'enum34', 'pytz', 'pkt', 'nicer']

setup(
    name='cap',
    version=version,
    packages=['cap', 'cap._nicer'],

    install_requires=REQUIREMENTS,

    author='netanelrevah',
    author_email='netanelrevah@users.noreply.github.com',
    description='Cap: lightweight package for use network captures',
    license='GNU General Public License, version 2',
    keywords="network capture packet pcap",
    url='https://github.com/netanelrevah/cap'
)
