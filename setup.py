from setuptools import setup

from cap import __version__

REQUIREMENTS = ['enum34']

setup(
    name='cap',
    version=__version__,
    py_modules=['cap'],
    install_requires=REQUIREMENTS,
    url='https://github.com/code-museum/cap',
    license='GNU General Public License, version 2',
    author='code-museum',
    author_email='code-museum@users.noreply.github.com',
    description='Cap: lightweight package for use network captures',
    keywords="network capture packet pcap"
)
