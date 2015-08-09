from setuptools import setup
import pftriage

setup(
    name='pftriage',
    version=pftriage.__version__,
    url='https://github.com/idiom/pype',
    author=pftriage.__author__,
    description=pftriage.__description__,
    install_requires=['pefile', 'python-magic', 'yara'],
    py_modules=['pftriage'],
    data_files=[('data', ['data/userdb.txt', 'data/default.yara'])],
    entry_points={'console_scripts': ['pftriage=pftriage:main']}
)
