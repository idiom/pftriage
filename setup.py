from setuptools import setup
import pftriage

setup(
    name='pftriage',
    version=pftriage.__version__,
    url='https://github.com/idiom/pftriage',
    author=pftriage.__author__,
    description=pftriage.__description__,
    install_requires=['pefile', 'python-magic'],
    py_modules=['pftriage'],
    entry_points={'console_scripts': ['pftriage=pftriage:main']}
)
