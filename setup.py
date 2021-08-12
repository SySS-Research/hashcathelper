import setuptools
from hashcathelper._meta import __version__, __doc__

setuptools.setup(
    name='hashcathelper',
    version=__version__,
    author='Adrian Vollmer',
    author_email='adrian.vollmer@syss.de',
    url='https://git.syss.intern/avollmer/hashcathelper',
    description=__doc__,
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'hashcathelper=hashcathelper.__main__:main'
        ],
    },
    install_requires=[
        'pyxdg',
        'pycryptodome',
    ],
    extras_require={
        'database': ['sqlalchemy'],
    },
    python_requires='>=3.5',
    tests_require=[
        'pytest',
        'tox',
        'flake8',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
