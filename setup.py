from setuptools import setup

setup(
    name='malinfo',
    version='0.1.0',
    py_modules=['malinfo'],
    install_requires=[
        'Click',
        'datetime',
        'lief',
        'vt',
    ],
    entry_points={
        'console_scripts': [
            'malinfo = malinfo:generate',
        ],
    },
)
