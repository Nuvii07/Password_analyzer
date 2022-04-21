from setuptools import setup

# python setup.py sdist
setup(
    name='password_validators',
    version='0.1',
    description='Collection of password validators',
    author='Mateusz Kopciński',
    packages=['password_validators'],
    install_requires=['requests']
)
