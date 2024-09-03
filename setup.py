from setuptools import setup

setup(
    name='jwtauthenticator',
    version='2.0.3',
    description='JSONWebToken Authenticator for JupyterHub',
    url='https://github.com/suptechlab/jwtauthenticator',
    author='ppodolsky',
    author_email='matt@digi.studio',
    license='Apache 2.0',
    packages=['jwtauthenticator'],
    install_requires=[
        'jupyterhub',
        'pyjwt==2.0.1',
    ]
)
