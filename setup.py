from setuptools import setup, find_packages
import os

version = '0.1.0'

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()

setup(
    name='ckanext-oidc',
    version=version,
    description="CKAN extension for OpenID Connect (OIDC) authentication",
    long_description=README,
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords='CKAN OIDC OpenID Connect authentication',
    author='',
    author_email='',
    url='https://github.com/promptlylabs/ckanext-oidc',
    license='Apache 2.0',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.oidc'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'authlib>=1.2.0',
        'pyjwt>=2.8.0',
        'cryptography>=41.0.0',
        'requests>=2.31.0',
    ],
    entry_points='''
        [ckan.plugins]
        oidc=ckanext.oidc.plugin:OidcPlugin
    ''',
)