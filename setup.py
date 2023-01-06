from setuptools import setup
import os

setup(
    name="aiokevoplus",
    version="4.1.1",
    author="Dominick Meglio",
    author_email="dmeglio@gmail.com",
    description="Control Kwikset Kevo locks",
    license="MIT",
    keywords="kevo kwikset",
    packages=["aiokevoplus"],
    url="https://github.com/dcmeglio/pykevoplus",
    long_description=open(os.path.join(os.path.dirname(__file__), "README.rst")).read(),
    install_requires=["httpx", "pkce", "PyJWT", "websockets"],
)
