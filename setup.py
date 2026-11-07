from setuptools import setup, find_packages

setup(
    name="deaddrop",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "deaddrop=deaddrop.client.cli:main",
            "deaddrop-server=deaddrop.server.main:main",
        ],
    },
)
