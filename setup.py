import os

from setuptools import setup
from setuptools import find_packages

packages = find_packages(exclude=["example_module"]) + [ "pwnshop.challenges.base_templates", "pwnshop.challenges.base" ]

setup(
    name="pwnshop",
    version="1.0",
    python_requires=">=3.8",
    packages=packages,
    install_requires=["jinja2==3.0.3", "nbconvert==6.4.4", "asteval", "pyastyle", "pwntools", "ezmp", "pyyaml", "ruamel.yaml", "docker"],
    package_data={ dd.replace("/","."):cc for dd,cc in ( (d,[f for f in c if f.endswith(".c")]) for d,_,c in os.walk("pwnshop") ) if cc },
    description="A framework for generating CTF challenges for learning",
    url="https://github.com/pwncollege/pwnshop",
    entry_points={
        "console_scripts": [
            "pwnshop = pwnshop.__main__:main"
        ],
    },
)
