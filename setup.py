try:
    from setuptools import setup
    from setuptools import find_packages

    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os

    packages = [
        x.strip("./").replace("/", ".")
        for x in os.popen('find -name "__init__.py" | xargs -n1 dirname')
        .read()
        .strip()
        .split("\n")
    ]

setup(
    name="pwnshop",
    version="0.0.1",
    python_requires=">=3.8",
    packages=packages,
    install_requires=["jinja2==3.0.3", "nbconvert==6.4.4", "asteval", "pyastyle", "pwntools", "ezmp", "pyyaml", "ruamel.yaml", "docker"],
    package_data={"pwnshop.challenges": ["pwnshop/challenges/*.j2"]},
    description="A framework for generating CTF challenges for learning",
    url="https://github.com/pwncollege/pwnshop",
)
