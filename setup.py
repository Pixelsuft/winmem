import sys
import os
import sys
import subprocess
from urllib.request import urlretrieve as download
from setuptools import setup, find_packages


if not sys.platform == 'win32':
    raise OSError('Working ONLY under windows')


version = '0.0.8'
readme = ''
requirements = []


if os.access('README.MD', os.F_OK):
    temp_file = open('README.MD', 'r')
    readme = temp_file.read()
    temp_file.close()
else:
    download('https://github.com/Pixelsuft/winmem/raw/main/README.MD', 'README.MD')
    temp_file = open('README.MD', 'r')
    readme = temp_file.read()
    temp_file.close()
    os.remove('README.MD')

if os.access('requirements.txt', os.F_OK):
    temp_file = open('requirements.txt', 'r')
    requirements = temp_file.read().split('\n')
    temp_file.close()
else:
    download('https://github.com/Pixelsuft/winmem/raw/main/requirements.txt', 'requirements.txt')
    temp_file = open('requirements.txt', 'r')
    requirements = temp_file.read().split('\n')
    temp_file.close()
    os.remove('requirements.txt')

setup(
    name="winmem",
    author="Pixelsuft",
    url="https://github.com/Pixelsuft/winmem",
    project_urls={
        "Readme": "https://github.com/Pixelsuft/winmem/blob/main/README.MD",
        "Example": "https://github.com/Pixelsuft/winmem/blob/main/main.py",
        "Issue tracker": "https://github.com/Pixelsuft/winmem/issues",
        "Pull requests": "https://github.com/Pixelsuft/winmem/pulls"
    },
    version=version,
    packages=find_packages(),
    license="MIT",
    description="Work easy with memory. (Windows ONLY)",
    long_description=readme,
    long_description_content_type="text/markdown",
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.6",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    zip_safe=False,
    py_modules=["winmem"],
    package_dir={'': '.'},
    keywords="winmem"
)
