# -*- coding: utf-8 -*-

from distutils.core import setup
import py2exe


setup(name="Project IDS",
 version="1.0",
 description="System of network traffic analyst ",
 author="Gregorio Carazo Maza",
 author_email="gcm00014@gmail.com",
 url="C:\Users\Gregorio\PycharmProjects\proyecto",
 license="Open Source",
 scripts=["project.py"],
 console=["project.py"],
 options={"py2exe": {
            # {"bundle_files": 1},
            "dll_excludes": ["MSVCP90.dll"]
        }
    },
 zipfile=None,
)