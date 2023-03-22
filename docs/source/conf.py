# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys
from sphinx.ext.apidoc import main as sphinx_apidoc

sys.path.insert(0, os.path.abspath('../../src/pkcs11_ca_service/'))
# print(sys.path)

# Auto generate docs with sphinx api docs
try:
    os.remove("pkcs11_ca_service.rst")
except OSError:
    pass
try:
    os.remove("modules.rst")
except OSError:
    pass
if sphinx_apidoc(['--implicit-namespaces', '-o', '.', '../../src/pkcs11_ca_service/']) != 0:
    print("ERROR: Could not auto generate docs")
    sys.exit(1)

project = 'PKCS11CA'
copyright = '2023, SUNET'
author = 'Victor Näslund'
release = '0.2'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
]

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
