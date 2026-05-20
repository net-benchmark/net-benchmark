import os
import sys

sys.path.insert(0, os.path.abspath("../../src"))

project = "net-benchmark"
copyright = "2026, Joseph Oseh Frank"
author = "Joseph Oseh Frank"
release = "0.5.0"
version = "0.5"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "myst_parser",
    "sphinx_autodoc_typehints",
]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "tasklist",
]

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_use_param = True
napoleon_use_rtype = True

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_mock_imports = [
    "dns", "dnspython", "httpx", "pandas", "aiohttp",
    "pyfiglet", "colorama", "jinja2", "openpyxl", "yaml",
    "tqdm", "matplotlib", "PIL", "weasyprint", "click",
]

autosummary_generate = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

todo_include_todos = True
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
master_doc = "index"

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "titles_only": False,
}
html_static_path = ["_static"]
html_context = {
    "display_github": True,
    "github_user": "net-benchmark",
    "github_repo": "net-benchmark",
    "github_version": "main",
    "conf_py_path": "/docs/source/",
}

latex_documents = [
    (master_doc, "net-benchmark.tex", "net-benchmark Documentation",
     "Joseph Oseh Frank", "manual"),
]
epub_show_urls = "footnote"
