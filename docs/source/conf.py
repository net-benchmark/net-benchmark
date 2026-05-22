import os
import sys
from datetime import datetime

from jinja2.sandbox import SandboxedEnvironment


def _dummy_install_gettext_translations(self, translations, newstyle=None):
    """Provide dummy gettext functions that just return the input string."""
    self.globals.setdefault("_", lambda x: x)
    self.globals.setdefault("gettext", lambda x: x)
    self.globals.setdefault("ngettext", lambda s, p, n: (s if n == 1 else p))


if not hasattr(SandboxedEnvironment, "install_gettext_translations"):
    SandboxedEnvironment.install_gettext_translations = (
        _dummy_install_gettext_translations
    )
# --------------------------------------------------------------------------------------

from sphinx.application import Sphinx

sys.path.insert(0, os.path.abspath("../../src"))

_PERSONAL_START_YEAR = 2025
_CURRENT_YEAR = datetime.now().year

_YEAR_RANGE = (
    str(_CURRENT_YEAR)
    if _CURRENT_YEAR == _PERSONAL_START_YEAR
    else f"{_PERSONAL_START_YEAR}–{_CURRENT_YEAR}"
)


def skip_autosummary_for_latex(app: Sphinx) -> None:
    """Disable autosummary stub generation for LaTeX/PDF builds."""
    from sphinx.builders.latex import LaTeXBuilder

    if isinstance(app.builder, LaTeXBuilder):
        app.config.autosummary_generate = False


def setup(app: Sphinx) -> None:
    app.connect("builder-inited", skip_autosummary_for_latex, priority=900)


project = "net-benchmark"
copyright = f"{_YEAR_RANGE}, Joseph Oseh Frank and net-benchmark contributors"
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
    "dns",
    "dnspython",
    "httpx",
    "pandas",
    "aiohttp",
    "pyfiglet",
    "colorama",
    "jinja2",
    "openpyxl",
    "yaml",
    "tqdm",
    "matplotlib",
    "PIL",
    "weasyprint",
    "click",
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
    (
        master_doc,
        "net-benchmark.tex",
        "net-benchmark Documentation",
        "Joseph Oseh Frank",
        "manual",
    ),
]
epub_show_urls = "footnote"
