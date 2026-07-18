.. net-benchmark documentation master file

net-benchmark
=============

.. image:: https://badge.fury.io/py/net-benchmark.svg
   :target: https://pypi.org/project/net-benchmark
   :alt: PyPI version

.. image:: https://img.shields.io/pypi/pyversions/net-benchmark.svg
   :target: https://pypi.org/project/net-benchmark
   :alt: Python versions

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://github.com/net-benchmark/net-benchmark/blob/main/LICENSE
   :alt: License: MIT

.. image:: https://github.com/net-benchmark/net-benchmark/actions/workflows/ci.yml/badge.svg
   :target: https://github.com/net-benchmark/net-benchmark/actions
   :alt: CI

.. image:: https://pepy.tech/badge/net-benchmark
   :target: https://pepy.tech/project/net-benchmark
   :alt: Downloads

----

**net-benchmark** is a fast, extensible network benchmarking suite for **DNS**, **HTTP**, and
**SSL** — all from a single CLI.

.. code-block:: bash

   pip install net-benchmark
   pip install net-benchmark[pdf]   # with PDF export

.. note::
   **net-benchmark** is the successor to
   `dns-benchmark-tool <https://github.com/net-benchmark/dns-benchmark-tool>`_.
   The ``dns-benchmark`` command still works as a backward-compatible alias.

----

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   guides/installation
   guides/quickstart
   guides/first-run

.. toctree::
   :maxdepth: 2
   :caption: DNS Benchmark

   guides/dns-benchmark
   guides/dns-security-encrypted
   guides/dns-advanced
   guides/dns-use-cases
   guides/dns-utilities

.. toctree::
   :maxdepth: 2
   :caption: HTTP Benchmark

   guides/http-benchmark
   guides/http-security-auth
   guides/http-use-cases
   guides/http-exports
   guides/http-load-test

.. toctree::
   :maxdepth: 1
   :caption: SSL Check

   guides/ssl-check

.. toctree::
   :maxdepth: 2
   :caption: Export & Configuration

   guides/export-formats
   guides/configuration-files
   guides/automation-ci

.. toctree::
   :maxdepth: 2
   :caption: Reference

   reference/cli-dns
   reference/cli-http
   reference/resolvers
   reference/domains
   reference/best-practices
   reference/faq

.. toctree::
   :maxdepth: 1
   :caption: API Docs

   api/modules

.. toctree::
   :maxdepth: 1
   :caption: 中文文档 (Chinese)

   zh/index

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
   contributing
   security


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
