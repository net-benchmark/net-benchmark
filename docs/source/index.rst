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

.. image:: https://github.com/net-benchmark/net-benchmark/actions/workflows/test.yml/badge.svg
   :target: https://github.com/net-benchmark/net-benchmark/actions/workflows/test.yml
   :alt: Tests

.. image:: https://github.com/net-benchmark/net-benchmark/actions/workflows/docker.yml/badge.svg
   :target: https://github.com/net-benchmark/net-benchmark/actions/workflows/docker.yml
   :alt: Docker

.. image:: https://pepy.tech/badge/net-benchmark
   :target: https://pepy.tech/project/net-benchmark
   :alt: Downloads

.. image:: https://img.shields.io/docker/pulls/joeovo/net-benchmark.svg
   :target: https://hub.docker.com/r/joeovo/net-benchmark
   :alt: Docker Pulls

.. image:: https://img.shields.io/docker/v/joeovo/net-benchmark.svg
   :target: https://hub.docker.com/r/joeovo/net-benchmark
   :alt: Docker Image Version

----

**net-benchmark** is a fast, extensible network benchmarking suite for **DNS**, **HTTP**, and
**SSL** — all from a single CLI.

.. code-block:: bash

   pip install net-benchmark
   pip install net-benchmark[pdf]   # with PDF export

Also available as a Docker image (``joeovo/net-benchmark``, ``ghcr.io/net-benchmark/net-benchmark``)
and via Homebrew (``brew tap net-benchmark/net-benchmark``) — see :doc:`guides/installation`.

.. note::
   **net-benchmark** is the successor to
   `dns-benchmark-tool <https://github.com/net-benchmark/dns-benchmark-tool>`_.
   The ``dns-benchmark`` command still works as a backward-compatible alias.
