.. net-benchmark — documentazione in italiano
..
.. Struttura piatta, come docs/source/zh/. Le pagine coprono un sottoinsieme
.. delle guide inglesi; il riferimento completo resta la documentazione in
.. inglese.

Documentazione in italiano
==========================

**net-benchmark** è una suite di benchmarking di rete veloce ed estensibile per
**DNS**, **HTTP** e **SSL** — il tutto da un'unica CLI.

.. code-block:: bash

   pip install net-benchmark
   pip install net-benchmark[pdf]   # con esportazione PDF

.. note::
   Questa traduzione copre un sottoinsieme della documentazione. La
   documentazione di riferimento completa è quella in inglese: in caso di
   discrepanza fa fede :doc:`la versione inglese </index>`.

----

.. toctree::
   :maxdepth: 2
   :caption: Per iniziare

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: Benchmark

   dns-benchmark
   http-benchmark
   http-load-test

.. toctree::
   :maxdepth: 2
   :caption: Esportazione

   export-formats
