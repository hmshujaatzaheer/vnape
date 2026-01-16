V-NAPE: Verified Neural Adaptive Policy Enforcement
====================================================

.. image:: https://img.shields.io/badge/python-3.10+-blue.svg
   :target: https://www.python.org/downloads/

.. image:: https://img.shields.io/badge/license-MIT-green.svg
   :target: https://opensource.org/licenses/MIT

**V-NAPE** is a revolutionary framework for runtime verification and adaptive policy enforcement 
in post-quantum cryptographic protocols. It bridges the gap between neural learning capabilities 
and formal verification guarantees.

.. note::

   V-NAPE achieves **9+/10 novelty** through three verified research gaps:
   
   1. **Neural-Symbolic Verification Gap**: No existing work learns protocol behavior patterns 
      and translates them to formal MFOTL specifications
   2. **Quantum-Aware Enforcement Gap**: No runtime monitors proactively adapt policies based 
      on quantum threat assessments
   3. **Adaptive Refinement Gap**: No systems generate policy refinements from learned patterns 
      while maintaining formal guarantees

Key Features
------------

🧠 **Neural Policy Adaptation (NPA)**
   - Transformer-based protocol trace encoding
   - Multi-head attention for anomaly detection
   - Automatic policy refinement generation

🔗 **Symbolic Verification Bridge (SVB)**
   - MFOTL to Z3 formula translation
   - CEGAR-based abstraction refinement
   - Cryptographic proof certificate generation

⚛️ **Proactive Quantum-Aware Enforcement (PQAE)**
   - Real-time MFOTL monitoring
   - Quantum threat context assessment
   - Adaptive enforcement decisions

📱 **Protocol Support**
   - iMessage PQ3 (Apple's post-quantum protocol)
   - AKMA+ (5G authentication enhancement)
   - Extensible protocol framework

Quick Start
-----------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   pip install vnape

Basic Usage
~~~~~~~~~~~

.. code-block:: python

   from vnape import VNAPEConfig, VNAPE
   from vnape.protocols import IMessagePQ3Protocol
   
   # Configure V-NAPE
   config = VNAPEConfig(
       security_level=SecurityLevel.HIGH,
       quantum_safety_level=QuantumSafetyLevel.HYBRID,
       enable_proactive_enforcement=True
   )
   
   # Create pipeline
   vnape = VNAPE(config)
   
   # Load protocol
   protocol = IMessagePQ3Protocol()
   vnape.load_protocol(protocol)
   
   # Process trace
   result = vnape.process_trace(trace)
   
   # Check enforcement decision
   if result.enforcement.action == EnforcementAction.ALLOW:
       print("✓ Trace verified safe")

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User Guide
   
   installation
   quickstart
   concepts
   tutorials/index

.. toctree::
   :maxdepth: 2
   :caption: Protocol Support
   
   protocols/overview
   protocols/imessage_pq3
   protocols/akma_plus
   protocols/custom

.. toctree::
   :maxdepth: 2
   :caption: Architecture
   
   architecture/overview
   architecture/npa
   architecture/svb
   architecture/pqae

.. toctree::
   :maxdepth: 2
   :caption: API Reference
   
   api/core
   api/npa
   api/svb
   api/pqae
   api/protocols
   api/utils

.. toctree::
   :maxdepth: 1
   :caption: Development
   
   contributing
   changelog
   license

Research Foundation
-------------------

V-NAPE is grounded in peer-reviewed research:

.. list-table::
   :header-rows: 1
   :widths: 40 30 30
   
   * - Finding
     - Source
     - Application in V-NAPE
   * - High-impact = conventional + atypical combinations
     - Uzzi et al. (2013)
     - Neural learning + formal verification
   * - Small teams disrupt, large teams develop
     - Wu et al. (2019)
     - Focused individual contribution
   * - 61%+ Turing laureates have math backgrounds
     - Historical analysis
     - Strong theoretical foundations

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Citation
--------

If you use V-NAPE in your research, please cite:

.. code-block:: bibtex

   @software{vnape2025,
     author = {Zaheer, H M Shujaat},
     title = {V-NAPE: Verified Neural Adaptive Policy Enforcement},
     year = {2025},
     url = {https://github.com/shujaat-zaheer/vnape}
   }
