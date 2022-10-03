ravl Documentation
=======================

RAVL is a library of remote attestation verification procedures that enables clients of confidential services to verify the remote attestation of the service.

An example of the most basic usage pattern is as follows:

.. literalinclude:: ../test/demo.cpp
    :language: cpp
    :start-after: SNIPPET_START: BASIC_USAGE
    :end-before: SNIPPET_END: BASIC_USAGE
    :dedent: 2

Generic Attestations
--------------------

.. doxygenclass:: ravl::Attestation
   :project: ravl
   :members:

Platform-specific Attestations
------------------------------

.. doxygenclass:: ravl::sgx::Attestation
   :project: ravl
   :members:

.. doxygenclass:: ravl::sev_snp::Attestation
   :project: ravl
   :members:

.. doxygenclass:: ravl::oe::Attestation
   :project: ravl
   :members:

Verification
------------

.. doxygenfunction:: ravl::verify_sync
   :project: ravl   

.. doxygenclass:: ravl::AttestationRequestTracker
   :project: ravl
   :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
