encrypt-cloud-image
===================

encrypt-cloud-image provides tooling for provisioning cloud images for use in
confidential VMs.

It provides functionality for integrity protecting the rootfs of a given image
using dm-verity, encrypting the rootfs and binding the decryption process to
a specific TPM using a profile which describes the state that the system must
be in in order to decrypt the key.

This is meant to be used either as part of a CVM provisioning pipeline by
a cloud provider or to locally produce pre-encrypted golden images so that
they can be deployed directly to the cloud.

---------

In this documentation
---------------------

..  grid:: 1 1 2 2

   ..  grid-item:: :doc:`Tutorials <tutorials/index>`

       **Start here**: a hands-on introduction to encrypt-cloud-image for new users

   ..  grid-item:: :doc:`How-to guides <howto/index>`

      **Step-by-step guides** covering key operations and common tasks

.. grid:: 1 1 2 2
   :reverse:

   .. grid-item:: :doc:`Reference <reference/index>`

      **Technical information** - specifications, APIs, architecture

   .. grid-item:: :doc:`Explanation <explanation/index>`

      **Discussion and clarification** of key topics

---------

Project and community
---------------------

encrypt-cloud-image is a member of the Ubuntu family. It’s an open source project that warmly welcomes community projects, contributions, suggestions, fixes and constructive feedback.

* Code of conduct
* Get support
* Join our online chat
* Contribute
* Roadmap
* Thinking about using encrypt-cloud-image for your next project? Get in touch!


.. toctree::
   :hidden:
   :maxdepth: 2

   self
   /tutorials/index
   /howto/index
   /reference/index
   /explanation/index
