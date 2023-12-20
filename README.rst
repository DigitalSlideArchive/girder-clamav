==============
ClamAV Scanner
==============

Stream new uploads through ClamAV to check for malware.

After any file is uploaded, if the ClamAV daemon can be reached, it is scanned to see if any security issues are found.  If so, the file is immediately deleted; this is shown as a notification to the Girder UI and logged.  The parent item is not removed.

Imported files are **NOT** checked.  They cannot be deleted from their source.

This expects that there is a ClamAV daemon running at a TCP port that can be accessed from Girder.

Settings
--------

These can be chanegd in Girder to modify the behavior of the plugin:

- ``clamav.host_and_port``: Set to the location of the clamavd tcp socket.  This defaults to 'clamav:3310'.
- ``clamav.maximum_scan_length``: Only the beginning of long files are checked.  This value must be no greater than the values configure in your ClamAV daemon.  The default is 64 MiB.
- ``clamav.connection_timeout``: The duration in seconds to wait for a response from the ClamAV daemon.  The default is 30 seconds.
- ``clamav.reponse_timeout``: The duration in seconds to wait for a response from the ClamAV daemon after sending it the data to check.  The default is 30 seconds.

Adding to the Digital Slide Archive
-----------------------------------

Add a ClamAV daemon to your ``docker-compose.yml`` file, such as:

.. code::

    services:
      clamav:
        image: clamav/clamav:stable

Install this plugin as part of the provisioning script.  This can be added to the ``provision.yaml`` file.  This plugin does not require rebuilding the client.

.. code::

    pip:
      - git+https://github.com/DigitalSlideArchive/girder-clamav

All Girder log messages from this plugin are at ``info`` or ``debug`` level and are prefixed with ``CLAMAV``.
