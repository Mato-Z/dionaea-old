log_json
========

This ihandler can submit information about attacks/connections encoded as json.

.. warning:: This ihandler is in pre alpha state and it might be changed or removed in the near future.

Configure
---------

Default configuration:

.. code-block:: text

    log_json = {
        handlers = [
            "http://127.0.0.1:8080/"
            "file:///tmp/dionaea.json"
        ]
    }

handlers

    List of URLs to submit the information to.
    At the moment only file, http and https are supported.

Format
------

Format of the connection information:

.. code-block:: JavaScript

    {
        "connection": {
            "local": {
                "address": "<string:local ip address>",
                "port": <integer:local port>,
            },
            "protocol": "<string:service name e.g. httpd>",
            "remote": {
                "address": "<string:remote ip address>",
                "port": <integer:remote port>,
                "hostname": "<string:hostname of the remote host>"
            },
            "transport": "<string:transport protocol e.g. tcp or udp>",
            "type": "<string:connection type e.g. accepted, listen, ...>"
        }
    }
