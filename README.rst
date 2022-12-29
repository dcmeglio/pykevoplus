=============
aiokevoplus
=============

This started as a fork of https://github.com/Bahnburner/pykevoplus but at this point is pretty much a rewrite.

This library has been converted to be compatible with asyncio and also to use the latest version of the Kevo API including support for
realtime updates via websockets.

Usage
=====

.. code:: python

    from aiokevoplus import KevoApi

    def status_changed(lock):
        print("Status changed for " + lock.name)

    api = KevoApi()
    try:
        await api.login("username@email.com", "password123")
        api.register_callback(status_changed)
        await api.websocket_connect()
        locks = api.get_locks()
        for lock in locks:
            lock.lock()
    except Exception as e:
        print("Something went wrong " + e)

