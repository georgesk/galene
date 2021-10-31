LDAP authentication for Galene
==============================

This program is based on concepts filed at
https://lists.galene.org/galene/87tugzwezl.wl-jch@irif.fr

The programm `auth.py` implements a web server which listens at
port 1234, accepts JSON-encoded posts with user data (typically
username and password), and replies with a signed token which
contains user's data, checked agains a LDAP server.

Properties of the LDAP server must be defined in a file `credentials.py`,
which must live somewhere in the paths considered by Python. An example
of such a file is provided in `credentials.template`.

The program `test_authentication.py` allows one to check the service
provided by `auth.py` easily.
