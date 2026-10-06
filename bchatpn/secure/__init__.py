"""Secure mode. Imported only when it is switched on (`serve --secure`); normal mode never loads this package.

What it adds on top of the normal server, with the same single process and the same one dependency:
  1. signed /subscribe and /unsubscribe: only the owner of an account can register devices for it
  2. per-device encrypted pushes: Google sees an opaque blob, not the message envelope
  3. ids hashed and tokens encrypted in the database
  4. registrations expire unless renewed
  5. per-message log lines off by default
"""
