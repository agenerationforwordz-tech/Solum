# SOLUM - Dashboard Account System (backend router)
# Selects the SQLite or PostgreSQL auth backend based on SOLUM_DB_BACKEND,
# exactly mirroring db.py. This keeps the SQLite path free of psycopg2:
# without this router the server imported the PostgreSQL auth module
# unconditionally, so a SQLite-only install (the documented demo quick-start)
# crashed at startup trying to connect to a PostgreSQL server that isn't there.
#
# Both backends expose identical public functions, so `import auth` in
# server.py works unchanged regardless of the selected backend.

import os

DB_BACKEND = os.environ.get("SOLUM_DB_BACKEND", "sqlite").lower()

if DB_BACKEND == "postgresql":
    from auth_pg import *  # noqa: F401,F403
else:
    from auth_sqlite import *  # noqa: F401,F403
