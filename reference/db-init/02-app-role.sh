#!/bin/sh
# Runs once when the Postgres volume is first created. Gives the app's
# limited role its password, so the app never connects as the superuser.
set -eu
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
ALTER ROLE assistant_app PASSWORD :'pw';
SQL
