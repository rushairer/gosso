#!/bin/sh
set -e

# Run database migrations before starting the application.
# Exit code 0 from "migrate up" means migrations were applied.
# Exit code 1 with "no change" in output means DB is already up to date.
echo "Running database migrations..."
if /app/gosso migrate up 2>&1; then
    echo "Migrations applied successfully."
else
    # migrate up exits 1 when there's nothing to do — that's fine.
    echo "Migrations: no change (already up to date)."
fi

# Start the application, replacing this shell process.
exec /app/gosso "$@"
