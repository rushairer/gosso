#!/bin/sh

# Run database migrations before starting the application.
# Exit code 0 from "migrate up" means migrations were applied.
# Exit code 1 with "no change" in output means DB is already up to date.
echo "Running database migrations..."
output=$(/app/gosso migrate up 2>&1) && rc=0 || rc=$?
echo "$output"

if [ "$rc" -eq 0 ]; then
    echo "Migrations applied successfully."
elif echo "$output" | grep -qi "no change"; then
    echo "Migrations: no change (already up to date)."
else
    echo "FATAL: Database migration failed (exit code $rc)."
    exit 1
fi

# Start the application, replacing this shell process.
exec /app/gosso "$@"
