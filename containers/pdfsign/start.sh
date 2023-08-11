#!/usr/bin/env bash

set -e
set -x

python3 -mvenv /opt/sunet/venv
/opt/sunet/venv/bin/pip install --upgrade pip wheel
/opt/sunet/venv/bin/pip install --index-url https://pypi.sunet.se/simple -r /opt/sunet/requirements.txt

ls -hal /opt/sunet/venv/
ls -hal /opt/sunet/src
ls -hal /opt/sunet


. /opt/sunet/venv/bin/activate


app_entrypoint="pkcs11_ca_service.pdf.run:api"
app_name="pdfsign"
base_dir="/opt/sunet"
project_dir="${base_dir}/src"
log_dir="/var/log/sunet"
state_dir="${base_dir}/run"
workers="1"
worker_class="sync"
worker_threads="1"
worker_timeout="30"

test -d "${log_dir}" && chown -R sunet: "${log_dir}"
test -d "${state_dir}" && chown -R sunet: "${state_dir}"

# set PYTHONPATH if it is not already set using Docker environment
export PYTHONPATH=${PYTHONPATH-${project_dir}}
echo "PYTHONPATH=${PYTHONPATH}"

export PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}/opt/sunet/venv"

echo ""
echo "$0: Starting ${app_name}"

exec start-stop-daemon --start -c sunet:sunet --exec \
     /opt/sunet/venv/bin/gunicorn \
     --pidfile "${state_dir}/${app_name}.pid" \
     --user=sunet --group=sunet -- \
     --bind 0.0.0.0:8080 \
     --workers "${workers}" --worker-class "${worker_class}" \
     --threads "${worker_threads}" --timeout "${worker_timeout}" \
     --access-logfile "${log_dir}/${app_name}-access.log" \
     --error-logfile "${log_dir}/${app_name}-error.log" \
     --capture-output \
      -k uvicorn.workers.UvicornWorker \
     "${app_entrypoint}"