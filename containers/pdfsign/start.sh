#!/usr/bin/env bash

set -e
set -x

python3 -mvenv /opt/sunet/pkcs11
/opt/sunet/pkcs11/bin/pip install --upgrade pip wheel
/opt/sunet/pkcs11/bin/pip install --index-url https://pypi.sunet.se/simple -r /opt/sunet/pkcs11/requirements.txt

ls -l /opt/sunet/pkcs11/bin/

. /opt/sunet/pkcs11/bin/activate

ls -hal /var/log/sunet
ls -hal /opt/sunet/pkcs11


app_entrypoint="pkcs11_ca_service.pdf.run:api"
app_name="pdfsign"
base_dir="/opt/sunet/pkcs11"
project_dir="${base_dir}/pdfsign/src"
#app_dir="${project_dir}/${app_name}"
#cfg_dir="${base_dir}/etc"
#extra_sources_dir=${extra_sources_dir-"${base_dir}/sources"}
# These *can* be set from Puppet, but are less expected to...
log_dir="/var/log/sunet"
state_dir="${base_dir}/run"
workers="4"
worker_class="sync"
worker_threads="1"
worker_timeout="30"

test -d "${log_dir}" && chown -R sunet: "${log_dir}"
test -d "${state_dir}" && chown -R sunet: "${state_dir}"

# set PYTHONPATH if it is not already set using Docker environment
export PYTHONPATH=${PYTHONPATH-${project_dir}}
echo "PYTHONPATH=${PYTHONPATH}"

exec start-stop-daemon --start -c sunet:sunet --exec \
     /opt/sunet/pkcs11/bin/gunicorn \
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