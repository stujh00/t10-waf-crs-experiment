#!/usr/bin/env bash
# Dedicated Ubuntu 24.04 lab only. Usage: bash bootstrap_ubuntu.sh PUBLIC_IP
set -euo pipefail
address="${1:?Pass the current public IPv4 address of this EC2 instance}"
python3 - "$address" <<'PY'
import ipaddress,sys
assert ipaddress.ip_address(sys.argv[1]).version == 4
PY
base="$(cd "$(dirname "$0")/.." && pwd)"
source_config="$base/original/evidence/after-main"
test -f "$source_config/pl1.conf"
python3 "$base/reproduction/fetch_crs.py" "$source_config"
# Match the recorded 2 GiB swap provision on a low-memory dedicated VM.
if test "$(awk '/MemTotal/{print $2}' /proc/meminfo)" -lt 2000000 && test "$(awk '/SwapTotal/{print $2}' /proc/meminfo)" -eq 0; then
    test ! -e /swap-t10
    test "$(df --output=avail -B1 / | tail -1)" -gt 3221225472
    sudo fallocate -l 2G /swap-t10
    sudo chmod 600 /swap-t10
    sudo mkswap /swap-t10
    sudo swapon /swap-t10
fi
sudo apt-get update
sudo apt-get install -y nginx libmodsecurity3t64 libnginx-mod-http-modsecurity python3 curl openssl
sudo install -d /etc/nginx/t10/crs /etc/nginx/t10/tls /var/www/t10
sudo cp -r "$source_config/rules" /etc/nginx/t10/crs/
sudo cp "$source_config/crs-setup.conf.example" /etc/nginx/t10/crs/
for pl in 1 2 3; do
    sudo cp "$source_config/pl$pl.conf" "/etc/nginx/t10/pl$pl.conf"
done
sudo openssl req -x509 -nodes -newkey rsa:2048 -days 90 \
    -keyout /etc/nginx/t10/tls/server.key -out /etc/nginx/t10/tls/server.crt \
    -subj "/CN=$address" -addext "subjectAltName=IP:$address"
sudo chmod 600 /etc/nginx/t10/tls/server.key
sudo cp "$source_config/t10-public" /etc/nginx/sites-available/t10-public
sudo cp "$source_config/t10-loopback.conf" /etc/nginx/conf.d/t10-loopback.conf
sudo cp "$base/reproduction/index.html" /var/www/t10/index.html
printf '%s\n' '<!doctype html><meta charset="utf-8"><h1>WAF blocked this request</h1>' | sudo tee /var/www/t10/blocked.html >/dev/null
# Remove only the default-site link on the dedicated lab server.
if test -L /etc/nginx/sites-enabled/default; then sudo unlink /etc/nginx/sites-enabled/default; fi
sudo ln -sfn /etc/nginx/sites-available/t10-public /etc/nginx/sites-enabled/t10-public
mkdir -p "$HOME/t10-waf/cases"
cp "$base/original/results/20261020T005958Z-ca99f72b/cases_main.json" "$HOME/t10-waf/cases/"
python3 - "$base" "$address" <<'PY'
import pathlib,sys
base=pathlib.Path(sys.argv[1]);address=sys.argv[2]
source=(base/'original/run_main.py').read_text()
old='address = "203.0.113.10"'
assert source.count(old)==1
path=pathlib.Path.home()/'t10-waf/run_main.py'
path.write_text(source.replace(old, 'address = '+repr(address)))
PY
sudo nginx -t
sudo systemctl restart nginx
python3 "$HOME/t10-waf/run_main.py" --check-only
printf '\nNew certificate and runner hashes will differ from the original experiment.\n'
printf 'Run main experiment: python3 ~/t10-waf/run_main.py --rounds 10\n'
