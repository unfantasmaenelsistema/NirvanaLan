#!/usr/bin/env bash
# Genera la demo estática para GitHub Pages en _site/:
# la misma interfaz que sirve Flask + demo.js, que sustituye la API por una red ficticia.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf _site
mkdir -p _site
cp -r static _site/static
sed 's#<!-- NIRVANA_DEMO -->#<script src="static/js/demo.js"></script>#' templates/index.html > _site/index.html
grep -q 'static/js/demo.js' _site/index.html || { echo "No se pudo inyectar demo.js" >&2; exit 1; }
touch _site/.nojekyll
echo "Demo generada en _site/"
