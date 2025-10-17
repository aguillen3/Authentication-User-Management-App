#!/usr/bin/env bash
set -e
ROOT=$(pwd)
# This script copies files to /var/www/auth-app and starts backend with pm2
TARGET=/var/www/auth-app
echo "Deploying to ${TARGET} (requires sudo)"
sudo mkdir -p ${TARGET}
sudo rsync -a --exclude node_modules --exclude dist ${ROOT}/ ${TARGET}/
cd ${TARGET}/backend
npm install --production
if ! command -v pm2 >/dev/null; then npm install -g pm2; fi
pm2 start server.js --name auth-backend --update-env
cd ${TARGET}/frontend
npm install --production
# build static (if Angular CLI present)
if command -v ng >/dev/null; then ng build --configuration production; fi
echo "Deployed. Configure nginx to serve frontend/dist and proxy /api to backend."
