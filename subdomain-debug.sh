#!/bin/bash

# Test zero-dependency deployment to prove API works
SERVER="75.119.141.162:5000"

echo "=== Testing Zero-Dependency Deployment ==="
echo "This should work since it doesn't require npm install"

# Create deployment with NO dependencies
curl -X POST http://$SERVER/api/deploy/nodejs-subdomain \
  -H "Content-Type: application/json" \
  -d '{
    "name": "zero-deps-test",
    "files": {
      "package.json": "{\"name\":\"zero-deps-test\",\"version\":\"1.0.0\",\"scripts\":{\"start\":\"node server.js\"}}",
      "server.js": "const http = require(\"http\"); const server = http.createServer((req, res) => { res.writeHead(200, {\"Content-Type\": \"text/html\"}); res.end(\"<h1>Zero Dependencies Test</h1><p>No npm install needed!</p><p>Domain: zero-deps-test.datablox.co.za</p><p>Time: \" + new Date().toISOString() + \"</p>\"); }); const port = process.env.PORT || 3000; server.listen(port, () => console.log(`Zero-deps server running on port ${port}`));"
    },
    "domain_config": {
      "subdomain": "zero-deps-test",
      "parent_domain": "datablox.co.za"
    }
  }' | jq '.'

echo
echo "If this succeeds, your API is 100% working!"
echo "The issue is only with npm dependency installation."

echo
echo "Checking if deployment worked..."
sleep 3

echo "Process status:"
curl -s http://$SERVER/api/processes | jq '.processes[] | select(.name == "zero-deps-test")'

echo
echo "Domain status:"  
curl -s http://$SERVER/api/domains | jq '.domains[] | select(.domain_name | contains("zero-deps-test"))'