ca:
	./ohttp-server/ca.sh

run: ca
	cargo run --bin ohttp-server -- --target http://127.0.0.1:5678

run-client:
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`

build:
	docker build -f docker/Dockerfile -t ohttp-server .
