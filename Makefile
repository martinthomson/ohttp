TARGET ?= http://127.0.0.1:3000

ca:
	./ohttp-server/ca.sh

run-client: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`

build-server:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-target:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-target

run-server:
	docker compose -f ./docker/docker-compose-streaming.yml up