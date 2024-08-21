TARGET ?= http://127.0.0.1:3000
INPUT ?= ./examples/request.txt

ca:
	./ohttp-server/ca.sh

build-whisper:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-server:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-streaming:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-streaming build-whisper

run-client-kms: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ${INPUT} \
  --kms-config ./keys.json --kms-cert ./service_cert.pem 

run-client-local: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ${INPUT} \
  --config `curl -s -k https://localhost:9443/discover`

run-server-streaming:
	docker compose -f ./docker/docker-compose-streaming.yml up

run-server-whisper:
	docker compose -f ./docker/docker-compose-whisper.yml up