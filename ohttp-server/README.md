# Test Server

Note: you will need to set `[DY]LD_LIBRARY_PATH` as noted in the top-level
readme or these won't run.

In order to run this as a test server with a dummy name, you need to generate a
certificate. `rustls` is very particular, so this needs to be right. You'll
need the `openssl` utility for this.

```sh
./ohttp-server/ca.sh
```

You can pass this a domain name if you like, but it uses `localhost` by
default, which is usually OK for testing.

This will create keys and certificates in the right places for the server to
find them without you passing any arguments to it.

```sh
cargo run --bin ohttp-server
```

This will listen on `127.0.0.1` port 9443 by default. The client chokes on IPv6
addresses in URLs, so don't bother with those (thanks `hyper`). The server only
serves responses to `POST` requests at a path of `/`; anything else gets 406 or
404 status codes in response.

When it starts up the server prints a single line like this:

```
Config: 000020dee0e3602cf94dc19d9e1a7bcaa508044355a0635e127dcb8473b58641c5671a002000080001000100010003
```

This is needed by the client, see below.

# Using the Client

The client takes two arguments:

1. the URL of the server (ideally, this is a proxy that will forward requests
   to the server, but in testing, you can go directly and forego privacy)

2. the server configuration (this is the string the server printed out above),
   encoded in hexadecimal

```
cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/' -i ./examples/request.txt \
  000020dee0e3602cf94dc19d9e1a7bcaa508044355a0635e127dcb8473b58641c5671a002000080001000100010003
```

The client needs to be told about the CA file that the script above created or
it will refuse to connect. Run the client with the `--trust` option pointing at
the CA file created above, as shown here.

If you provide the wrong configuration to the client, the server will response
with a 422 response if the keys are bad, 400 otherwise.

