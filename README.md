# MPC over Signal

## Overview

This library provides a high-level interface for connecting to Signal Server and using it to 
exchange messages with other connected nodes (parties). Together with [round_based] crate, it 
allows you running any MPC protocol that implements [round_based::StateMachine][SM] 
over secure transport backed by Signal.

[round_based]: https://docs.rs/round-based
[SM]: https://docs.rs/round-based/*/round_based/trait.StateMachine.html

Here is a [demo] showing how to use this library to run [threshold BLS](https://github.com/ZenGo-X/multi-party-bls) keygen & signing. For more details read our [blog](https://medium.com/zengo/mpc-over-signal-977db599de66) as well. 

[demo]: ./demo

### Self-hosted Signal Server

In order to be more confident in the server and to reduce the load on the original Signal Server, 
better option would be using self hosted Signal Server. The [Signal Server][signal-server] code is open source 
and there are unofficial instructions on deploying it ([here][deploy1], [here][deploy2]).
This library is designed to work with any Signal-compatible API.

[signal-server]: https://github.com/signalapp/Signal-Server
[deploy1]: https://github.com/aqnouch/Signal-Setup-Guide/tree/master/signal-server
[deploy2]: https://github.com/madeindra/signal-setup-guide

## How to use it

### Construct SignalClient

It is first required to specify how to reach the Signal Server. If using the Signal messenger Server, then the default settings are enough:

```rust
let client = SignalClient::new()?;
```

In case of self-hosted Signal Server, address and CA certificate must be set:
```rust
let mut root_certs = rustls::RootCertStore::empty();
root_certs
    .add_pem_file(&mut &include_bytes!("path/to/certificate.pem")[..])?;

let mut tls_config = rustls::ClientConfig::new();
tls_config.root_store = root_certs;

let client = awc::Client::builder()
    .connector(
        awc::Connector::new()
            .rustls(tls_config.into())
            .finish())
    .finish();

let mut builder = SignalClient::builder()?;
builder
    .set_server_host("https://localhost:1234/")?
    .set_http_client(client);
let client = builder.finish();
```

### Link with Signal account

To communicate through Signal, obviously you need to have a Signal account. This library
can only link with existing accounts, creating a new one is out of scope. Process
of linking is the same as logging in to Signal Desktop: it is done by scanning the QR code with
a mobile app.

```rust
use futures::channel::oneshot;
use rand::rngs::OsRng;

let (provision_url_tx, provision_url) = oneshot::channel();
let device_future = signal_client
    .login(&mut OsRng, provision_url_tx, "MPC device");
```

Method `login` takes oneshot channel and fires it when it got a provision URL.
Provision URL should be rendered as QR code and scanned with a phone (linked device). After
it has been scanned, `device_future` completes, and you can obtain your `Device`:

```rust
let device: Device = device_future.await?;
```

### Distribute Public Identities

Before the parties can talk with each other, they need to know all counter parties identities.

Obtain a local party's identity:

```rust
let me: ParticipantIdentity = device.me();
```

Distribute it among group of parties you want to communicate with and receive their 
identities. Then construct a group that will run an MPC protocol:

```rust
// Order doesn't matter. It must include local party's identity too.
let group = Group::new(vec![me, party2, party3]); 
```

### Start messaging

To construct a stream of incoming messages and sink for outgoing messages, call this:

```rust
let device = DeviceStore::new(device);

let mut binded_client = signal_client
    .start_listening_for_incoming_messages(device)
    .await?;
let (incoming, outgoing) = binded_client.join_computation(me.addr, group);
```

Now incoming and outgoing can be used to send or receive messages. Transmitting messages
have type [`round_based::Msg<T>`][msg] where `T` is any type implementing serde's Serialize
and Deserialize traits.

To run an MPC protocol that implements [round_based::StateMachine][SM], use 
[round_based::AsyncProtocol][async-protocol]. See [demo] sources for details.

[msg]: https://docs.rs/round-based/*/round_based/struct.Msg.html
[async-protocol]: https://docs.rs/round-based/*/round_based/async_runtime/struct.AsyncProtocol.html

## Supported Rust version

The only supported version is Rust Nightly 1.49.0. This is a limitation of 
[libsignal-protocol crate][libsignal].

[libsignal]: https://github.com/signalapp/libsignal-client

## License

MPC-over-Signal is released under the terms of the AGPLv3 license. See [LICENSE](./LICENSE) for more 
information.

## Development Process & Contact
This library is maintained by ZenGo-X. Contributions are highly welcomed! Besides GitHub issues
and PRs, feel free to [reach out](mailto:github@kzencorp.com) by mail or join ZenGo X
[Telegram](https://t.me/joinchat/ET1mddGXRoyCxZ-7) for discussions on code and research. 
