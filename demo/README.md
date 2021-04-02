# Threshold BLS over Signal

This little program (2 files, <500 lines) demonstrates how to use mpc-over-signal to achieve
secure transport with a small setup. It uses [multi-party-bls] crate providing threshold BLS
keygen & signing implementation.

[multi-party-bls]: https://github.com/ZenGo-X/multi-party-bls

## Watch the video

Demo record is available [here](https://user-images.githubusercontent.com/14890036/113412748-489c6380-93e3-11eb-8d1f-78aea0c21b0d.mp4).

## Build a program

It requires [Rust](https://www.rust-lang.org) to be installed. This project uses Rust Nightly
1.49.0, the toolchain will be selected automatically by `cargo`.

```shell
cargo build --release 
cp ../target/release/demo .
```

## Link with Signal account

```shell
./demo login
```

This command will prompt you a QR code which you need to scan with Signal app
on your phone. After scanning, it'll create a new MPC device and link it with your 
account. Device will be used to send and receive messages from other parties. It
will be displayed in "Linked devices" on your phone and can be unlinked at any time.

## Distribute your identity

Before parties can talk with each other, they need to know others' identities. Local
party identity can be observed by typing:

```shell
./demo me --json
```

You need to concatenate the output of this command from every party and save it
in `group.json`. E.g. content of `group.json` could be:

```text
{"addr":"5a7748e9-bf29-4418-9a11-13c079b7e3e2.2","public_key":"lzqcZv5v6aHAXLvOPDv51BRCkVdpVin1+H2ANhF6pmw="}
{"addr":"043c06ed-00b9-462a-8269-19b1da1c47f9.2","public_key":"TXO6eJZRd0wjINmjZw765F85mEelDRFKvqscZFjak0k="}
```

Order of those lines doesn't matter. Distribute this file between the parties.

## Keygen

```shell
./demo keygen -t 1 -n 2 --group group.json -o local-key.json
```

This will run distributed key generation with threshold parameter t=1 between n=2 parties
(t+1 parties will be required to perform signing).

Resulting local share will be saved to `local-key.json`. Resulted public key will be printed
to stdout, e.g.:

```text
Public key: a0c2e574f772eafe0829986bcc36b02423d1419367bf3b920968ad89ac0469689db44c9e84be467d2ac483b0c27b04e70269e76a59746818937cbb70b7a0c5de5bce5f300ed1b4105f18c53ef8c288ec5deb78539d9a2680d3eaf6f2d0c28155
```

## Sign

```shell
./demo sign --local-key local-key.json --group group.json --digits hello
```

Run signing between parties listed in group.json, message to sign is "hello". It
will produce resulting signature to stdout, e.g.:

```text
Signature: b46c3db8f2288fc202a6d8bd2ab0c555844ca1e0e94dd3783d6f3b69dd00a4bb4bca8a9dbd34d32fc3bd813e779b14ff
```

## Verify

You can check if signature matches its public key by typing:

```shell
./demo verify --public-key a0c2e574f772eafe0829986bcc36b02423d1419367bf3b920968ad89ac0469689db44c9e84be467d2ac483b0c27b04e70269e76a59746818937cbb70b7a0c5de5bce5f300ed1b4105f18c53ef8c288ec5deb78539d9a2680d3eaf6f2d0c28155 \
    --signature b46c3db8f2288fc202a6d8bd2ab0c555844ca1e0e94dd3783d6f3b69dd00a4bb4bca8a9dbd34d32fc3bd813e779b14ff \
    --digits hello
```

On success, it outputs a message:

```text
Signature is valid
```

## Self-hosted Signal Server

In order to work with self-hosted Signal Server, address and CA certificate must be set by
specifying `--signal-host` and `--signal-cert` options, e.g.:

```shell
./demo login --signal-host https://localhost:1234/ --signal-cert path/to/cert.pem
```
