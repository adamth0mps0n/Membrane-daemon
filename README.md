# membrane-daemon

The customer-side daemon for [membrane-cloud][membrane], an MCP server
that gives AI assistants (Claude, ChatGPT) controlled, audited access
to your local files and shell.

The daemon is the local half of the system: it runs on your machine
under your user, holds an outbound QUIC tunnel to the cloud, and
responds to RPC calls from the cloud (read this file, list this
directory, run this command) under a policy *you* control.

[membrane]: https://mcp.membrane.informationpatterns.com

## Trust model

This is the half of the system that touches your files, so its
contents are open source. You can read every line that runs on your
machine.

* **Cloud talks, daemon decides.** The cloud can request operations,
  but every request is policy-checked locally before anything happens.
* **Workspace isolation.** The default policy is a single workspace
  root (e.g. `/home/you/Documents`); paths outside are rejected.
* **mTLS pinned.** The daemon pins the cloud's serving certificate by
  Blake3 hash, set at pair time. A MITM attempt drops the connection.
* **Audit log.** Every RPC the cloud makes — every file read, every
  command run — is appended to `~/.local/share/membrane-daemon/audit.log`.
  Inspect with `membrane-daemon audit`.
* **No phone-home, no telemetry, no analytics.** The daemon talks to
  exactly one address: the cloud you paired it with.

## Install (Linux x86_64)

```sh
curl -fsSL https://mcp.membrane.informationpatterns.com/install.sh \
    | sh -s -- --pair-token pair_xxxx
```

(Get the pair token from the **Agents** page in your membrane-cloud
account.)

The install script downloads this binary, verifies its Blake3 hash
against the cloud's manifest, pairs the daemon with your account, and
installs it as a systemd user service.

## Install (build from source — any platform)

```sh
git clone https://github.com/adamth0mps0n/Membrane-daemon.git
cd Membrane-daemon
cargo build --release -p membrane-daemon
./target/release/membrane-daemon pair \
    --enrol https://mcp.membrane.informationpatterns.com \
    --api-key pair_xxxx
./target/release/membrane-daemon install
```

The `install` subcommand writes a systemd user service (Linux),
launchd plist (macOS), or Windows Service definition.

## CLI

```
membrane-daemon run         start the daemon and connect to the cloud (default)
membrane-daemon status      show config and policy
membrane-daemon mode        change policy mode (Workspace / ReadOnly / Off)
membrane-daemon audit       inspect the audit log
membrane-daemon pair        pair the daemon with the cloud
membrane-daemon install     install as an OS service
membrane-daemon uninstall   remove the OS service
membrane-daemon start|stop  start/stop the OS service
```

## What the daemon does NOT do

The daemon is *only* a local-side RPC server. It does not contain or
implement:

* The pattern substrate, R-formula, or any of membrane's storage /
  inference logic (all lives in the cloud).
* Any user data — it streams files on demand, doesn't cache them.
* Any AI model — it just talks to whatever client opens an MCP
  session with the cloud.

The full transitive dependency tree contains exactly one
crate from this repo (`membrane-wire`, the RPC type definitions) and
otherwise only open-source crates: tokio, quinn, rustls, ring, clap,
serde, blake3, etc.

## License

Apache-2.0. See LICENSE.
