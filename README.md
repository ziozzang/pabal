# Pabal

A small native SMTP relay and local mail test server written in Go, with a built-in administration UI. Start in **discard mode** to inspect application SMTP traffic without sending email. Relay mode forwards synchronously to configured SMTP providers.

Pabal includes source-IP allow/deny rules, envelope sender restrictions, recipient address/domain allow/deny policies, recipient-domain routing, STARTTLS or implicit-TLS upstream connections, environment-based authentication, client aliases/categories/notes, delivery events and administration change history. It runs as one binary; a container is optional.

## Build and test

Use the Go version declared in `go.mod` or a compatible newer version.

```sh
go build -trimpath -o pabal .
go test -race ./...
go vet ./...
```

The repository examples use loopback listeners: SMTP `127.0.0.1:12525` and administration HTTP `127.0.0.1:16882`. `examples/discard.json` needs no upstream account. Point a local application's SMTP client at the SMTP listener; discarded messages are accepted for testing but are never delivered externally. Start with:

```sh
./pabal -config examples/discard.json -state-dir ./state
```

Use `-check` to validate configuration without starting listeners. With no config file, startup defaults are loopback listeners and discard mode. Run `./pabal -help` for command options.

The administration UI is intended for an internal HTTP deployment. Client access is controlled independently from administration access. Configuration changes require CSRF validation. Runtime state, generated session secrets and envelope history are private local data and are excluded from version control.

## Configuration

Configuration is JSON; unknown fields are rejected. See [the complete discard example](examples/discard.json) and provider examples below.

| Field | Behavior |
|---|---|
| `mode` | `discard` for local testing or `relay` for synchronous forwarding. |
| `access.allow_cidrs`, `access.deny_cidrs` | SMTP client addresses; deny takes precedence. At least one allowed network is required. Catch-all `/0` networks are rejected. |
| `admin_allow_cidrs` | Separate administration network restriction. |
| `allowed_senders` | Optional exact envelope sender restrictions. |
| `targets.allow`, `targets.deny` | Exact recipients or `@example.com` domain patterns; deny takes precedence. Empty allow list permits recipients that are not denied. |
| `targets.denied_action` | `reject` or intentional `discard` for denied recipients. Discard does not mean delivery. |
| `upstreams` | Named SMTP endpoints with TLS mode and authentication environment-variable references. |
| `routes`, `default_upstream` | Route by recipient domain, with an optional default provider. |
| `limits` | Message size, recipient count, concurrent connections and timeout bounds. |

Recipient domains are case-insensitive; exact mailbox local parts are case-sensitive. IP access normalizes IPv4-mapped IPv6 client addresses. Prefer narrow source networks when adapting the loopback examples to a LAN. SMTP clients rely on network access policy; provider authentication is outbound. Policy changes apply at the next MAIL transaction, including existing connections; an already accepted transaction retains its policy snapshot. The client registry switches between Block IP and Unblock IP for exact deny rules. A broader network deny is managed in relay settings and is never removed by an individual unblock action.

### Providers

Examples contain placeholder addresses and environment-variable **names**, never account passwords. Supply values through your local service environment or secret manager and adapt the sender and recipient placeholders before using relay mode.

| Example | Endpoint / TLS | Authentication values |
|---|---|---|
| [Gmail](examples/gmail.json) | `smtp.gmail.com:587`, `starttls` | `GMAIL_USERNAME`: full account address; `GMAIL_SMTP_PASSWORD`: an eligible app password. See [Google's SMTP settings](https://support.google.com/mail/answer/7104828?hl=en). |
| [Amazon SES](examples/ses.json) | `email-smtp.us-east-1.amazonaws.com:587`, `starttls`; select your region | `SES_SMTP_USERNAME` and `SES_SMTP_PASSWORD`: region-specific SES SMTP credentials, which differ from AWS access keys. Use a verified sender identity. See [SES SMTP requirements](https://docs.aws.amazon.com/ses/latest/dg/send-email-smtp.html). |
| [SendGrid](examples/sendgrid.json) | `smtp.sendgrid.net:587`, `starttls` | `SENDGRID_USERNAME`: the literal `apikey`; `SENDGRID_SMTP_PASSWORD`: your API key. See [SendGrid's SMTP integration](https://www.twilio.com/docs/sendgrid/for-developers/sending-email/integrating-with-the-smtp-api). |
| [Custom SMTP](examples/custom.json) | Replace `smtp.example.com:587` | Set `CUSTOM_SMTP_USERNAME` and `CUSTOM_SMTP_PASSWORD` to your provider's credentials. |

`tls: "starttls"` requires a successful STARTTLS upgrade; `tls: "tls"` connects with implicit TLS, commonly on port 465. Plaintext upstream mode is allowed only for a literal loopback address with `auth.type: "none"`. TLS certificates are verified. SES supports STARTTLS and implicit TLS; see [AWS security protocols](https://docs.aws.amazon.com/ses/latest/dg/security-protocols.html).

Authentication types are `none`, `plain`, `login` and `oauth2`. Password authentication references `username_env` and `password_env`. OAuth2 uses XOAUTH2 with `username_env` and `token_env`; supply an existing access token. Pabal does not obtain or refresh OAuth tokens. Credential changes must reach the running process environment, normally by restarting the service with updated secrets.

## Install as a native service

Use the [systemd unit example](deploy/pabal.service) with a dedicated `pabal` system account. On a system using `useradd`:

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin pabal
sudo install -m 0755 pabal /usr/local/bin/pabal
sudo install -d -m 0750 /etc/pabal
sudo install -m 0644 examples/discard.json /etc/pabal/config.json
sudo install -m 0644 deploy/pabal.service /etc/systemd/system/pabal.service
sudo systemctl daemon-reload
sudo systemctl enable --now pabal.service
```

The example starts in discard mode on loopback. systemd creates `/var/lib/pabal` for private runtime state using `StateDirectory=pabal`. Adapt listening addresses and access policies in `/etc/pabal/config.json` before enabling LAN access. If the account already exists, reuse it rather than running `useradd` again.

For relay mode, provide the environment variables referenced by your selected provider through the optional local `/etc/pabal/credentials.env`. Keep this file root-owned with mode `0600`, outside version control. `EnvironmentFile` reads it for the service; no credentials file is needed in discard mode. Restart the service after changing process credentials or startup-only settings. Saved UI policy persists across restarts and overrides matching startup policy fields.

## Delivery semantics and history

Pabal is a synchronous relay with **no durable outgoing message queue or retry worker**. Upstream acceptance means the upstream accepted the SMTP transaction, not that the final inbox received the message. A temporary forwarding failure is returned to the sending application, which must implement retries. A single SMTP transaction cannot span different upstreams: a recipient requiring a different provider is rejected at RCPT with SMTP 550. Send separate transactions for separate providers and check every RCPT response; an SMTP client can continue with previously accepted recipients after another recipient is rejected. Use a queueing MTA when durable retry and stronger delivery coordination are required.

Message bodies and authentication secrets are not retained. Events contain envelope/connection metadata and fixed outcomes. Recent history is bounded: up to 10,000 events are loaded for viewing, with a rotating local journal; administration changes retain the latest 1,000 entries. Client labels are grouped by source IP, so NAT and shared addresses can represent multiple machines. This is an operational test/relay history, not a mailbox or inbox viewer.

Local state persists UI settings and labels across restarts. Saved policy overrides the startup file on restart, while listening addresses, domain and resource limits remain startup settings. Keep it separate from source files. For a native service, run the binary as a dedicated account with write access only to its state directory and read access to the selected configuration; provide authentication environment values through your service manager.

MIT licensed. [한국어 안내](docs/README.ko.md).
