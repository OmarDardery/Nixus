# Cloudflare Tunnel

For a remotely managed tunnel, Cloudflare owns public hostnames and origin
routes. Nixus runs the official cloudflared container and supplies the tunnel
secret. No local tunnel JSON, login certificate, router port forward, dedicated
LAN IP or extra reverse proxy is required for a sidecar in the same app.

## Run the connector beside the app

Add a service to the app's existing Compose file:

```yaml
services:
  cloudflared:
    image: cloudflare/cloudflared:2026.5.2 # Pin image digests before deployment.
    command: ["tunnel", "--no-autoupdate", "--metrics", "0.0.0.0:2000", "run"]
    restart: unless-stopped
```

Use a current supported cloudflared version; `2026.5.2` is the minimum for the
built-in connectivity prechecks described below. In **Environment Variables**,
set `TUNNEL_TOKEN` to just the token from this tunnel's Cloudflare installation
command. Enter it before the first deploy. Keep it out of Compose source,
Dockerfile layers, command arguments, Git and troubleshooting transcripts.
Nixus injects saved app variables when it creates the instances. Treat the whole app as a trusted boundary: the current Compose startup
override supplies app variables to every service. File-delivery bindings alone
do not restrict this startup environment.

Set the tunnel's application route in the Cloudflare dashboard to, for example,
`http://aiostreams:3000` when `aiostreams` is the web service in the **same app**.
Use the application's internal listening port. `localhost` inside cloudflared
is the connector container itself. A connector in another isolated app cannot
resolve/reach this origin without an explicit networking design.

Do not publish port 2000 or attach the connector to the LAN merely to make the
tunnel connect. The metrics/readiness endpoint belongs on the private app
network. Incus restart settings are provided, but Nixus currently disables
incus-compose's health daemon; Docker-style continuous health/restart semantics
are not fully provided by the deployment's short Running-state check.

## Diagnose a disconnected tunnel

Start with **Apps → app → Logs**, selecting cloudflared. On the host, if the
service/instance is named `cloudflared` and the Incus project is `aiostreams`:

```sh
sudo incus list --project aiostreams
sudo incus console cloudflared --project aiostreams --show-log
sudo incus exec cloudflared --project aiostreams -- cloudflared tunnel diag
```

Adapt names from `incus list`. The diagnostic command requires a running
instance and a cloudflared version supporting it. Images may use a different
binary path. For a stopped connector, its log is the first source of evidence.
Logs/diagnostic archives may contain sensitive details: inspect and redact them
before sharing. Do not print the full Incus instance configuration to share a
log; its environment can contain the tunnel token.

Check the layers separately:

| Observation | Next check |
|---|---|
| Process stops or says a tunnel name/ID is required | Ensure `TUNNEL_TOKEN` exists at process creation and that `command` runs `tunnel … run`; a later secret file does not change a running process's environment |
| Authentication/token error | Verify the secret is the installation token for this remotely managed tunnel, not an API token, UUID, whole command or local credentials JSON |
| DNS error | Inspect the instance resolver and host upstream DNS; check Cloudflare's edge discovery names from this same app network |
| QUIC/HTTP2 connection error | Allow outbound UDP 7844 for QUIC or TCP 7844 for HTTP/2, including return traffic; TCP 443 alone is insufficient |
| Container Running but no connectors in Cloudflare | Use cloudflared logs, built-in prechecks and `/ready`; process state alone is insufficient |
| Connector healthy but public requests return 502 | Check origin name, port, listening address and reachability from cloudflared; this is separate from tunnel registration |

Cloudflared 2026.5.2+ performs DNS and transport prechecks itself. Prefer those
over a second custom Nixus tunnel-probing service. If UDP is blocked upstream,
`--protocol http2` before `run` can isolate that problem **if TCP 7844 works**.
Leave protocol selection automatic otherwise. A UDP `nc -z` success by itself
does not prove that replies or a QUIC handshake work.

The private metrics endpoint's `/ready` returns HTTP 200 when cloudflared has
an active Cloudflare connection, otherwise 503. Check it from a diagnostic
container on the same app network; the official minimal image need not include
curl or a shell. This does not prove the routed origin application is healthy.

## Keep one owner for each layer

- Cloudflare dashboard/API: tunnel configuration and public hostname routes.
- Official cloudflared: authentication, edge discovery, QUIC/HTTP2 fallback,
  connection retry and readiness evidence.
- Incus: private bridge address allocation, DHCP, dnsmasq and app NAT.
- NixOS: physical NICs/VLANs and the host's input/forwarding boundary.

A single host-level `services.cloudflared` service is an alternative when one
connector must reach many origins. Use the maintained NixOS module rather than
a custom systemd launcher, but first replace per-app service names with origins
the host can actually resolve and reach. Moving the existing sidecar without
changing `http://aiostreams:3000` would introduce an origin-resolution failure.

References: [run parameters](https://developers.cloudflare.com/tunnel/reference/run-parameters/),
[connectivity prechecks](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/),
[readiness example](https://developers.cloudflare.com/tunnel/guides/kubernetes/).
