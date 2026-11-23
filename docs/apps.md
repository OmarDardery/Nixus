# Apps

An app is a Compose project (one or more containers) or a VM/container you
describe. Each app gets its own Incus project, network and storage.

## Compose apps

**Apps → New app** takes a `compose.yaml` and, if it builds its own image, a
`Dockerfile` and any files it copies. Or push the folder to your
[apps repository](apps-repo.md).

Not ready to deploy? **Save draft** keeps the form on the server, including environment
variables (encrypted with your secrets key), so you can finish from another device. Drafts
list on the Apps page and are removed when the app deploys.

Rules, checked before anything runs:

- Images are pinned by digest: `image: ghcr.io/org/app@sha256:…`. Use
  **Pin** on the app page to turn tags into digests. `FROM` lines in
  Dockerfiles follow the same rule.
- Images are pulled, and Dockerfiles are built, by `incus-compose` with Buildah on the server.
- Named volumes (`volumes: { data: {} }`) become Incus volumes, are backed up
  and survive updates. Host paths are not allowed.
- `ports:` publish on the server's address.
- No `privileged`, `cap_add`, `network_mode: host` or Docker secrets. Put
  secrets in the Env tab instead.

### Devices

Serial ports (3D printers, Zigbee/Z-Wave sticks) and USB devices can be passed
through. **Apps → app → Settings → Devices** lists what is plugged in, each
with the line to paste.

```yaml
services:
  klipper:
    image: …@sha256:…
    devices:
      - /dev/serial/by-id/usb-Klipper_stm32f446xx_123-if00:/dev/ttyACM0
    x-nixus:
      usb: ["0bda:2838"]        # raw USB by vendor:product, e.g. an SDR or Coral
```

- Use `/dev/serial/by-id/…` paths. They stay the same across reboots and
  replugging; `ttyUSB0` numbering does not.
- Devices are hotplugged: the app starts without them and picks them up when
  plugged in.
- Only serial ports and USB IDs are accepted. `/dev/sda`, `/dev/kvm` and similar
  are refused.

## VMs and containers

**New app → VM or container** creates a Debian (or other) system image with
CPU, memory, disk and USB devices. In Nix (`default.nix`):

```nix
{ ... }: {
  nixus.project = {
    backend = "incus-native";
    instances.printer = {
      image = "images:debian/13";
      cpus = 2; memory = "2GiB";
      serial.mcu = { source = "/dev/serial/by-id/usb-Klipper_…-if00"; path = "/dev/ttyACM0"; };
      usb.sdr = { vendorId = "0bda"; productId = "2838"; };
    };
  };
}
```

## Updates

Nixus checks registries for new digests. **Update all apps** (Overview) or
**Update image** (app page) updates them. Before each update Nixus snapshots
the app's volumes, then deploys and waits for it to be healthy. On failure it
rolls back and holds the broken digest. Set
`updates.policy = "auto"` in an app's `default.nix` to do this unattended.

## Logs and data

- **Logs** tab: recent output of each container.
- **Settings → Import data**: upload a `.tar`/`.tar.gz` into a folder of an
  instance, e.g. to move an existing app's data in.
