# Install and update

## Requirements

An installed x86_64 NixOS system with Internet access and hardware
virtualization (VT-x/AMD-V) enabled in the firmware. Existing disks are never
formatted; users, bootloader and network addressing are kept.

## Install

From the server's console or an SSH session:

```sh
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install
```

The installer checks the machine, builds the full stack (Incus, Cockpit,
the console) and activates it with automatic rollback if the new
configuration cannot be reached. Rerun the same command after any
interruption; it resumes.

Useful options (after `--`):

| Option | Purpose |
|---|---|
| `--ssh-key laptop.pub` | Allow your laptop's SSH key for the `operator` account |
| `--no-ssh-password-login` | Key-only SSH |
| `--guest-subnet 10.78.0.0/24` | Choose the private subnet for containers and VMs |
| `--interactive` | Answer questions in the terminal instead of the browser |

## First sign-in

1. Open `http://SERVER_IP/`. It redirects to `https://SERVER_IP:9440/`.
   Compare the certificate fingerprint with the one the installer printed.
2. The page shows a one-time code. On the server run
   `sudo nixus-admin approve-enrollment` and paste it.
3. Choose your administrator name and password.

The **Next step** card on Overview walks through the rest: activate the
hypervisor, enroll the browser for the Incus UI, create the secrets key and
save the recovery kit, and set up backups.

## Daily use

| Task | Where |
|---|---|
| Deploy an app | Apps → New app, or push it to your [apps repository](apps-repo.md) |
| Env vars and secrets | Apps → app → Env ([details](secrets.md)) |
| USB / serial devices | Apps → app → Settings → Devices ([details](apps.md#devices)) |
| Update app images | Overview → **Update all apps** |
| Back up now | Overview → **Back up now** ([details](backups.md)) |
| Update Nixus | Overview → **Update Nixus** |

## Update Nixus

**Update Nixus** on Overview builds the new version, activates it and confirms
it from your browser; if the console stops answering, the server rolls back.
From a terminal: `nix run --refresh github:OmarDardery/Nixus#update`.

## Forgotten password

On the sign-in page choose **Recover access**, then on the server run
`sudo nixus-admin recovery approve CODE`. If the console itself is down:
`sudo nixus-admin reset-password`.
