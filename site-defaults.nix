# Deployment inventory. Empty values deliberately prevent activation.
# Fill from the physical host; documentation examples are not discovered facts.
{
  schemaVersion = 1;
  ready = false;
  system = "x86_64-linux";
  hostName = "nixus";
  cpuVendor = ""; # intel or amd
  adminKeys = [ ];
  access.sshPasswordLogin = true; # Normal Linux passwords work for non-root server administration.
  management = {
    interface = "";
    address = "";
    prefixLength = 24;
    gateway = "";
    dns = [ ];
    trustedCIDRs = [ ];
    configure = false; # preserve installer networking until explicitly enabled
  };
  guests = {
    bridge = "incusbr0";
    cidr = "";
    gatewayCIDR = "";
    dhcpRange = ""; # e.g. 10.77.0.100-10.77.0.199 (not an actual LAN)
  };
  storage = {
    pool = "guests";
    driver = "dir"; # dir is the non-formatting baseline; zfs requires an existing dataset
    source = "/var/lib/incus/storage-pools/guests";
    confirmedExistingZfsDataset = false;
    hostId = ""; # eight hexadecimal characters, required for ZFS
  };
  cockpit = { enable = false; port = 9090; managePassword = false; };
  # Additional instances: { name; project = "lab"; image = "images:<fingerprint>";
  # type = "container"; profiles = [ "base" ]; config = {}; devices = {}; }
  instances = [ ];
  mounts = [ ]; # existing UUID filesystems only, managed under /srv/nixus
  connectivity = {
    preservedIncusBridges = [ ]; # Native Incus bridges retained during adoption.
    bridges = [ ]; # { name = "br-lan"; interfaces = [ "enp2s0" ]; }
    vlans = [ ]; # { name = "vlan20"; interface = "enp2s0"; id = 20; }
    guestInterfaces = [ "incusbr0" ]; # Host firewall integration, not guest network definitions.
    trustedLANAccess = false;
    privateAccess = [ ]; # { cidr = "192.168.1.2/32"; protocol = "udp"; ports = [ 53 ]; }
  };
  hardware.serialAliases = [ ]; # Explicit { name; vendorId; productId; serial; } selections only.
  helpers.enable = true; # CLI only, no background service or browser script execution.
  radios = {
    wifi = { enable = false; interface = ""; ssid = ""; manageProfile = false; };
    bluetooth.enable = false;
  };
  monitoring = { collection = false; history = false; retentionDays = 14; scrapeSeconds = 60; };
  maintenance = { trim = true; optimiseStore = true; timeZone = "UTC"; laptopMode = false; };
  setup = { enable = false; port = 9440; confirmationSeconds = 600; };
  secrets = {
    enable = false; # enable sops-nix after adding encrypted files
    hostFile = ""; # repository-relative encrypted YAML
    guestFile = "";
    ageKeyFile = "/var/lib/sops-nix/key.txt"; # private key deployed out of band
  };
  tunnel = {
    enable = false;
    uuid = "";
    credentialsFile = "/var/lib/nixus-secrets/cloudflared.json";
    ingress = { }; # "app.example.com" = "http://<guest address>:8080";
  };
  backup = {
    enable = false;
    repository = ""; # independent storage, e.g. sftp:backup@server:/backups/nixus
    passwordFile = "/var/lib/nixus-secrets/restic-password";
    environmentFile = "/var/lib/nixus-secrets/restic-environment";
    stagingDirectory = "/var/lib/nixus/exports";
    initialize = false; # explicitly opt in after verifying the remote repository
    schedule = "*-*-* 03:00:00";
    groups = [ ]; # Lists of project/guest identities that must stop together.
    exclude = [ ]; # Explicit maintenance exclusions; also honors user.nixus.backup=manual.
    reserveMiB = 1024;
  };
}

