{ ... }: {
  nixus.project = {
    name = "beta";
    backend = "incus-native";
    backup.consistency = "quiesce";
    claims = [ "instance/beta-guest" ];
    volumes.printer-data.size = "2GiB";
    instances.printer = {
      image = "images:debian/13";
      cpus = 1;
      memory = "1GiB";
      disks.data = { volume = "printer-data"; path = "/srv/data"; };
      usb.board = { vendorId = "1d50"; productId = "614e"; };
    };
  };
}
