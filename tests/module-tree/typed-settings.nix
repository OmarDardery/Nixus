{ ... }: {
  nixus.settings.maintenance.timeZone = "UTC";
  nixus.incus.instances.fixture = { image = "images:fixture-only"; };
}
