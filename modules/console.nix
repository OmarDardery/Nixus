{ config, lib, pkgs, ... }:
let
  status = pkgs.writeShellApplication {
    name = "nixus-status";
    runtimeInputs = [ pkgs.python3 pkgs.iproute2 pkgs.systemd ];
    text = ''exec python3 ${../scripts/console_status.py} "$@"'';
  };
  fetchConfig = pkgs.writeText "nixus-fastfetch.json" (builtins.toJSON {
    logo = { type = "data"; source = "NIXUS\nNixOS + Incus"; padding.right = 4; };
    modules = [
      "title" "separator"
      { type = "custom"; key = "Nixus"; format = lib.removeSuffix "\n" (builtins.readFile ../VERSION); }
      "os" "kernel" "uptime" "cpu" "memory"
      { type = "disk"; folders = "/"; }
      "break"
      { type = "command"; key = ""; text = "${status}/bin/nixus-status"; timeout = 2500; }
    ];
  });
  fetch = pkgs.writeShellApplication {
    name = "nixus-fetch";
    runtimeInputs = [ pkgs.fastfetch.minimal ];
    text = ''exec fastfetch --config ${fetchConfig} "$@"'';
  };
  # Shell startup budget: generate every init script at build time, so an
  # interactive shell sources files instead of spawning starship/zoxide.
  starship = config.programs.starship;
  starshipToml = (pkgs.formats.toml { }).generate "nixus-starship.toml" starship.settings;
  starshipInit = pkgs.runCommand "nixus-starship-init.bash" { } ''
    HOME=$TMPDIR ${starship.package}/bin/starship init bash --print-full-init > $out
  '';
  zoxideInit = pkgs.runCommand "nixus-zoxide-init.bash" { } ''
    ${pkgs.zoxide}/bin/zoxide init bash > $out
  '';
  # Completion for the Nixus CLIs (subcommands only; arguments stay free-form).
  # bash-completion loads completions/<command> lazily, so install one copy per name.
  completionScript = pkgs.writeText "nixus-completion.bash" ''
    _nixus_words() {
      case "$1" in
        nixus) echo "list doctor install-plan commissioning enroll-key exec exec-many restart backup action" ;;
        nixus-admin) echo "doctor identity enroll-key backend web guard renew approve-enrollment reset-password config projects deploy guests recovery commissioning install-plan prune-jobs disk" ;;
      esac
    }
    _nixus_complete() {
      (( COMP_CWORD == 1 )) || return 0
      mapfile -t COMPREPLY < <(compgen -W "$(_nixus_words "$1")" -- "''${COMP_WORDS[1]}")
    }
    complete -F _nixus_complete nixus nixus-admin
  '';
  completions = pkgs.runCommand "nixus-bash-completion" { } ''
    mkdir -p $out/share/bash-completion/completions
    for name in nixus nixus-admin; do
      ln -s ${completionScript} $out/share/bash-completion/completions/$name
    done
  '';
in {
  environment.systemPackages = [ status fetch (lib.lowPrio pkgs.fastfetch.minimal) completions ]
    ++ (with pkgs; [ eza bat ripgrep fd zoxide ]);
  environment.etc."xdg/fastfetch/config.jsonc".source = fetchConfig;
  programs.bash.completion.enable = lib.mkDefault true;
  # ble.sh is loaded below with deferred attachment; the upstream module would
  # attach before fzf/starship initialise and slow every shell.
  programs.bash.blesh.enable = lib.mkDefault false;
  programs.fzf = { keybindings = lib.mkDefault true; fuzzyCompletion = lib.mkDefault true; };
  programs.starship = {
    # Settings only: the prompt is initialised from a pre-generated script below.
    enable = lib.mkDefault false;
    settings = lib.mapAttrsRecursive (_: value: lib.mkDefault value) {
      add_newline = true;
      command_timeout = 250;
      scan_timeout = 50;
      format = "$username@$hostname $directory$git_branch$git_status$nix_shell$cmd_duration$line_break$character";
      username = { show_always = true; style_user = "bold cyan"; style_root = "bold red"; format = "[$user]($style)"; };
      hostname = { ssh_only = false; format = "[$hostname]($style)"; style = "bold green"; };
      directory = { truncation_length = 3; style = "bold blue"; };
      git_branch = { symbol = ""; format = " on [$branch]($style)"; };
      nix_shell = { disabled = false; symbol = "nix"; format = " via [$symbol]($style)"; };
      character = { success_symbol = "[>](bold green)"; error_symbol = "[>](bold red)"; };
    };
  };
  programs.bash.shellAliases = {
    # Override the upstream default; ordinary user definitions still win.
    ll = lib.mkOverride 900 "ls -lah --group-directories-first --color=auto";
    failed = lib.mkDefault "systemctl --failed --no-pager";
    nixus-update = lib.mkDefault "nix run --refresh github:OmarDardery/Nixus#update --";
    la = lib.mkDefault "eza -la --group-directories-first --git";
    lt = lib.mkDefault "eza --tree --level=2 --group-directories-first";
  };
  programs.bash.promptInit = lib.mkIf (starship.settings != { }) ''
    if [[ $TERM != dumb ]]; then
      [[ -f "''${STARSHIP_CONFIG:-$HOME/.config/starship.toml}" ]] || export STARSHIP_CONFIG=${starshipToml}
      source ${starshipInit}
    fi
  '';
  programs.bash.interactiveShellInit = lib.mkMerge [
    # Pinned ble.sh requires the XDG cache directory to exist before sourcing.
    # Otherwise a fresh account falls back to its read-only Nix store path.
    (lib.mkOrder 400 ''
      ${pkgs.coreutils}/bin/mkdir -p -m 700 -- "''${XDG_CACHE_HOME:-$HOME/.cache}"
    '')
    # Load ble.sh early without attaching; attach once everything else is set up.
    (lib.mkOrder 450 ''
      if [[ $- == *i* && -t 0 && $TERM != dumb ]]; then
        source ${pkgs.blesh}/share/blesh/ble.sh --attach=none
      fi
    '')
    (lib.mkAfter ''
      source ${zoxideInit}
      [[ ! ''${BLE_VERSION-} ]] || ble-attach
    '')
    ''
    HISTCONTROL=ignoreboth:erasedups
    HISTSIZE=50000
    HISTFILESIZE=100000
    HISTTIMEFORMAT='%F %T '
    shopt -s histappend checkwinsize cmdhist autocd globstar
    # Share history between concurrent sessions (ble.sh) without extra prompt hooks.
    [[ ! ''${BLE_VERSION-} ]] || bleopt history_share=1
    bind 'set completion-ignore-case on'
    bind 'set show-all-if-ambiguous on'
  '' ];
  programs.bash.loginShellInit = ''
    if [[ $- == *i* && -t 1 && "$TERM" != dumb && ! -e "$HOME/.hushlogin" && -z "''${NIXUS_NO_FETCH:-}" ]]; then
      ${fetch}/bin/nixus-fetch
    fi
  '';
}
