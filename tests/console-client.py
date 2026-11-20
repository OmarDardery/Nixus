"""Exercise installed Bash and a real Ctrl+R history selection through a PTY."""
import errno
import fcntl
import os
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time

with tempfile.TemporaryDirectory() as home:
    reader, writer = os.pipe()
    # Synchronize with precmd, not cursor-rendered terminal text. The fzf wrapper
    # uses the real binary in filter mode to select a deterministic history entry;
    # Ctrl+R must still invoke the installed widget and populate the editing line.
    with open(home + '/.bash_profile', 'w') as profile:
        profile.write(f'''PROMPT_COMMAND+=('printf P >&{writer}')
fzf() {{
  command fzf --filter='^printf H' "$@"
  local result=$?
  printf R >&{writer}
  return "$result"
}}
''')
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 100, 0, 0))
    env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=home + '/.config', TERM='xterm-256color')
    env.pop('NIXUS_NO_FETCH', None)
    command = ('if test "$(type -t ble-attach)" = function && '
               'test "$(type -t __fzf_history__)" = function && '
               'test "$STARSHIP_SHELL" = bash && test "$_ble_attached" = 1; '
               f'then history -s "printf H >&{writer}"; printf F >&{writer}; '
               'else printf "ble=%s fzf=%s starship=%s attached=%s\\n" '
               '"$(type -t ble-attach)" "$(type -t __fzf_history__)" "$STARSHIP_SHELL" "$_ble_attached"; '
               'exit 1; fi\n')
    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    process = subprocess.Popen(['bash', '--login', '-i'], stdin=slave, stdout=slave,
                               stderr=slave, env=env, pass_fds=(writer,), preexec_fn=controlling_terminal)
    started = time.monotonic()
    os.close(slave); os.close(writer)
    output = bytearray()
    first_prompt = None
    deadline = time.monotonic() + 20
    phase = 'startup'
    try:
        while True:
            if time.monotonic() >= deadline:
                raise AssertionError('Interactive Bash deadline in ' + phase + ': ' + repr(bytes(output[-16384:])))
            ready, _, _ = select.select([master, reader], [], [], 0.1)
            for descriptor in ready:
                try: data = os.read(descriptor, 65536)
                except OSError as error:
                    if descriptor == master and error.errno == errno.EIO: data = b''
                    else: raise
                if descriptor == master:
                    output.extend(data)
                    if b'\x1b[6n' in data: os.write(master, b'\x1b[1;1R')
                    if b'\x1b[>c' in data: os.write(master, b'\x1b[>0;136;0c')
                    if b'\x1b[c' in data: os.write(master, b'\x1b[?1;2c')
                else:
                    for token in data:
                        if token == ord('P') and phase == 'startup':
                            first_prompt = time.monotonic() - started
                            os.write(master, command.encode()); phase = 'features'
                        elif token == ord('F') and phase == 'features':
                            phase = 'history-prompt'
                        elif token == ord('P') and phase == 'history-prompt':
                            os.write(master, b'\x12'); phase = 'history-widget'
                        elif token == ord('R') and phase == 'history-widget':
                            os.write(master, b'\n'); phase = 'history-execution'
                        elif token == ord('H') and phase == 'history-execution':
                            os.write(master, b'printf NIXUS_CONSOLE_OK; exit 0\n'); phase = 'done'
            if process.poll() is not None: break
        assert process.wait(timeout=2) == 0 and phase == 'done', (phase, output.decode(errors='replace'))
        assert b'NIXUS' in output, output.decode(errors='replace')
        # Startup budget for a cold first login shell (ble.sh builds its cache,
        # fastfetch runs). Locally ~0.8s cold / ~0.3s warm; VMs are slower.
        print(f'First interactive prompt after {first_prompt:.2f}s', flush=True)
        assert first_prompt is not None and first_prompt < 5.0, first_prompt
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        os.close(master); os.close(reader)
