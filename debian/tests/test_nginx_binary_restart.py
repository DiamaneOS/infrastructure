import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('nginx_binary_restart', str(ROOT / 'debian/nginx-binary-restart'))
spec = importlib.util.spec_from_loader(loader.name, loader)
restart = importlib.util.module_from_spec(spec)
loader.exec_module(restart)

MAPS = '''55d0c0a00000-55d0c0a2a000 r--p 00000000 08:01 1234 /usr/sbin/nginx
7f00a0000000-7f00a0100000 rw-s 00000000 00:01 5678 /dev/zero (deleted)
7f00a0200000-7f00a0300000 rw-s 00000000 00:01 5679 /memfd:zone (deleted)
7f00a0400000-7f00a0500000 r-xp 00000000 08:01 4321 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f00a0600000-7f00a0700000 r-xp 00000000 08:01 4322 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00a0800000-7f00a0900000 rw-p 00000000 00:00 0
'''
TCP = '''  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 1
   1: 0100007F:01BB 0200007F:D431 01 00000000:00000000 00:00000000 00000000    33        0 2
   2: 0100007F:0050 0200007F:D432 01 00000000:00000000 00:00000000 00000000    33        0 3
   3: 0100007F:1F90 0200007F:D433 01 00000000:00000000 00:00000000 00000000    33        0 4
   4: 0100007F:D431 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 5
'''
TCP6 = '''  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:01BB 00000000000000000000000002000000:C001 01 00000000:00000000
'''


def completed(code=0, output=''):
    return subprocess.CompletedProcess([], code, output)


class NginxBinaryRestartTest(unittest.TestCase):
    def test_only_replaced_files_under_usr_or_lib_count(self):
        self.assertEqual(['/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)'], restart.replaced('/usr/sbin/nginx', MAPS))
        self.assertEqual([], restart.replaced('/usr/sbin/nginx', MAPS.replace(' (deleted)\n', '\n', 3)))
        self.assertIn('/usr/sbin/nginx (deleted)', restart.replaced('/usr/sbin/nginx (deleted)', ''))

    def test_counts_established_connections_on_the_served_ports_only(self):
        # Listening sockets, other ports and the client side of a local connection do not count.
        self.assertEqual(3, restart.established([TCP, TCP6]))

    def test_a_package_run_is_seen_through_dpkg_locks_not_process_names(self):
        locks = ('1: FLOCK  ADVISORY  WRITE 681 00:19:1486 0 EOF\n'
                 '2: POSIX  ADVISORY  WRITE 4242 fe:03:260898 0 EOF\n'
                 '2: -> POSIX  ADVISORY  WRITE 4343 fe:03:260898 0 EOF\n')
        self.assertTrue(restart.held(locks, {(254, 3, 260898)}))
        self.assertFalse(restart.held(locks, {(254, 3, 260899)}))
        self.assertFalse(restart.held('', {(254, 3, 260898)}))
        self.assertNotIn('PACKAGE_MANAGERS', vars(restart))

    def test_an_unreadable_process_fails_instead_of_passing_as_nothing_replaced(self):
        with mock.patch.object(restart.os, 'readlink', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                restart.stale(42)
        with mock.patch.object(restart.os, 'readlink', side_effect=FileNotFoundError):
            self.assertEqual([], restart.stale(42))

    def flow(self, files, reload_code=0):
        calls = []

        def systemctl(*args):
            calls.append(args[0])
            return completed(reload_code if args[0] == 'reload' else 0)

        stale = iter(files)
        with mock.patch.object(restart, 'main_pid', return_value=42), \
                mock.patch.object(restart, 'stale', side_effect=lambda pid: next(stale)), \
                mock.patch.object(restart, 'systemctl', side_effect=systemctl), \
                mock.patch.object(restart, 'busy', return_value=False), \
                mock.patch.object(restart, 'connections', return_value=0), \
                mock.patch.object(restart, 'log'):
            return restart.main(), calls

    def test_nothing_replaced_does_nothing(self):
        self.assertEqual((0, []), self.flow([[]]))

    def test_a_refused_config_test_never_restarts(self):
        code, calls = self.flow([['/usr/sbin/nginx (deleted)']] * 2, reload_code=1)
        self.assertEqual((1, ['reload']), (code, calls))

    def test_restarts_after_the_test_and_checks_the_new_code(self):
        self.assertEqual((0, ['reload', 'restart']), self.flow([['/usr/sbin/nginx (deleted)']] * 2 + [[]]))
        self.assertEqual(1, self.flow([['/usr/sbin/nginx (deleted)']] * 3)[0])

    def test_waits_for_the_package_manager_before_it_acts(self):
        waited = []
        with mock.patch.object(restart, 'main_pid', return_value=42), \
                mock.patch.object(restart, 'stale', side_effect=[['x'], []]), \
                mock.patch.object(restart, 'wait', side_effect=lambda condition, limit: waited.append(condition)), \
                mock.patch.object(restart, 'systemctl') as systemctl:
            self.assertEqual(0, restart.main())
        self.assertEqual([restart.busy], waited)
        systemctl.assert_not_called()

    def test_installed_by_the_runtime_with_a_hook_that_never_fails_a_package_run(self):
        runtime = (ROOT / 'debian/install-web-runtime').read_text()
        for line in ['install -m 0755 "$here/nginx-binary-restart" /usr/local/sbin/diamaneos-nginx-binary-restart',
                     'install -o root -g root -m 0644 "$here/nginx-binary-restart.service" '
                     '/etc/systemd/system/nginx-binary-restart.service',
                     'install -o root -g root -m 0644 "$here/apt-nginx-restart.conf" '
                     '/etc/apt/apt.conf.d/54diamaneos-nginx-restart']:
            self.assertIn(line, runtime)
        self.assertLess(runtime.index('nginx-binary-restart.service'), runtime.index('systemctl daemon-reload'))
        hook = (ROOT / 'debian/apt-nginx-restart.conf').read_text()
        self.assertIn('DPkg::Post-Invoke', hook)
        self.assertIn('--no-block', hook)
        self.assertIn('|| true', hook)
        unit = (ROOT / 'debian/nginx-binary-restart.service').read_text()
        self.assertIn('ExecStart=/usr/local/sbin/diamaneos-nginx-binary-restart', unit)
        self.assertIn('CapabilityBoundingSet=CAP_SYS_PTRACE', unit)


if __name__ == '__main__':
    unittest.main()
