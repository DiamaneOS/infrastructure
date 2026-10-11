# SPDX-License-Identifier: Apache-2.0
"""Unprivileged logging-policy boundaries; no host service is changed."""
import configparser
import contextlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('configure_logging', str(HERE / 'host/configure-logging'))
spec = importlib.util.spec_from_loader(loader.name, loader)
logging = importlib.util.module_from_spec(spec); loader.exec_module(logging)
POLICY = '[Journal]\nStorage=volatile\nRuntimeMaxUse=160M\nMaxRetentionSec=1day\nForwardToSyslog=no\n'
RECEIVERS = ('syslog.socket', 'rsyslog.service', 'syslog.service', 'syslog-ng.service')


class Manager:
    """Service lifecycle fixture; masks block starts but do not stop live readers."""
    def __init__(self, config=POLICY):
        self.config = config
        self.active = {unit: 'active' for unit in RECEIVERS}
        self.jobs = dict.fromkeys(RECEIVERS, '')
        self.masked = set()
        self.calls = []
        self.failed_stop = None
        self.survivor = None
        self.unmasked = None
        self.daemon = False
        self.instances = ()

    def command(self, argv, accepted=(0,)):
        self.calls.append(argv)
        if argv[:2] == ['/usr/bin/systemd-analyze', 'cat-config']:
            return 0, self.config
        if argv[0] == '/usr/bin/pgrep':
            return (0, '123\n') if self.daemon else (1, '')
        if argv[0] != '/usr/bin/systemctl':
            raise AssertionError('unexpected tool')
        action = argv[1]
        if action == 'list-units':
            return 0, ''.join(unit + ' loaded active running Public fixture\n' for unit in self.instances)
        if action == 'list-unit-files':
            return 0, 'syslog.socket static -\n' + ''.join(unit + ' enabled enabled\n' for unit in self.instances)
        if action == 'mask':
            self.masked.update(unit for unit in argv[3:] if unit != self.unmasked)
            return 0, ''
        if action == 'daemon-reload': return 0, ''
        unit = argv[2]
        if action == 'show':
            return 0, ('LoadState=' + ('masked' if unit in self.masked else 'loaded') + '\n'
                'ActiveState=' + self.active[unit] + '\nJob=' + self.jobs[unit] + '\n')
        if action == 'stop':
            if unit == self.failed_stop: raise RuntimeError('native stop refused')
            if unit != self.survivor:
                self.active[unit] = 'inactive'; self.jobs[unit] = ''
            return 0, ''
        if action == 'is-enabled':
            return (1, 'masked\n') if unit in self.masked else (0, 'enabled\n')
        raise AssertionError('unexpected manager action')


@contextlib.contextmanager
def fixture(manager):
    with patch.object(logging.os, 'geteuid', return_value=0), patch.object(logging, 'command', side_effect=manager.command):
        yield


class JournalPolicyTest(unittest.TestCase):
    def test_final_source_dropin_reasserts_all_four_privacy_controls(self):
        path = HERE / 'host/files/etc/systemd/journald.conf.d/zz-diamaneos.conf'
        config = configparser.ConfigParser(); config.read(path)
        self.assertEqual({'storage':'volatile', 'runtimemaxuse':'160M', 'maxretentionsec':'1day',
                          'forwardtosyslog':'no'}, dict(config['Journal']))
        logging.check_journal_policy(path.read_text())

    def test_later_conflicts_empty_resets_and_missing_keys_refuse_before_any_mask(self):
        conflicts = ['Storage=persistent', 'RuntimeMaxUse=1G', 'MaxRetentionSec=30day',
                     'ForwardToSyslog=yes', 'ForwardToSyslog=']
        for directive in conflicts:
            manager = Manager(POLICY + '[Journal]\n' + directive + '\n')
            with self.subTest(directive=directive), fixture(manager), self.assertRaises(RuntimeError):
                logging.configure_logging()
            self.assertFalse(manager.masked)
            self.assertEqual(1, len(manager.calls))
        for key in ('Storage=volatile\n', 'RuntimeMaxUse=160M\n', 'MaxRetentionSec=1day\n', 'ForwardToSyslog=no\n'):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                logging.check_journal_policy(POLICY.replace(key, ''))

    def test_other_sections_cannot_supply_or_override_journal_policy(self):
        logging.check_journal_policy(POLICY + '[Other]\nStorage=persistent\n')
        with self.assertRaises(RuntimeError): logging.check_journal_policy('[Other]\n' + POLICY.split('\n',1)[1])


class SyslogIsolationTest(unittest.TestCase):
    def test_masks_block_reactivation_before_all_active_receivers_are_stopped(self):
        manager = Manager()
        with fixture(manager): logging.configure_logging()
        expected = {'syslog.socket','rsyslog.service','syslog.service','syslog-ng.service','syslog-ng@.service'}
        self.assertEqual(expected, manager.masked)
        actions = [argv[1] for argv in manager.calls if argv[0] == '/usr/bin/systemctl']
        self.assertLess(actions.index('mask'), actions.index('stop'))
        self.assertLess(actions.index('daemon-reload'), actions.index('stop'))
        self.assertEqual(list(RECEIVERS), [argv[2] for argv in manager.calls if argv[1] == 'stop'])
        self.assertTrue(all(value == 'inactive' for value in manager.active.values()))

    def test_repeated_deployment_is_quiescent_and_keeps_permanent_masks(self):
        manager = Manager()
        with fixture(manager): logging.configure_logging()
        manager.calls.clear()
        with fixture(manager): logging.configure_logging()
        self.assertFalse(any(argv[1] == 'stop' for argv in manager.calls))
        self.assertIn('syslog-ng@.service', manager.masked)

    def test_failed_stop_never_passes_or_advances_to_daemon_absence(self):
        for unit in RECEIVERS:
            manager = Manager(); manager.failed_stop = unit
            with self.subTest(unit=unit), fixture(manager), self.assertRaises(RuntimeError):
                logging.configure_logging()
            self.assertFalse(any(argv[0] == '/usr/bin/pgrep' for argv in manager.calls))

    def test_successful_stop_and_mask_commands_cannot_hide_live_receivers_or_jobs(self):
        for unit in RECEIVERS:
            for state, job in (('active',''), ('deactivating',''), ('failed',''), ('inactive','123')):
                manager = Manager(); manager.survivor = unit
                manager.active[unit] = state; manager.jobs[unit] = job
                with self.subTest(unit=unit, state=state, job=job), fixture(manager), self.assertRaises(RuntimeError):
                    logging.configure_logging()

    def test_every_receiver_and_template_must_actually_be_masked(self):
        for unit in (*RECEIVERS, 'syslog-ng@.service'):
            manager = Manager(); manager.unmasked = unit
            with self.subTest(unit=unit), fixture(manager), self.assertRaises(RuntimeError):
                logging.configure_logging()

    def test_independent_syslog_daemon_refuses_even_with_masked_inactive_units(self):
        manager = Manager(); manager.daemon = True
        with fixture(manager), self.assertRaises(RuntimeError): logging.configure_logging()

    def test_active_and_explicit_instance_units_are_masked_and_stopped(self):
        manager = Manager(); manager.instances = ('syslog-ng@fixture.service',)
        manager.active['syslog-ng@fixture.service'] = 'active'
        manager.jobs['syslog-ng@fixture.service'] = '123'
        with fixture(manager): logging.configure_logging()
        self.assertIn('syslog-ng@fixture.service', manager.masked)
        self.assertEqual('inactive', manager.active['syslog-ng@fixture.service'])
        self.assertIn(['/usr/bin/systemctl','stop','syslog-ng@fixture.service'], manager.calls)
        manager = Manager(); manager.instances = ('syslog-ng@fixture.service',)
        manager.active['syslog-ng@fixture.service'] = 'active'; manager.jobs['syslog-ng@fixture.service'] = ''
        manager.failed_stop = 'syslog-ng@fixture.service'
        with fixture(manager), self.assertRaises(RuntimeError): logging.configure_logging()

    def test_instance_inventory_combines_loaded_and_boot_activatable_units(self):
        with patch.object(logging, 'command', side_effect=[(0,'syslog-ng@running.service loaded active running\n'),
                (0,'syslog.socket static -\nsyslog-ng@.service disabled enabled\nsyslog-ng@boot.service enabled enabled\n')]):
            self.assertEqual(('syslog-ng@boot.service','syslog-ng@running.service'), logging.syslog_instances())

    def test_instance_inventory_refuses_unrelated_malformed_or_unbounded_units(self):
        for text in ('unrelated.service loaded active running\n', 'syslog-ng@fixture.service\n',
                     'syslog-ng@../outside.service loaded active running\n',
                     ''.join(f'syslog-ng@fixture{n}.service loaded active running\n' for n in range(34))):
            with self.subTest(text=text), patch.object(logging, 'command', return_value=(0,text)), self.assertRaises(RuntimeError):
                logging.syslog_instances()
        for count in (32,33):
            units=''.join(f'syslog-ng@fixture{n}.service loaded active running\n' for n in range(count))
            with patch.object(logging, 'command', side_effect=[(0,units),(0,'syslog.socket static -\n')]):
                if count==32:self.assertEqual(32, len(logging.syslog_instances()))
                else:
                    with self.assertRaises(RuntimeError): logging.syslog_instances()

    def test_empty_instance_inventory_requires_a_successful_socket_anchor(self):
        with patch.object(logging, 'command', side_effect=[(0,''),(0,'syslog.socket static -\n')]) as command:
            self.assertEqual((), logging.syslog_instances())
            self.assertIn('syslog.socket', command.call_args.args[0])
        with patch.object(logging, 'command', side_effect=[(0,''),(0,'')]), self.assertRaises(RuntimeError):
            logging.syslog_instances()
        with patch.object(logging, 'command', side_effect=[(0,''),RuntimeError('native read failed')]), self.assertRaises(RuntimeError):
            logging.syslog_instances()

    def test_malformed_or_duplicate_manager_properties_refuse(self):
        for text in ('', 'LoadState=masked\nActiveState=inactive\n',
                     'LoadState=masked\nActiveState=inactive\nActiveState=inactive\n',
                     'LoadState=masked\nActiveState=inactive\nJob=\nPRIVATE=raw\n'):
            with patch.object(logging, 'command', return_value=(0,text)), self.assertRaises(RuntimeError):
                logging.unit_facts('rsyslog.service')

    def test_nonroot_refuses_before_configuration_or_manager_commands(self):
        with patch.object(logging.os, 'geteuid', return_value=1000), patch.object(logging, 'command') as command:
            with self.assertRaises(RuntimeError): logging.configure_logging()
            command.assert_not_called()


class NativeCommandBoundaryTest(unittest.TestCase):
    def test_real_unprivileged_output_cap_and_exit_status_are_enforced(self):
        program = [sys.executable, '-I', '-B', '-c']
        status, text = logging.command(program + ['import os;os.write(1,b"x"*65535)'])
        self.assertEqual((0,65535), (status,len(text)))
        for count in (65536,65537):
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                logging.command(program + [f'import os;os.write(1,b"x"*{count})'])
        with self.assertRaisesRegex(RuntimeError, '^host logging policy failed$'):
            logging.command(program + ['import sys;print("PRIVATE");sys.exit(2)'])
        self.assertEqual((1,''), logging.command(program + ['import sys;sys.exit(1)'], accepted=(0,1)))

    def test_host_apply_installs_and_checks_logging_before_journal_restart(self):
        path = HERE / 'host/apply'; text = path.read_text()
        subprocess.run(['/bin/bash','-n',str(path)], check=True, timeout=5)
        self.assertLess(text.index('install_tree "$HERE/files"'), text.index('python3 "$HERE/configure-logging"'))
        self.assertLess(text.index('python3 "$HERE/configure-logging"'), text.index('systemctl restart systemd-journald'))


@unittest.skipUnless(sys.platform == 'linux' and Path('/usr/bin/systemd-analyze').is_file()
    and Path('/usr/bin/systemctl').is_file(), 'requires installed Linux systemd for offline references')
class NativeSystemdReferenceTest(unittest.TestCase):
    @staticmethod
    def reference():
        """Only configuration and unit-file operations in fresh unprivileged roots."""
        results = []
        policy = (HERE / 'host/files/etc/systemd/journald.conf.d/zz-diamaneos.conf').read_text()
        old = (HERE / 'host/files/etc/systemd/journald.conf.d/50-diamaneos.conf').read_text()
        cases = (('vendor_syslog',False,False), ('vendor_99_syslog',False,False),
                 ('both_vendors',True,False), ('same_vendor_basename',True,False),
                 ('same_runtime_basename',True,False), ('later_conflict',True,True))
        for label, final, late in cases:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for path in ('usr/lib/systemd/journald.conf.d','etc/systemd/journald.conf.d','run/systemd/journald.conf.d'):
                    (root/path).mkdir(parents=True)
                (root/'usr/lib/systemd/journald.conf').write_text('[Journal]\n')
                (root/'etc/systemd/journald.conf.d/50-diamaneos.conf').write_text(old)
                if label != 'vendor_99_syslog':
                    (root/'usr/lib/systemd/journald.conf.d/syslog.conf').write_text('[Journal]\nForwardToSyslog=yes\n')
                if label != 'vendor_syslog':
                    (root/'usr/lib/systemd/journald.conf.d/99-syslog.conf').write_text('[Journal]\nForwardToSyslog=yes\n')
                if final: (root/'etc/systemd/journald.conf.d/zz-diamaneos.conf').write_text(policy)
                if label in ('same_vendor_basename','same_runtime_basename'):
                    parent = 'usr/lib' if label == 'same_vendor_basename' else 'run'
                    (root/parent/'systemd/journald.conf.d/zz-diamaneos.conf').write_text('[Journal]\nStorage=persistent\nForwardToSyslog=yes\n')
                if late: (root/'etc/systemd/journald.conf.d/zzz-unexpected.conf').write_text('[Journal]\nForwardToSyslog=yes\n')
                status, text = logging.command(['/usr/bin/systemd-analyze','--root='+str(root),
                                               'cat-config','systemd/journald.conf'])
                try: logging.check_journal_policy(text); accepted = True
                except RuntimeError: accepted = False
                value = logging.journal_settings(text).get('ForwardToSyslog')
                expected = final and not late
                results.append(dict(case=label, cat_config_exit=status, helper_accepts=accepted,
                    forwarding=value if value in ('yes','no') else 'other',
                    passed=accepted==expected and value==('no' if expected else 'yes')))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'usr/lib/systemd/system').mkdir(parents=True); (root/'etc/systemd/system').mkdir(parents=True)
            units = (*RECEIVERS, 'syslog-ng@.service', 'syslog-ng@fixture.service')
            for unit in units:
                if unit == 'syslog.service': continue
                (root/'usr/lib/systemd/system'/unit).write_text('[Unit]\nDescription=Public fixture\n')
            (root/'etc/systemd/system/syslog.service').symlink_to('../../../usr/lib/systemd/system/rsyslog.service')
            # This operation reads unit files, never the production manager.
            _, listing = logging.command(['/usr/bin/systemctl','--root='+str(root),'list-unit-files',
                '--all','--plain','--full','--no-legend','--no-pager','syslog-ng@*.service','syslog.socket'])
            explicit_instance_listed = any(row.split()[0]=='syslog-ng@fixture.service' for row in listing.splitlines())
            anchor_listed = any(row.split()[0]=='syslog.socket' for row in listing.splitlines())
            empty_status, empty = logging.command(['/usr/bin/systemctl','--root='+str(root),'list-unit-files',
                '--all','--plain','--full','--no-legend','--no-pager','syslog-ng@missing*.service'], accepted=(0,1))
            status, _ = logging.command(['/usr/bin/systemctl','--root='+str(root),'mask','--force',*units])
            again, _ = logging.command(['/usr/bin/systemctl','--root='+str(root),'mask','--force',*units])
            states = {}
            for unit in units:
                code, state = logging.command(['/usr/bin/systemctl','--root='+str(root),'is-enabled',unit], accepted=(0,1))
                path = root/'etc/systemd/system'/unit
                states[unit] = dict(status=code, masked=state.strip()=='masked',
                    dev_null_symlink=path.is_symlink() and os.readlink(path)=='/dev/null')
            results.append(dict(case='permanent_alias_template_and_instance_masks', mask_exit=status,
                repeated_mask_exit=again, explicit_instance_listed=explicit_instance_listed, units=states,
                socket_anchor_listed=anchor_listed, empty_glob_exit=empty_status,
                passed=explicit_instance_listed and anchor_listed and empty_status==1 and not empty.strip()
                    and status==again==0 and all(value['masked']
                    and value['dev_null_symlink'] for value in states.values())))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'etc/systemd/system').mkdir(parents=True)
            path = root/'etc/systemd/system/rsyslog.service'; body = '[Unit]\nDescription=Public fixture\n'; path.write_text(body)
            status, _ = logging.command(['/usr/bin/systemctl','--root='+str(root),'mask','--force','rsyslog.service'], accepted=(0,1))
            preserved = not path.is_symlink() and path.read_text()==body
            results.append(dict(case='regular_local_unit_refuses_mask', mask_exit=status,
                local_unit_preserved=preserved, passed=status!=0 and preserved))
        return results

    def test_actual_config_priority_masks_aliases_instances_and_local_unit_refusal(self):
        for facts in self.reference():
            with self.subTest(case=facts['case']): self.assertTrue(facts['passed'], facts)


if __name__ == '__main__': unittest.main()
