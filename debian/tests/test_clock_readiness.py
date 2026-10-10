import importlib.machinery
import importlib.util
from pathlib import Path
import unittest

loader = importlib.machinery.SourceFileLoader('clock_readiness',
    str(Path(__file__).resolve().parents[1] / 'clock-readiness'))
spec = importlib.util.spec_from_loader(loader.name, loader)
clock = importlib.util.module_from_spec(spec)
loader.exec_module(clock)


class ClockReadinessTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.tracking = 'ABCD,192.0.2.1,2,999,0.00001,0,0,0,0,0,0.01,0.001,64,Normal'
        self.sources = '\n'.join(
            f'^,{"*" if n == 1 else "+"},192.0.2.{n},1,6,377,1,0,0,0.01'
            for n in range(1, 4))

    def test_requires_authenticated_policy_and_rejects_dynamic_or_local_sources(self):
        policy = 'authselectmode require\nminsources 3\n' + '\n'.join(
            f'server clock{n}.example.invalid nts iburst' for n in range(3))
        self.assertTrue(clock.authenticated_policy(policy))
        for invalid in (policy.replace('nts', ''), policy + '\nlocal stratum 1',
                policy + '\nsourcedir /run/sources', policy.replace('require', 'ignore')):
            self.assertFalse(clock.authenticated_policy(invalid))

    def test_requires_three_fresh_combined_sources_and_the_actual_reference(self):
        self.assertTrue(clock.health(self.tracking, self.sources, self.now)['healthy'])
        for sources in (self.sources.splitlines()[0], self.sources.replace(',1,0,0,0.01',
                ',400,0,0,0.01'), self.sources.replace('^,*', '^,+')):
            self.assertFalse(clock.health(self.tracking, sources, self.now)['healthy'])
        self.assertFalse(clock.health(self.tracking.replace('192.0.2.1', '192.0.2.9'),
            self.sources, self.now)['healthy'])

    def test_rejects_stale_or_unsynchronised_time_and_accepts_announced_leap(self):
        self.assertFalse(clock.health(self.tracking, self.sources, self.now + 301)['healthy'])
        self.assertFalse(clock.health(self.tracking.replace('Normal', 'Not synchronised'),
            self.sources, self.now)['healthy'])
        self.assertTrue(clock.health(self.tracking.replace('Normal', 'Insert second'),
            self.sources, self.now)['healthy'])

    def test_malformed_and_nonfinite_reports_fail_closed(self):
        for tracking in ('unexpected', self.tracking.replace('0.00001', 'nan')):
            with self.assertRaises(ValueError):
                clock.health(tracking, self.sources, self.now)


if __name__ == '__main__':
    unittest.main()
