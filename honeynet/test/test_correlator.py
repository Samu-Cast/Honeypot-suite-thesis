import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../correlator"))

os.environ.setdefault("SESSION_WINDOW_SECS", "15")
os.environ.setdefault("BRUTE_FORCE_THRESHOLD", "5")

from correlator import classify_pattern

THRESHOLD = 5


def classify(cowrie=0, dionaea=0, canary=0):
    return classify_pattern(cowrie, dionaea, canary, threshold=THRESHOLD)


class TestFullSpectrum:
    def test_one_hit_each(self):
        assert classify(cowrie=1, dionaea=1, canary=1) == "FULL_SPECTRUM"

    def test_many_hits(self):
        assert classify(cowrie=10, dionaea=5, canary=3) == "FULL_SPECTRUM"

    def test_beats_brute_force(self):
        assert classify(cowrie=20, dionaea=1, canary=1) == "FULL_SPECTRUM"


class TestSSHThenPayload:
    def test_basic(self):
        assert classify(cowrie=1, dionaea=1, canary=0) == "SSH_THEN_PAYLOAD"

    def test_many_cowrie_with_dionaea(self):
        assert classify(cowrie=10, dionaea=2, canary=0) == "SSH_THEN_PAYLOAD"


class TestSSHThenLateral:
    def test_basic(self):
        assert classify(cowrie=1, dionaea=0, canary=1) == "SSH_THEN_LATERAL"

    def test_many_cowrie(self):
        assert classify(cowrie=20, dionaea=0, canary=1) == "SSH_THEN_LATERAL"


class TestPayloadAndLateral:
    def test_basic(self):
        assert classify(cowrie=0, dionaea=1, canary=1) == "PAYLOAD_AND_LATERAL"

    def test_many_hits(self):
        assert classify(cowrie=0, dionaea=5, canary=3) == "PAYLOAD_AND_LATERAL"


class TestBruteForceSSH:
    def test_above_threshold(self):
        assert classify(cowrie=THRESHOLD + 1, dionaea=0, canary=0) == "BRUTE_FORCE_SSH"

    def test_many_hits(self):
        assert classify(cowrie=100, dionaea=0, canary=0) == "BRUTE_FORCE_SSH"

    def test_at_threshold_is_not_brute_force(self):
        # strictly greater-than, so == threshold -> LOW_SSH_ACTIVITY
        assert classify(cowrie=THRESHOLD, dionaea=0, canary=0) == "LOW_SSH_ACTIVITY"


class TestAutomatedExploit:
    def test_basic(self):
        assert classify(cowrie=0, dionaea=1, canary=0) == "AUTOMATED_EXPLOIT"

    def test_many_dionaea(self):
        assert classify(cowrie=0, dionaea=50, canary=0) == "AUTOMATED_EXPLOIT"


class TestReconOnly:
    def test_basic(self):
        assert classify(cowrie=0, dionaea=0, canary=1) == "RECON_ONLY"

    def test_many_canary(self):
        assert classify(cowrie=0, dionaea=0, canary=10) == "RECON_ONLY"


class TestLowSSHActivity:
    def test_one_hit(self):
        assert classify(cowrie=1, dionaea=0, canary=0) == "LOW_SSH_ACTIVITY"

    def test_up_to_threshold(self):
        assert classify(cowrie=THRESHOLD, dionaea=0, canary=0) == "LOW_SSH_ACTIVITY"

    def test_two_hits(self):
        assert classify(cowrie=2, dionaea=0, canary=0) == "LOW_SSH_ACTIVITY"


class TestUnknown:
    def test_no_hits(self):
        assert classify(cowrie=0, dionaea=0, canary=0) == "UNKNOWN"


class TestCustomThreshold:
    def test_lower_threshold(self):
        assert classify_pattern(3, 0, 0, threshold=2) == "BRUTE_FORCE_SSH"

    def test_higher_threshold(self):
        assert classify_pattern(5, 0, 0, threshold=10) == "LOW_SSH_ACTIVITY"
