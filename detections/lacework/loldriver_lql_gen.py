"""Generate the Lacework query from this revision's local validated catalog."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'bin'))
from detection_generation import REPO, build_outputs
from indicator_safety import load_catalog

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=REPO / 'yaml')
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('LOLDriver_Malicious_Hashes.yaml'))
    args = parser.parse_args()
    # No network fetch or execution of samples; use the shared generator.
    outputs = build_outputs(load_catalog(args.catalog), Path('/nonexistent/no-driver-input'))
    args.output.write_text(outputs['detections/lacework/LOLDriver_Malicious_Hashes.yaml'])
