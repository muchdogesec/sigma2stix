import argparse
from src.sigma2stix import Sigma2Stix
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def filetype(file):
    path = Path(file)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{path.absolute()} is not a file")
    return path

parser = argparse.ArgumentParser(description='Run Sigma2Stix with specific Sigma version tag.')
parser.add_argument('--sigma_version_tag', type=str, help='Sigma version tag to use', default='r2024-02-26')
parser.add_argument('--mode', choices=["sigmahq", "sigmayaml"], required=True)
fileaction = parser.add_argument('--file', type=filetype, nargs='+')
args = parser.parse_args()

if args.mode == "sigmayaml" and not args.file:
    parser.error(f"{'/'.join(fileaction.option_strings)} is required in mode {args.mode}")

Sigma2Stix(branch=args.sigma_version_tag).run(args.mode, args.file)