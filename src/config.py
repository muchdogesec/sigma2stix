import logging
from uuid import UUID
from stix2 import FileSystemStore
from .utils import check_dir

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)

namespace = UUID("860f4c0f-8c26-5889-b39d-ce94368bc416")
source_repo = "https://github.com/SigmaHQ/sigma.git"
temporary_path = "data"
file_system_path = "stix2_objects"
check_dir(file_system_path)
fs = FileSystemStore(file_system_path)
SIGMA2STIX_MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/sigma2stix.json"
SIGMA2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/sigma2stix.json"
MITRE_TECHNIQUE_PATH = "https://attack.mitre.org/techniques/{}"
CVE_PATH = "https://nvd.nist.gov/vuln/detail/{}"