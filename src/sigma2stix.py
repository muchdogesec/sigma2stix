import itertools
import logging
from pathlib import Path
import uuid
from tqdm import tqdm
from src import config
from src import utils
from src.parser import SigmaParser
from stix2.datastore.filters import Filter
from stix2 import Relationship
from src.retriever import STIXObjectRetriever

class Sigma2Stix:

    def __init__(self, branch):
        self.parser = SigmaParser()
        self.tag = branch
        print(self.tag)

    #
    @staticmethod
    def prepare_bundle():
        utils.store_in_bundle(
            utils.append_data()
        )

    def run(self, mode, yamlfiles:Path):
        files = []

        utils.clean_filesystem(config.temporary_path)
        utils.clean_filesystem(config.file_system_path)
        if mode == 'sigmahq':
            logging.info("Cloning start. tag: `%s`", self.tag)
            utils.clone_github_repository(config.source_repo, config.temporary_path, tag_name=self.tag)
            logging.info("Cloning end")
            utils.delete_files_and_folders_except_rules()
            files = utils.get_all_yaml_files()
        elif mode == 'sigmayaml':
            files = [{mode: yamlfiles}]

        #print(files)
        self.parser.parse_marking_definition()
        self.parser.parse_identity()

        data_list = []
        for d in tqdm(files):
            temp_data = []
            for file in d.get(list(d.keys())[0]):
                data = utils.read_yaml_file(file)
                if mode == 'sigmahq':
                    git_path = '/'.join(Path(file).parts[1:])
                    url = f"https://github.com/SigmaHQ/sigma/blob/{self.tag}/{git_path}"
                elif mode == 'sigmayaml':
                    url = Path(file).absolute().as_uri()
                temp_data += self.parser.parse_indicator(data, file, url)
                data_list += temp_data
                if data.get("related", None):
                    data_list += self.parser.parse_relationship(data['related'])

            if len(temp_data)>0 and mode == 'sigmahq':
                temp_data_ = []
                temp_data_ += [d.get("id") for d in temp_data]
                data_list += self.parser.parse_grouping({
                    "path": list(d.keys())[0][5:],
                    "indicators": temp_data_,
                })

        self.process_cve_objects()
        self.prepare_bundle()
        utils.clean_filesystem(config.temporary_path)

    def process_cve_objects(self):
        indicators = config.fs.query([Filter("type", "=", "indicator")])
        indicator_cve_id_map : dict[str, list[str]] = {}
        for indicator in indicators:
            cves = []
            for ref in indicator['external_references']:
                if ref['source_name'] == 'cve':
                    cves.append(ref['external_id'])
            if cves:
                indicator_cve_id_map[indicator['id']] = cves
        cve_ids = itertools.chain(*indicator_cve_id_map.values())
        cve_objects = STIXObjectRetriever('vulmatch').get_vulnerabilities(cve_ids)
        for indicator in indicators:
            indicator_id = indicator['id']
            cve_ids = indicator_cve_id_map.get(indicator_id)
            if not cve_ids:
                continue
            for cve_id in cve_ids:
                cve_obj = cve_objects.get(cve_id)
                if not cve_obj:
                    continue
                cve_obj = cve_obj[0]
                
                relationship = dict(
                    type="relationship",
                    spec_version="2.1",
                    created_by_ref=indicator['created_by_ref'],
                    created=indicator['created'],
                    modified=indicator['modified'],
                    relationship_type="detects",
                    source_ref=indicator_id,
                    target_ref=cve_obj['id'],
                    description=f"{indicator['name']} detects {cve_id}",
                    object_marking_refs=indicator['object_marking_refs'],
                )
                relationship['id'] = "relationship--" + str(uuid.uuid5(config.namespace, "{relationship_type}/{source_ref}/{target_ref}".format_map(relationship)))
                config.fs.add(Relationship(**relationship, allow_custom=True))
                logging.debug("add cve relationship: {description} {source_ref}/{relationship_type}/{target_ref}".format_map(relationship))

