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
                    data_list += self.parser.parse_relationship(data)

            if len(temp_data)>0 and mode == 'sigmahq':
                temp_data_ = []
                temp_data_ += [d.get("id") for d in temp_data]
                data_list += self.parser.parse_grouping({
                    "path": list(d.keys())[0][5:],
                    "indicators": temp_data_,
                })

        self.process_cve_objects()
        self.process_attack_objects()
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
        logging.info("Resolving CVE Relationships")
        cve_objects = STIXObjectRetriever('vulmatch').get_vulnerabilities(cve_ids)
        self.process_objects(indicators, indicator_cve_id_map, retrieved_objects=cve_objects, relationship_type='detects')
        
    def process_attack_objects(self):
        indicators = config.fs.query([Filter("type", "=", "indicator")])
        indicator_attack_id_map : dict[str, list[str]] = {}
        indicator_attack_tactic_map = {}
        for indicator in indicators:
            attack_ids = []
            attack_names = []
            for ref in indicator['external_references']:
                if ref['source_name'] != 'mitre-attack':
                    continue
                if ref.get('description') == 'tactic':
                    attack_names.append(ref['external_id'])
                else:
                    attack_ids.append(ref['external_id'])
            if attack_ids:
                indicator_attack_id_map[indicator['id']] = attack_ids
            if attack_names:
                indicator_attack_tactic_map[indicator['id']] = attack_names
        attack_ids = tuple(itertools.chain(*indicator_attack_id_map.values()))
        for matrix in ['enterprise', 'ics', 'mobile']:
            logging.info(f"Resolving ATT&CK {matrix.upper()} #1: Using ATT&CK ID")
            attack_objects = STIXObjectRetriever('ctibutler').get_objects_by_external_ids(attack_ids, f'attack-{matrix}', 'objects', 'attack_id')
            self.process_objects(indicators, indicator_attack_id_map, retrieved_objects=attack_objects, relationship_type='detects')
            logging.info(f"Resolving ATT&CK {matrix.upper()} Relationships #2: Using ATT&CK Tactic Name")
            tactic_objects = STIXObjectRetriever('ctibutler').get_attack_tactics(matrix)
            self.process_objects(indicators, indicator_attack_tactic_map, retrieved_objects=tactic_objects, relationship_type='detects')
    
    def process_objects(self, indicators, indicator_to_id_map, retrieved_objects, relationship_type='detects'):
        for indicator in indicators:
            indicator_id = indicator['id']
            object_keys = indicator_to_id_map.get(indicator_id)
            if not object_keys:
                continue
            for obj_key in object_keys:
                for obj in retrieved_objects.get(obj_key, []):
                    relationship = dict(
                        type="relationship",
                        spec_version="2.1",
                        created_by_ref=indicator['created_by_ref'],
                        created=indicator['created'],
                        modified=indicator['modified'],
                        relationship_type=relationship_type,
                        source_ref=indicator_id,
                        target_ref=obj['id'],
                        description=f"{indicator['name']} detects {obj_key}",
                        object_marking_refs=indicator['object_marking_refs'],
                    )
                    relationship['id'] = "relationship--" + str(uuid.uuid5(config.namespace, "{relationship_type}/{source_ref}/{target_ref}".format_map(relationship)))
                    config.fs.add(Relationship(**relationship, allow_custom=True))
                    logging.debug("add relationship: {description} {source_ref}/{relationship_type}/{target_ref}".format_map(relationship))

        
