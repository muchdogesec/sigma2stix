import json

from stix2 import Indicator, Grouping, Relationship, parse, Identity
from datetime import datetime, date
from src import config
from src import utils
import uuid
import re


def as_date(d):
    if isinstance(d, datetime) or isinstance(d, date):
        return d
    return datetime.strptime(d, "%Y/%m/%d")
    

class SigmaParser:

    @classmethod
    def parse_indicator(cls, data:dict, path:str, url: str) -> list:
        data_list = []
        id = data.get('id')
        if not config.fs.get(f"indicator--{id}"):
            try:
                id = str(uuid.uuid5(config.namespace, f"{id}+sigma"))
                indicator = Indicator(
                    id=f"indicator--{id}",
                    created_by_ref=utils.get_data_from_fs("identity")[0],
                    created=as_date(data.get('date')),
                    modified=as_date(data.get('modified') if data.get('modified') else data.get('date')),
                    indicator_types=["malicious-activity","anomalous-activity"],
                    name=data.get("title"),
                    description=f"{data.get('description')}. The following false positives can result from this detection; {', '.join(data.get('falsepositives',[]))}",
                    pattern=data,
                    pattern_type="sigma",
                    valid_from=as_date(data.get('date')),
                    external_references=[
                        {
                            "source_name": "sigma-rule",
                            "external_id": "rule",
                            "url": url
                        }
                    ] + cls.process_tags_and_labels(data) + utils.generate_all_references(data),
                    object_marking_refs=[
                        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                    ]+[utils.get_data_from_fs("marking-definition")[0]]
                )
                data_list.append(indicator)
                config.fs.add(indicator)
            except Exception as e:
                pass
        return data_list

    @staticmethod
    def parse_relationship(data:list):
        data_list = []
        for relation in data: 
            source_object_id = uuid.uuid5(config.namespace, f"{data.get('id')}+sigma")
            target_object_id = uuid.uuid5(config.namespace, f"{relation.get('id')}+sigma")
            id = f'indicator--{source_object_id}+' + f'indicator--{target_object_id}'
            id = str(uuid.uuid5(config.namespace, f"{id}"))
            if config.fs.get(f"relationship--{id}"):
                continue

            relation = Relationship(
                id=f"relationship--{id}",
                created_by_ref=utils.get_data_from_fs("identity")[0],
                created=as_date(data.get('date')),
                modified=as_date(data.get('modified') if data.get('modified') else data.get('date')),
                relationship_type=relation.get('type'),
                source_ref=f"indicator--{source_object_id}",
                target_ref=f"indicator--{target_object_id}",
                object_marking_refs=[
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                ]+[utils.get_data_from_fs("marking-definition")[0]]
            )
            config.fs.add(relation)
            data_list.append(relation.serialize())
        return data_list

    @classmethod
    def process_tags_and_labels(cls, data: dict):
        references = []
        for key in ['id', 'level', 'status', 'author', 'license']:
            if value := data.get(key):
                references.append(dict(source_name='sigma-rule', external_id=key, description=value))
        for tag in data.get('tags', []):
            if match := re.match(r'detection\.(.*)', tag):
                references.append(dict(source_name='sigma-rule', external_id='detection', description=match.group(1)))
            elif match := re.match(r'(cve\..*)', tag):
                cve_id = match.group(1).replace(".", '-').upper()
                references.append(dict(source_name='cve', external_id=cve_id, url=config.CVE_PATH.format(cve_id)))
            elif match := re.match(r'attack\.(t.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=config.MITRE_TECHNIQUE_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(s.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=config.MITRE_SOFTWARE_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(g.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=config.MITRE_GROUP_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(.*)', tag):
                attack_id = match.group(1).replace('_', '-')
                references.append(dict(source_name='mitre-attack', external_id=attack_id, description='tactic')) #, url=config.TECHNIQUE_PATH.format(attack_id)))
        return references    

    @staticmethod
    def parse_grouping(data:dict)-> list:
        id = str(uuid.uuid5(config.namespace, f"{data.get('path')}"))
        grouping = Grouping(
            id=f"grouping--{id}",
            context="suspicious-activity",
            created_by_ref=utils.get_data_from_fs("identity")[0],
            created=config.fs.get(data.get("indicators")[0]).get("created"),
            modified=config.fs.get(data.get("indicators")[0]).get("modified"),
            name=f"{data.get('path')}",
            object_refs=data.get("indicators"),
            object_marking_refs=[
                        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
                    ]+[utils.get_data_from_fs("marking-definition")[0]]
        )
        config.fs.add(grouping)
        return [grouping.serialize()]

    @staticmethod
    def parse_marking_definition():
        marking_definition = parse(
            json.loads(utils.load_file_from_url(config.SIGMA2STIX_MARKING_DEFINITION_URL))
        )
        if not config.fs.get(marking_definition.get("id")):
            config.fs.add(marking_definition)
        return marking_definition

    @staticmethod
    def parse_identity():
        identity = parse(
            json.loads(utils.load_file_from_url(config.SIGMA2STIX_IDENTITY_URL))
        )
        if not config.fs.get(identity.get("id")):
            config.fs.add(identity)
        return identity
