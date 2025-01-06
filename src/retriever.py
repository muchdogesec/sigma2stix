import json
from pathlib import Path
from urllib.parse import urljoin
import  os
import stix2
import requests



class STIXObjectRetriever:
    def __init__(self, host="ctibutler") -> None:
        if host == "ctibutler":
            self.api_root = os.environ['CTIBUTLER_HOST']
            self.api_key = os.environ.get('CTIBUTLER_API_KEY')
        elif host == "vulmatch":
            self.api_root = os.environ['VULMATCH_HOST']
            self.api_key = os.environ.get('VULMATCH_API_KEY')
        else:
            raise NotImplementedError("The type `%s` is not supported", host)

    def get_attack_objects(self, matrix, attack_id):
        endpoint = urljoin(self.api_root, f"/api/v1/attack-{matrix}/objects/{attack_id}/")
        return self._retrieve_objects(endpoint)
    
    def get_objects_by_external_ids(self, ids, type, key='objects', query_filter='id'):
        objects = self._retrieve_objects(urljoin(self.api_root, f"/api/v1/{type}/objects/?{query_filter}={','.join(ids)}"), key)
        objects_map : dict[str, list[dict]] = {}
        for obj in objects:
            object_id = obj['external_references'][0]['external_id']
            arr = objects_map.setdefault(object_id, [])
            arr.append(obj)
        return objects_map
    
    def get_attack_tactics(self, matrix):
        objects = self._retrieve_objects(urljoin(self.api_root, f"/api/v1/attack-{matrix}/objects/?type=x-mitre-tactic"), 'objects')
        objects_map : dict[str, list[dict]] = {}
        for obj in objects:
            name = obj['x_mitre_shortname']
            objects_map.setdefault(name, []).append(obj)
        return objects_map
    
    def get_vulnerabilities(self, cve_ids):
        return self.get_objects_by_external_ids(cve_ids, 'cve', 'objects', 'cve_id')
    
    def _retrieve_objects(self, endpoint, key='objects'):
        s = requests.Session()
        s.headers.update({
            "API-KEY": self.api_key
        })
        data = []
        page = 1
        while True:
            resp = s.get(endpoint, params=dict(page=page, page_size=50))
            if resp.status_code != 200:
                break
            d = resp.json()
            if len(d[key]) == 0:
                break
            data.extend(d[key])
            page+=1
            if d['page_results_count'] < d['page_size']:
                break
        return data
   