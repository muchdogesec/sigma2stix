import os
import shutil
import uuid
import json
import yaml
import hashlib
import requests
from git import Repo
from typing import List
from src import config
from stix2 import Bundle
from stix2 import Filter

def clone_github_repository(repo_url, destination_path, tag_name):
    try:
        repo = Repo.clone_from(repo_url, destination_path, branch=tag_name)
        print(f"Repository cloned successfully to {destination_path}")
    except Exception as e:
        print(f"Failed to clone repository: {e}")


def check_dir(dir:str):
    if not os.path.exists(dir):
        os.makedirs(dir)



def delete_files_and_folders_except_rules(prefix='rules', keep_count=2):
    directory_path = 'data'
    all_items = os.listdir(directory_path)
    rules_folders = [item for item in all_items if item.startswith(prefix)]
    rules_folders.sort()
    folders_to_keep = rules_folders[:keep_count]
    for item in all_items:
        item_path = os.path.join(directory_path, item)
        if os.path.isdir(item_path) and not item.startswith(prefix):
            if item not in folders_to_keep:
                shutil.rmtree(item_path)
                print(f"Deleted: {item_path}")
        elif os.path.isfile(item_path):
            if not item.startswith(prefix):
                os.remove(item_path)


def get_all_yaml_files(folder="data"):
    file_with_path = []
    for root, dirs, files in list(os.walk(folder)):
        yaml_files = []
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                yaml_files.append(file_path)
        if len(yaml_files)>1:
            file_with_path.append({root:yaml_files})
    return file_with_path


def read_yaml_file(file_path):
    try:
        with open(file_path, 'r') as file:
            yaml_data = yaml.safe_load(file)
            return yaml_data
    except Exception as e:
        print(f"Error reading YAML file: {e}")
        return None


def generate_all_references(data:dict) -> List[dict]:
    return [
        {"source_name": "sigma-rule", "external_id": "reference", "description": reference}
        for reference in data.get("references", [])
    ]


def clean_filesystem(path):
    try:
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
    except Exception as e:
        print(e)
        pass


def append_data():
    results = []
    for root, _, files in os.walk(config.file_system_path):
        for filename in files:
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                with open(file_path, "r") as file:
                    stix_object = json.load(file)
                    results.append(stix_object)
    return results


def generate_md5_from_list(stix_objects: list) -> str:
    json_str = json.dumps(stix_objects, sort_keys=True).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()


def store_in_bundle(stix_objects):
    bundle_id = "bundle--" + str(uuid.uuid5(
        config.namespace, generate_md5_from_list(stix_objects))
    )
    bundle_of_all_objects = Bundle(id=bundle_id, objects=stix_objects)
    stix_bundle_file = f"{config.file_system_path}/sigma-rule-bundle.json"
    with open(stix_bundle_file, "w") as f:
        f.write(json.dumps(json.loads(bundle_of_all_objects.serialize()), indent=4))


def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error loading JSON from {url}: {e}")
        return None


def get_data_from_fs(query:str):
    query = [Filter("type", "=", query)]
    return config.fs.query(query)
