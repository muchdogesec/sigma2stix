import logging
from pathlib import Path
from tqdm import tqdm
from src import config
from src import utils
from src.parser import SigmaParser


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
                    url = f"https://github.com/SigmaHQ/sigma/blob/master/{file[5:]}"
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

        self.prepare_bundle()
        utils.clean_filesystem(config.temporary_path)

