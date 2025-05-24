import os
import subprocess
import json
import hashlib
import time
import shutil
import random
from typing import List, Any
from pygments.lexers import get_lexer_for_filename
from secret_harvest.file_manager import FileManager
from tabulate import tabulate


class Utility:

    @staticmethod
    def is_trufflehog_installed() -> bool:
        try:
            # Check if the trufflehog3 binary is available on the system's PATH
            subprocess.run(
                ["trufflehog3",
                 "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def clean_up():
        base_dirs = [
            '/tmp/inspect_packages'
        ]

        for folder in base_dirs:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)

                    try:
                        if (os.path.isfile(item_path) or
                                os.path.islink(item_path)):

                            os.unlink(item_path)

                        elif os.path.isdir(item_path):

                            print(f"Deleting Folder {item_path}")
                            shutil.rmtree(item_path)

                    except Exception as e:
                        print(f"Failed to delete {item_path}: {e}")

    @staticmethod
    def setup_directories():
        required_dirs = [
            '/tmp/inspect_packages',
            '/tmp/secret_harvest',
            '/tmp/secret_harvest/to_verify',
            '/tmp/secret_harvest/to_verify/files',
            '/tmp/secret_harvest/to_verify/meta',
            '/tmp/secret_harvest/to_verify/snipet',
            '/tmp/secret_harvest/verified',
            '/tmp/secret_harvest/verified/files',
            '/tmp/secret_harvest/verified/meta',
            '/tmp/secret_harvest/verified/snipet',
        ]

        for directory in required_dirs:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                print(f"Failed to create {directory}: {e}")

    @staticmethod
    def calculate_sha1(input_string: str) -> str:
        input_bytes = input_string.encode('utf-8')
        sha1_hash = hashlib.sha1(input_bytes)
        hex_digest = sha1_hash.hexdigest()
        return hex_digest

    @staticmethod
    def enrich_found_credentials(destination_folder,
                                 found_credentials: List[dict]):

        data = [("Filename", "File-Type", "Credential")]

        for credential in found_credentials:

            del credential['author']
            del credential['branch']
            del credential['commit']
            del credential['date']
            del credential['message']

            path = credential["path"]
            rule_name = credential["rule"]["message"]
            line_number = int(credential["line"])

            filename = path.split('/')[-1]
            try:
                type_file = get_lexer_for_filename(filename).name
            except Exception:
                type_file = "UNKNOWN"

            full_path = os.path.join(destination_folder, path)
            file_num_lines = FileManager.count_lines(full_path)

            if (line_number + 5) < file_num_lines:
                start_line = line_number - 5
                end_line = line_number + 5
            else:
                start_line = line_number - 5
                end_line = file_num_lines

            credential["snippet_start_line"] = start_line
            credential["snippet_end_line"] = end_line
            credential["full_path"] = full_path
            credential["file_name"] = filename
            credential["file_type"] = type_file
            credential["secret_sha1"] = Utility.calculate_sha1(
                credential["secret"]
                )

            data.append((
                filename,
                type_file,
                rule_name
            ))

        print(tabulate(data, headers="firstrow"))

    @staticmethod
    def run_trufflehog_scan(destination_path: str) -> Any:

        print("Scanning for Secrets using trufflehog3")
        output_file = "output.json"
        result = None
        cmd = (f"trufflehog3 {destination_path}"
               f" --no-entropy -f JSON -o {output_file}")
        print(f"Command {cmd}")
        try:
            subprocess.run(cmd,
                           shell=True,
                           check=True)

        except subprocess.CalledProcessError as e:
            if e.returncode != 2:
                print(f"Error running trufflehog3: {e}")
                return None

        with open(output_file, 'r') as f:
            result = json.load(f)
        #     os.remove(output_file)

        if result is None:
            return []

        for entry in result:
            entry["path"] = os.path.join(
                "/tmp/inspect_packages",
                entry["path"]
                )
            print(entry["path"])

        return result

    @staticmethod
    def extract_all_files_with_findings(file_path):
        all_paths = []
        with open(file_path, 'r') as file:
            data = json.load(file)
            for entry in data:
                all_paths.append(entry["path"])
        return all_paths

    @staticmethod
    def enumerate_clean_files(folder_path,
                              files_with_findings):
        result_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path not in files_with_findings:
                    result_files.append(file_path)

        return result_files

    @staticmethod
    def copy_files_by_hash(hashes,
                           desposition_folder,
                           base_dir='/tmp/secret_harvest'):

        to_verify_dir = os.path.join(base_dir, 'to_verify')

        for subfolder in ['files', 'meta', 'snipet']:
            source_subdir = os.path.join(to_verify_dir, subfolder)
            dest_subdir = os.path.join(desposition_folder, subfolder)

            os.makedirs(dest_subdir, exist_ok=True)

            for filename in os.listdir(source_subdir):

                if any(hash_str in filename for hash_str in hashes):
                    src_path = os.path.join(source_subdir, filename)
                    dst_path = os.path.join(dest_subdir, filename)
                    print(f"Copy {src_path} {dst_path}")
                    shutil.copy(src_path, dst_path)

    @staticmethod
    def delete_files_by_hash(hashes,
                             base_dir='/tmp/secret_harvest'):

        to_verify_dir = os.path.join(base_dir, 'to_verify')

        for subfolder in ['files', 'meta', 'snipet']:
            folder_path = os.path.join(to_verify_dir, subfolder)

            for filename in os.listdir(folder_path):
                if any(hash_str in filename for hash_str in hashes):
                    file_path = os.path.join(folder_path, filename)
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Failed to delete {file_path}: {e}")

    @staticmethod
    def review_pending_entries(folder_path):

        confirmed_hashes = []
        rejected_hashes = []

        def clear_screen():
            os.system('cls' if os.name == 'nt' else 'clear')

        dir_list = os.listdir(folder_path)
        random.shuffle(dir_list)

        for filename in dir_list[0:10]:

            file_path = os.path.join(folder_path, filename)

            if os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8',
                          errors='ignore') as f:
                    content = f.read()

                    print(f"--- {filename} ---")
                    print("\n")
                    print("\n")
                    print(content)
                    print("\n")
                    print("\n")

                    prompt = "Is this verified? (y/n): "
                    response = input(prompt).strip().lower()
                    if response == "y":
                        hash = filename.split("_")[1]
                        confirmed_hashes.append(hash)
                    else:
                        hash = filename.split("_")[1]
                        rejected_hashes.append(hash)

                    time.sleep(2)
                    clear_screen()

        combined_hashes = confirmed_hashes + rejected_hashes

        Utility.copy_files_by_hash(confirmed_hashes,
                                   "/tmp/secret_harvest/verified")
        Utility.copy_files_by_hash(rejected_hashes,
                                   "/tmp/secret_harvest/false_positives")
        Utility.delete_files_by_hash(combined_hashes)
