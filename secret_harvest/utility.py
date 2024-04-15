import os
import subprocess
import json
import hashlib
from typing import List, Any
from pygments.lexers import get_lexer_for_filename
from file_manager import FileManager
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
        cmd = (f"trufflehog3 filesystem {destination_path}"
               f"--no-entropy -f JSON -o {output_file}")
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
    def enumerate_clean_files(folder_path, files_with_findings):
        result_files = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path not in files_with_findings:
                    result_files.append(file_path)

        return result_files
