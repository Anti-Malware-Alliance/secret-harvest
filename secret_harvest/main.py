import json
import subprocess
import hashlib
import os
from pathlib import Path
from typing import List, Any
from pprint import pprint
from pygments.lexers import get_lexer_for_filename
from file_manager import GitHubManager

destination_folder = "/tmp"
harvest_folder = None

def is_trufflehog3_installed() -> bool:
    try:
        # Check if the trufflehog3 binary is available on the system's PATH
        subprocess.run(["trufflehog3", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_trufflehog_scan(destination_path: str) -> Any:
    output_file = "output.json"
    result = None

    try:
        subprocess.run(f"trufflehog3 filesystem {destination_path} --no-entropy -f JSON -o {output_file}", shell=True, check=True)
        
    except subprocess.CalledProcessError as e:
        if e.returncode != 2:
            print(f"Error running trufflehog3: {e}")
            return None

    with open(output_file, 'r') as f:
        result = json.load(f)
        #os.remove(output_file)

    return result

def count_lines(filename):
    try:
        with open(filename, 'r') as file:
            line_count = file.read().count('\n')
        return line_count + 1
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None

def save_found_credentials(found_credentials: List[str]):
    global harvest_folder

    for credential in found_credentials:
        snippet_file = os.path.join(harvest_folder, f"{credential['secret_sha1']}_{credential['file_name']}")
        metadata_file = os.path.join(harvest_folder, f"{credential['secret_sha1']}_{credential['file_name']}.metadata")
        save_snippet(credential["full_path"], snippet_file,  credential["snippet_start_line"], credential["snippet_end_line"])
        save_credential_metadata(credential, metadata_file)

def save_snippet(input_filename: str, output_filename :str, start_line: int, end_line: int):
    try:
        with open(input_filename, 'r') as input_file:
            lines = input_file.readlines()

            start_line -= 1
            end_line -= 1
            
            extracted_content = lines[start_line:end_line+1]

        with open(output_filename, 'w') as output_file:
            output_file.writelines(extracted_content)

    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.")

def save_credential_metadata(credential: str, output_file: str):
        with open(output_file, 'w') as output_file:
            json.dump(credential, output_file, indent=4)

def calculate_sha1(input_string: str) -> str:
    input_bytes = input_string.encode('utf-8')
    sha1_hash = hashlib.sha1(input_bytes)
    hex_digest = sha1_hash.hexdigest()
    return hex_digest

def enrich_found_credentials(found_credentials: List[str]):

    global destination_folder
    global harvest_folder

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
        except Exception as e:
            type_file = "Uk"

        full_path = os.path.join(destination_folder, path)
        file_num_lines = count_lines(full_path)

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
        credential["secret_sha1"] = calculate_sha1(credential["secret"])

        print(f"Filename : {filename} FileType:{type_file} Rule:{rule_name}")

def delete_results(folder_path: str):
    try:
        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
    except Exception as e:
        print(f"Error: Failed to delete files in the folder. {e}")

def main(args):
    
    global destination_folder
    global harvest_folder
    
    max_repos = 30
    destination_folder = "/tmp"
    harvest_folder = os.path.join(destination_folder, "secret_harvest")
    repo_blacklist = [
        ""
    ]

    github = GitHubManager(destination_folder)

    delete_results(harvest_folder)

    if not is_trufflehog3_installed():
        print("trufflehog3 is missing. Please install it.")

    repos = github.search_code_repositories(args.keywords, max_repos)
    print(f"Found {len(repos)} repositories")

    github.clone_repositories(repos)
    found_credentials = run_trufflehog_scan(destination_folder)

    print(f"Found {len(found_credentials)} Credentials")
    print("--------------------------------------------------------")

    dest_path = os.path.join(destination_folder, "secret_harvest")
    if not os.path.exists(dest_path):
        try:
            os.mkdir(dest_path)
        except Exception as e:
            print(f"Error: Failed to create folder '{dest_path}'. {e}")

    enrich_found_credentials(found_credentials)
    save_found_credentials(found_credentials)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("keywords", nargs="+")
    args = parser.parse_args()
    main(args)

