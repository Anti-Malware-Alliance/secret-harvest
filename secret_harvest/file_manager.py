import os
import json
import shutil
from typing import Dict, List


class FileManager:

    @staticmethod
    def count_lines(filename: str):
        try:
            with open(filename, 'r') as file:
                line_count = file.read().count('\n')
            return line_count + 1
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            return None

    @staticmethod
    def save_found_credentials(harvest_folder: str,
                               found_credentials: List[Dict]):
        for credential in found_credentials:

            print("Inside of Save Found Credentials")
            snippet_file = os.path.join(
                harvest_folder, "snipet", 
                f"snip_{credential['secret_sha1']}_{credential['file_name']}"
                )
            
            carried_over_file = os.path.join(
                harvest_folder, "files", 
                f"snip_{credential['secret_sha1']}_{credential['file_name']}"
            )
            
            metadata_file = os.path.join(
                harvest_folder, "meta", 
                f"{credential['secret_sha1']}_{credential['file_name']}.meta"
                )
            
            shutil.copy(credential["full_path"], carried_over_file)

            FileManager.save_snippet(credential["full_path"],
                                     snippet_file,
                                     credential["snippet_start_line"],
                                     credential["snippet_end_line"])
            FileManager.save_credential_metadata(credential, metadata_file)

    @staticmethod
    def save_snippet(input_filename: str,
                     output_filename: str,
                     start_line: int,
                     end_line: int):
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

    @staticmethod
    def save_credential_metadata(credential: dict, output_file: str):
        with open(output_file, 'w') as file_object:
            json.dump(credential, file_object, indent=4)

    @staticmethod
    def delete_folder(folder_path: str):
        try:
            for file_name in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file_name)
                if os.path.isfile(file_path):
                    os.remove(file_path)
        except Exception as e:
            print(f"Error: Failed to delete files in the folder. {e}")
