import os
from github_manager import GitHubManager
from file_manager import FileManager
from utility import Utility
from pprint import pprint

destination_folder = "/tmp"
harvest_folder = None




def main(args):

    global destination_folder
    global harvest_folder

    max_repos = 30
    destination_folder = "/tmp/"
    results_folder = os.path.join(destination_folder, "secret_harvest/to_verify")
    clone_folder = os.path.join(destination_folder, "inspect_packages")
    repo_blacklist = [
        ""
    ]

    FileManager.delete_folder(clone_folder)
    github = GitHubManager(clone_folder, repo_blacklist)

    if not Utility.is_trufflehog_installed():
        print("trufflehog3 is missing. Please install it.")

    repos = github.search_code_repositories(args.search, max_repos)
    print(f"Found {len(repos)} repositories")

    github.clone_repositories(repos)
    found_credentials = Utility.run_trufflehog_scan(clone_folder)

    if len(found_credentials) == 0:
        print(f"Found {len(found_credentials)} Credentials")
    print(f"Found {len(found_credentials)} Credentials")
    print("--------------------------------------------------------")

    if not os.path.exists(results_folder):
        try:
            os.mkdir(results_folder)
        except Exception as e:
            print(f"Error: Failed to create folder '{results_folder}'. {e}")

    Utility.enrich_found_credentials(clone_folder, found_credentials)
    FileManager.save_found_credentials(results_folder, found_credentials)
    FileManager.delete_folder(clone_folder)

    files = Utility.extract_all_files_with_findings("output.json")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--search", nargs="+", help="Optional list of keywords")
    parser.add_argument("--clean", action="store_true", help="Trigger cleanup and exit")
    parser.add_argument("--verify", action="store_true", help="Trigger cleanup and exit")
    args = parser.parse_args()

    Utility.setup_directories()

    if args.clean:
        Utility.clean_up()
    elif args.verify:
        Utility.review_pending_entries("/tmp/secret_harvest/to_verify/snipet")
    elif args.search:
        main(args)

