import os
from secret_harvest.github_manager import GitHubManager
from secret_harvest.file_manager import FileManager
from secret_harvest.utility import Utility

destination_folder = "/tmp"
harvest_folder = None


def main(args):

    global destination_folder
    global harvest_folder

    max_repos = 30
    destination_folder = "/tmp/"
    results_folder = os.path.join(destination_folder, "secret_harvest")
    clone_folder = os.path.join(destination_folder, "inspect_packages")
    repo_blacklist = [
        ""
    ]

    FileManager.delete_folder(clone_folder)
    github = GitHubManager(clone_folder, repo_blacklist)

    if not Utility.is_trufflehog_installed():
        print("trufflehog3 is missing. Please install it.")

    repos = github.search_code_repositories(args.keywords, max_repos)
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

    Utility.extract_all_files_with_findings("output.json")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("keywords", nargs="+")
    args = parser.parse_args()
    main(args)
