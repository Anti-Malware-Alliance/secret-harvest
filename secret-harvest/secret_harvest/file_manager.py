from typing import List, Any
import time
import requests
import random
import git
import os

class GitHubManager:

    def __init__(self, destination_path: str, repo_blacklist: List[str] = None):
        # Excluded Repositories because many artificial results.
        self.repo_blacklist = repo_blacklist
        self.destination_path = destination_path

    def search_code_repositories(self,
                                 keywords: List[str], 
                                 max_repos: int) -> List[str]:
    # search GitHub api for repositories containing the keyword
    # Rate limit 60 request per hour not authenticated.

        max_repos = 30
        repos = []

        for keyword in keywords:
            print(f"Searching for {keyword}...")

            url = f"https://api.github.com/search/repositories?q={keyword}"
            response = requests.get(url)

            if response.status_code == 403:
                print("Rate limited. Waiting 5 minutes...")
                time.sleep(300)
                response = requests.get(url)

            response.raise_for_status()
            data = response.json()

            num_repos = data["total_count"]
            print(f"Found {num_repos} repositories containing {keyword}")
            print(f"Collecting {max_repos} repositories")

            num_pages = max_repos // 30

            for page in range(1, num_pages + 1):

                url = f"https://api.github.com/search/repositories?q={keyword}&page={page}"
                response = requests.get(url)

                # try to avoid getting rate limited
                if response.status_code == 403:
                    print("Rate limited. Waiting 5 minutes...")
                    time.sleep(300)
                    response = requests.get(url)

                if response.status_code == 422:
                    break

                response.raise_for_status()

                data = response.json()

                if len(data) == 0:
                    break

                for repo in data["items"]:

                    html_url = repo["html_url"]
                    if self.repo_blacklist is None:
                        repos.append(html_url)
                    else:
                        if html_url not in self.repo_blacklist:
                            repos.append(html_url)

        random.shuffle(repos)
        if len(repos) > max_repos:
            return repos[0:max_repos]
        else:
            return repos

    def clone_repo(self, repo_url: str, base_path: str):
        # Perform a shallow clone of a GitHub repository.
        try:
            repo_name = os.path.basename(repo_url)
            destination_path = os.path.join(base_path, repo_name)
            git.Repo.clone_from(repo_url, destination_path, depth=1)
            print(f"Repository {repo_url} cloned successfully to {destination_path}")
        except git.exc.GitCommandError as e:
            print(f"Error: {e}")
    
    def clone_repositories(self, repo_list: List[str]):
        for repo in repo_list:
            self.clone_repo(repo, self.destination_path)
    
    def run_trufflehog_scan(self) -> Any:
        pass
