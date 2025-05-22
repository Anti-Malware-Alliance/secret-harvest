![Secret Harvester](docs/images/secret-harvester.png)


# Secret-Harvest

Python Project to Automate Collection of Snippets with Leaked Secrets in Code, and Snippets Clean of Secrets to Build a Dataset for ML Trainning.

# Problem

Secret Sprawl in Code Repositories, Artifacts, Logs and Documentation is an increasing issue.
Current Secret Scanning Solutions have a high False positive Ratio, making the solutions noisy.
Machine Learning Models can be Developed to aid in reducing False Positive from Secrets that are been scanned.

Further Datasets are required for Researchers to work and Develop ML Models around Secret Detection. 

# Solution

This Python tooling aims to automate and maintain such datasets.
Secret Harvester mimics, tactics used by Malicious Actors to mass harvest secrets in github
by using a mix of github API, github dorks, and opensource secret scanners. 

The result is a curated list of files with secrets to later evaluate performance of secret scanner tools, or train ML models for Secret Detection. 