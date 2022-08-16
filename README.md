# test-runs-utils
Public Repo to host utility scripts for Levo.ai Security Test Runs

## Usage

```bash

# Install sqlgc python package (This package offers an easy to use GraphQL client)
pip install sgqlc

# The following command generates vulnerabilities json file at the location specified in the command (stdout argument)
./fetch_levo_vulns.py <Your Levo Workspace ID (32 digit UUID)> > <output path to the JSON vulnerabilities file>

```
