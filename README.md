# test-runs-utils
Public Repo to host utility scripts for Levo.ai Security Test Runs

## Usage

```bash

# Install sqlgc python package (This package offers an easy to use GraphQL client)
pip install sgqlc

# Export the following ENV variables
export WORKSPACE_ID=<32 digit UUID LEVO workspaceId>
export ORG_ID=<32 digit UUID LEVO orgId>
export AUTH_TOKEN=<Levo Access Token>

# The following command generates vulnerabilities json file at the location specified in the command (stdout argument)
./fetch_levo_vulns.py <Your Levo Test Run ID (32 digit UUID)> > <output path to the JSON vulnerabilities file>

```
