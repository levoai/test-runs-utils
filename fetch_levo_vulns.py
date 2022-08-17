import json
import os
import sys
from collections import defaultdict

from sgqlc.endpoint.http import HTTPEndpoint

GRAPHQL_SERVICE_URL = os.getenv("GQL_SERVICE_URL", "https://api.levo.ai/graphql")
workspace_id = os.getenv("WORKSPACE_ID", "")
org_id = os.getenv("ORG_ID", "")
auth_token = os.getenv("AUTH_TOKEN", "")


def get_vulnerability_details(
    run_uuid: str,
):
    test_suite_runs = get_test_suite_runs(run_uuid)
    vulnerabilities = []
    for test_suite_run in test_suite_runs:
        test_suite_run_id = test_suite_run["testSuiteRunId"]
        test_case_runs = get_test_case_runs(run_uuid, test_suite_run_id)
        for test_case_run in test_case_runs:
            if test_case_run["status"] != "CaseFailed":
                continue
            test_case_run_uuid = test_case_run["testCaseRunUuid"]
            test_case_attachment = get_test_case_attachment(
                run_uuid, test_case_run_uuid
            )
            content = test_case_attachment["content"]
            vuln_content = json.loads(content)
            for _, assertion in vuln_content["assertions"].items():
                if assertion["status"] == "failure":
                    vulnerability = {
                        "endpoint": test_suite_run["name"],
                        "test_case_name": test_case_run["name"],
                        "test_case_category": test_case_run["category"],
                        "risk": assertion["risk"],
                        "confidence": assertion["confidence"],
                        "evidence": assertion["evidence"],
                        "solution": assertion["solution"],
                        "reference": assertion["reference"],
                        "overview": vuln_content["summary"]
                    }
                    if (
                        "evidence" in assertion
                        and assertion["evidence"]
                        and "title" in assertion["evidence"]
                    ):
                        evidence = assertion["evidence"]["title"]
                        vulnerability.update({"evidence": evidence})
                    if (
                        "cwe" in assertion
                        and assertion["cwe"]
                        and "code" in assertion["cwe"]
                    ):
                        cwe_code = assertion["cwe"]["code"]
                        vulnerability.update({"cwe": cwe_code})
                    if (
                            "cwe" in assertion
                            and assertion["cwe"]
                            and "summary" in assertion["cwe"]
                    ):
                        cwe_summary = assertion["cwe"]["summary"]
                        vulnerability.update({"summary": cwe_summary})

                    vulnerabilities.append(
                        vulnerability
                    )
    return json.dumps(vulnerabilities)


def get_test_runs(my_runs_only: bool):
    query = """
query GetTestRuns(
  $myRunsOnly: Boolean,
  $meta: AiLevoApitestingRunsV1GetAllRequestMetadataInput!
) {
  aiLevoApitestingRunsV1ApiTestRunsServiceGetApiTestRuns(
    input: {
      myRunsOnly: $myRunsOnly
      meta: $meta
    }
  ) {
    runs {
      runId
      name
      description
      status
      startTime
      durationMillis
      author
      targetUrl
      testPlanName
      runUuid
    }
  }
}
"""
    variables = {
        "myRunsOnly": my_runs_only,
        "meta": {
            "page": 0,
            "pageSize": 20,
            "sort": {"sortFields": ["lastModified"], "sortDirection": "Desc"},
        },
    }
    response = execute_gql_query(query, variables)
    runs = response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetApiTestRuns"][
        "runs"
    ]
    return runs


def get_test_run_details(run_uuid: str):
    query = """
    query GetApiTestRunDetails(
      $runUuid: String
    ) {
      aiLevoApitestingRunsV1ApiTestRunsServiceGetApiTestRunDetails(
        input: {
          runUuid: $runUuid
        }
      ) {
        author
        runId
        name
        durationMillis
        testPlanMetadata {
          planId
          planName
          planLrn
        }
        runNumber
        startTime
        status
        description
        successfulTests
        failedTests
        targetUrl
        failingTestSuitesData {
          dataItems {
            name
            count
            percentage
          }
        }
        failingTestCaseCategoriesData {
          dataItems {
            name
            count
            percentage
          }
        }
      }
    }
    """
    variables = {"runUuid": run_uuid}
    response = execute_gql_query(query, variables)
    test_run_details = response["data"][
        "aiLevoApitestingRunsV1ApiTestRunsServiceGetApiTestRunDetails"
    ]
    return test_run_details


def get_test_suite_runs(run_uuid: str):
    query = """
    query GetTestSuiteRuns(
      $runUuid: String,
      $meta: AiLevoApitestingRunsV1GetAllRequestMetadataInput!
    ) {
      aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRuns(
        input: {
          runUuid: $runUuid
          meta: $meta
        }
      ) {
        meta {
            currentPage
            pageSize
            totalItems
            totalPages
        }
        testSuiteRuns {
          testSuiteRunId
          name
          description
          status
          durationMillis
          successfulTests
          failedTests
          erroredTests
        }
      }
    }
    """
    variables = {
        "runUuid": run_uuid,
        "meta": {
            "page": 0,
            "pageSize": 100,
            "sort": {
                "sortFields": ["failedTests", "erroredTests"],
                "sortDirection": "Desc",
            },
        },
    }
    response = execute_gql_query(query, variables)
    meta = response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRuns"][
        "meta"
    ]
    data = []
    data.extend(
        response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRuns"][
            "testSuiteRuns"
        ]
    )
    current_page = 1
    while current_page < meta["totalPages"]:
        variables["meta"]["page"] = current_page
        response = execute_gql_query(query, variables)
        data.extend(
            response["data"][
                "aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRuns"
            ]["testSuiteRuns"]
        )
        current_page += 1

    return data


def get_test_suite_run_details(run_uuid: str, test_suite_run_id: str):
    query = """
    query GetTestSuiteRunDetails(
      $runUuid: String,
      $suiteRunId: String
    ) {
      aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRunDetails(
        input: {
          runUuid: $runUuid,
          testSuiteRunId: $suiteRunId
        }
      ) {
        testSuiteId
        testRunId
        testSuiteRunId
        name
        description
        status
        startTime
        durationMillis
        totalTests
        successfulTests
        failedTests
        erroredTests
        failingTestCaseCategoriesData {
          dataItems {
            name
            count
            percentage
          }
        }
      }
    }
    """
    variables = {
        "runUuid": run_uuid,
        "suiteRunId": test_suite_run_id,
        "meta": {"page": 0, "pageSize": 5},
    }
    response = execute_gql_query(query, variables)
    test_suite_run_details = response["data"][
        "aiLevoApitestingRunsV1ApiTestRunsServiceGetTestSuiteRunDetails"
    ]
    return test_suite_run_details


def get_test_case_runs(run_uuid: str, test_suite_run_id: str):
    query = """
    query GetApiTestCaseRuns(
      $runUuid: String,
      $suiteRunId: String,
      $meta: AiLevoApitestingRunsV1GetAllRequestMetadataInput!
    ) {
      aiLevoApitestingRunsV1ApiTestRunsServiceGetTestCaseRuns(
        input: {
          runUuid: $runUuid,
          testSuiteRunId: $suiteRunId,
          meta: $meta
        }
      ) {
        meta {
            currentPage
            pageSize
            totalItems
            totalPages
        }

        testCaseRuns {
          testCaseRunId
          testCaseRunUuid
          name
          description
          status
          durationMillis
          category
          summary
        }
      }
    }
    """
    variables = {
        "runUuid": run_uuid,
        "suiteRunId": test_suite_run_id,
        "meta": {
            "page": 0,
            "pageSize": 10,
            "sort": {"sortFields": ["startTime"], "sortDirection": "Asc"},
        },
    }
    response = execute_gql_query(query, variables)
    meta = response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetTestCaseRuns"][
        "meta"
    ]
    data = []
    data.extend(
        response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetTestCaseRuns"][
            "testCaseRuns"
        ]
    )
    current_page = 1
    while current_page < meta["totalPages"]:
        variables["meta"]["page"] = current_page
        response = execute_gql_query(query, variables)
        data.extend(
            response["data"]["aiLevoApitestingRunsV1ApiTestRunsServiceGetTestCaseRuns"][
                "testCaseRuns"
            ]
        )
        current_page += 1

    return data


def get_test_case_attachment(run_uuid: str, test_case_run_uuid: str):
    query = """
        query GetTestCaseAttachment(
          $testCaseRunUuid: String,
          $runUuid: String,
          $attachmentType: AiLevoApitestingRunsV1TestCaseAttachment!
        ) {
          aiLevoApitestingRunsV1ApiTestRunsServiceGetCaseAttachment(
            input: {
              runUuid: $runUuid,
              testCaseRunUuid: $testCaseRunUuid,
              attachmentType: $attachmentType
            }
          ) {
            content
            contentType
          }
        }
        """
    variables = {
        "runUuid": run_uuid,
        "testCaseRunUuid": test_case_run_uuid,
        "attachmentType": "Result",
    }
    response = execute_gql_query(query, variables)
    test_case_attachment = response["data"][
        "aiLevoApitestingRunsV1ApiTestRunsServiceGetCaseAttachment"
    ]
    return test_case_attachment


def execute_gql_query(query, variables):
    headers = {"Authorization": "Bearer " + auth_token}

    # Set workspace id header if it's present.
    if workspace_id:
        headers["x-levo-workspace-id"] = workspace_id

    if org_id:
        headers["x-levo-organization-id"] = org_id

    endpoint = HTTPEndpoint(GRAPHQL_SERVICE_URL, headers)
    try:
        response = endpoint(query, variables)
        if "errors" in response:
            raise Exception(f"GQL query has failed. Response: {response}")
        return response
    except Exception as e:
        raise Exception(f"Could not run the GQL query. Error: {e}")


if __name__ == "__main__":
    run_uuid = sys.argv[1]
    vulnerabilities = get_vulnerability_details(run_uuid)
    print(vulnerabilities)
