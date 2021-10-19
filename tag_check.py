import dataclasses
from typing import List

import jmespath
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from analyzers.checkov.integration import CustomCheckDetails, FindingSettings
from analyzers.terraform.tf_shared import get_tag_value, check_for_variable_tags
from config import RSConfig
from finding import FindingSeverity
from analyzers.terraform.tf_shared import LINTER_TAGS_REQUIRED, TAGGABLE_RESOURCES

LINTER_TAGS_REQUIRED = [  # These are just samples, the list is much longer
    "aws_codebuild_project",
    "aws_customer_gateway",
    "aws_db_event_subscription",
    "aws_db_instance",
    "aws_db_security_group",
    "aws_db_snapshot",
]

TAGGABLE_RESOURCES = [  # These are just samples, the list is much longer
 "aws_accessanalyzer_analyzer", 
  "aws_acm_certificate",
  "aws_acmpca_certificate_authority", 
  "aws_ami", 
  "aws_ami_copy", 
  "aws_ami_from_instance", 
  "aws_api_gateway_api_key", 
  "aws_api_gateway_client_certificate", 
]

class AppTag(BaseResourceCheck, CustomCheckDetails):
    def __init__(
        self, id: str, supported_resources: List[str], finding_settings: FindingSettings
    ):
        self.search_pattern = jmespath.compile("tags[*].App")
        self.finding_settings = finding_settings
        super().__init__(
            name="Ensure resources have an `App` tag",
            id=id,
            categories=[CheckCategories.CONVENTION],
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf):
        if check_for_variable_tags(conf):
            return CheckResult.PASSED

        value = get_tag_value(conf, "App")
        if value is None:
            return CheckResult.FAILED

        return CheckResult.PASSED

    def finding_details(self, config: RSConfig, repo_dir: str) -> FindingSettings:
        return dataclasses.replace(self.finding_settings)


checks = [
    AppTag(
        "terraform/app_tag",
        LINTER_TAGS_REQUIRED,
        FindingSettings(severity=FindingSeverity.NEEDS_REVIEW),
    ),  # prod
    AppTag(
        "terraform/app_tag-TEST",
        TAGGABLE_RESOURCES,
        FindingSettings(severity=FindingSeverity.NEEDS_REVIEW),
    ),  # test
]

def check_for_variable_tags(conf: Dict) -> Optional[bool]:
    value = jmespath.search(f"tags[*]", conf)
    if value:
        if "common_data_tags" in value:
            return True
        if "var.common_tags" in value:
            return True
        if "var.tags" in value:
            return True
        if "var.TAGS" in value:
            return True
        if "var.VO_ROUTING_KEY" in value:
            return True
        if "local." in value:
            return True
