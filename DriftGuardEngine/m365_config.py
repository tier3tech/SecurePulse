"""
M365ConfigFetcher - Module for fetching Microsoft 365 configuration via Graph API

Required Graph API permissions:
- Organization.Read.All: For reading tenant information
- Policy.Read.All: For reading security policies and Conditional Access policies
- SharePointTenantSettings.Read.All: For reading SharePoint tenant settings
- ServiceActivity-Exchange.Read.All: For reading Exchange Online settings and activity
"""

import os
import json
import logging
import requests
import time
import random
from msal import ConfidentialClientApplication

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('M365ConfigFetcher')

class M365ConfigFetcher:
    """
    Fetches Microsoft 365 configuration via Graph API for comparison against baselines
    """
    def __init__(self, client_id=None, client_secret=None, tenant_id=None):
        """Initialize the configuration fetcher with authentication credentials"""
        self.client_id = client_id or os.environ.get("MS_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("MS_CLIENT_SECRET", "")
        self.tenant_id = tenant_id or os.environ.get("MS_TENANT_ID", "")
        
        # Branding for reports
        self.brand_name = "SecurePulse"
        self.module_name = "DriftGuard Engine"
        
        # Initialize API endpoints
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scope = ["https://graph.microsoft.com/.default"]
        self.graph_api = "https://graph.microsoft.com/v1.0"
        self.graph_api_beta = "https://graph.microsoft.com/beta"
        
        # Initialize auth app
        self.app = None
        self.headers = None
        self.initialize_auth()
        
    def initialize_auth(self):
        """Initialize authentication with Microsoft Graph"""
        logger.info(f"{self.brand_name} - {self.module_name} initializing authentication...")
        
        if not all([self.client_id, self.client_secret, self.tenant_id]):
            logger.error("Missing authentication credentials")
            return False
        
        try:
            self.app = ConfidentialClientApplication(
                self.client_id,
                authority=self.authority,
                client_credential=self.client_secret
            )
            
            # Try to get an application token (non-delegated permission)
            token_response = self.app.acquire_token_for_client(scopes=self.scope)
            
            if "access_token" in token_response:
                self.headers = {
                    'Authorization': f"Bearer {token_response['access_token']}",
                    'Content-Type': 'application/json',
                    'ConsistencyLevel': 'eventual'  # Add this for better pagination support
                }
                logger.info("Successfully acquired application token")
                return True
            else:
                logger.error(f"Failed to acquire token: {token_response.get('error_description', 'Unknown error')}")
                return False
                
        except Exception as e:
            logger.error(f"Error initializing authentication: {str(e)}")
            return False

    def make_api_request(self, url, method="GET", json_data=None, params=None, max_retries=3, initial_delay=1):
        """
        Make a request to the Graph API with built-in error handling and retries
        """
        if not self.headers:
            logger.error("Authentication headers not initialized")
            return None
            
        retry_count = 0
        delay = initial_delay
        
        while retry_count < max_retries:
            try:
                if method.upper() == "GET":
                    response = requests.get(url, headers=self.headers, params=params, timeout=30)
                elif method.upper() == "POST":
                    response = requests.post(url, headers=self.headers, json=json_data, params=params, timeout=30)
                elif method.upper() == "PATCH":
                    response = requests.patch(url, headers=self.headers, json=json_data, params=params, timeout=30)
                elif method.upper() == "DELETE":
                    response = requests.delete(url, headers=self.headers, params=params, timeout=30)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle rate limiting (HTTP 429)
                if response.status_code == 429:
                    # Get retry-after header, or use exponential backoff
                    retry_after = int(response.headers.get('Retry-After', delay))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds before retrying...")
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                    
                # Handle token expiration (HTTP 401)
                if response.status_code == 401:
                    logger.warning("Auth token expired. Refreshing token...")
                    self.refresh_auth_token()
                    retry_count += 1
                    continue
                
                # Special handling for permission issues (HTTP 403)
                if response.status_code == 403:
                    logger.warning(f"API request error: 403 Forbidden for url: {url}")
                    # Only retry once for 403 errors since they're likely permission issues
                    # that won't be resolved with retries
                    if retry_count < max_retries - 1:
                        jitter = random.uniform(0, 0.1) * delay
                        wait_time = delay + jitter
                        logger.info(f"Retrying in {wait_time:.1f} seconds... (Attempt {retry_count + 1}/{max_retries})")
                        time.sleep(wait_time)
                        delay *= 2
                        retry_count += 1
                        continue
                    else:
                        # If we've retried enough times, log and return None to indicate failure
                        # This allows the calling function to handle the missing data appropriately
                        logger.error(f"Failed to complete request after {retry_count + 1} attempts: {url}")
                        return None
                
                # Handle other errors
                try:
                    response.raise_for_status()  # Raise exception for other 4XX/5XX responses
                except requests.exceptions.RequestException as e:
                    logger.warning(f"API request error: {e}")
                    
                    # Add jitter to prevent thundering herd problem
                    jitter = random.uniform(0, 0.1) * delay
                    wait_time = delay + jitter
                    
                    logger.info(f"Retrying in {wait_time:.1f} seconds... (Attempt {retry_count + 1}/{max_retries})")
                    time.sleep(wait_time)
                    
                    # Exponential backoff
                    delay *= 2
                    retry_count += 1
                    continue
                
                # Return the JSON response if successful
                if response.status_code in (200, 201, 204):
                    if response.status_code == 204 or not response.text:
                        return {}  # Empty response
                    return response.json()
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"API request error: {e}")
                
                # Add jitter to prevent thundering herd problem
                jitter = random.uniform(0, 0.1) * delay
                wait_time = delay + jitter
                
                logger.info(f"Retrying in {wait_time:.1f} seconds... (Attempt {retry_count + 1}/{max_retries})")
                time.sleep(wait_time)
                
                # Exponential backoff
                delay *= 2
                retry_count += 1
            
        logger.error(f"Failed to complete request after {max_retries} attempts: {url}")
        return None

    def refresh_auth_token(self):
        """Refresh the authentication token"""
        logger.info("Refreshing authentication token...")
        
        try:
            token_response = self.app.acquire_token_for_client(scopes=self.scope)
            
            if "access_token" in token_response:
                self.headers = {
                    'Authorization': f"Bearer {token_response['access_token']}",
                    'Content-Type': 'application/json',
                    'ConsistencyLevel': 'eventual'
                }
                logger.info("Successfully refreshed application token")
                return True
            else:
                logger.error(f"Failed to refresh token: {token_response.get('error_description', 'Unknown error')}")
                return False
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return False

    def test_permissions(self):
        """Test Graph API permissions required for fetching configuration"""
        logger.info("Testing API access and permissions...")
        
        # Test endpoints and their required permissions
        endpoints = [
            {"url": f"{self.graph_api}/organization", "name": "Organization", "permission": "Organization.Read.All"},
            {"url": f"{self.graph_api}/identity/conditionalAccess/policies", "name": "Conditional Access policies", "permission": "Policy.Read.All"},
            {"url": f"{self.graph_api}/policies/identitySecurityDefaultsEnforcementPolicy", "name": "Security defaults", "permission": "Policy.Read.All"},
            {"url": f"{self.graph_api}/admin/sharepoint/settings", "name": "SharePoint settings", "permission": "SharePointTenantSettings.Read.All"},
            {"url": f"{self.graph_api}/admin/exchange/settings", "name": "Exchange settings", "permission": "ServiceActivity-Exchange.Read.All"}
        ]
        
        results = {}
        
        for endpoint in endpoints:
            try:
                response = self.make_api_request(endpoint["url"])
                success = response is not None
                results[endpoint["name"]] = {
                    "permission": endpoint["permission"],
                    "success": success
                }
                
                status = "✅ Working" if success else "❌ Failed"
                logger.info(f"{status} - {endpoint['name']} - Requires: {endpoint['permission']}")
                
            except Exception as e:
                logger.error(f"Error testing {endpoint['name']}: {str(e)}")
                results[endpoint["name"]] = {
                    "permission": endpoint["permission"],
                    "success": False,
                    "error": str(e)
                }
                
        return results
        
    def get_tenant_info(self):
        """Fetch basic tenant information"""
        logger.info("Fetching tenant information...")
        
        try:
            url = f"{self.graph_api}/organization"
            response = self.make_api_request(url)
            
            if not response or "value" not in response:
                logger.error("Failed to fetch tenant information")
                return {}
                
            # Get the first organization (there's typically just one)
            org = response["value"][0] if len(response["value"]) > 0 else {}
            
            tenant_info = {
                "id": org.get("id"),
                "displayName": org.get("displayName"),
                "verifiedDomains": org.get("verifiedDomains", []),
                "tenantType": org.get("tenantType"),
                "createdDateTime": org.get("createdDateTime")
            }
            
            logger.info(f"Tenant information retrieved for {tenant_info['displayName']}")
            return tenant_info
            
        except Exception as e:
            logger.error(f"Error fetching tenant information: {str(e)}")
            return {}
            
    def get_conditional_access_policies(self):
        """Fetch conditional access policies"""
        logger.info("Fetching conditional access policies...")
        
        try:
            url = f"{self.graph_api}/identity/conditionalAccess/policies"
            response = self.make_api_request(url)
            
            if not response or "value" not in response:
                logger.error("Failed to fetch conditional access policies")
                return []
                
            policies = response["value"]
            logger.info(f"Retrieved {len(policies)} conditional access policies")
            return policies
            
        except Exception as e:
            logger.error(f"Error fetching conditional access policies: {str(e)}")
            return []
            
    def get_security_defaults(self):
        """Fetch security defaults policy state"""
        logger.info("Fetching security defaults policy...")
        
        try:
            url = f"{self.graph_api}/policies/identitySecurityDefaultsEnforcementPolicy"
            response = self.make_api_request(url)
            
            if not response:
                logger.error("Failed to fetch security defaults policy")
                return {}
                
            logger.info(f"Security defaults policy retrieved, enabled: {response.get('isEnabled', False)}")
            return response
            
        except Exception as e:
            logger.error(f"Error fetching security defaults policy: {str(e)}")
            return {}
            
    def get_sharepoint_settings(self):
        """Fetch SharePoint settings"""
        logger.info("Fetching SharePoint settings...")
        
        try:
            combined_response = {}
            
            # Using the SharePointTenantSettings.Read.All permission
            # Try to get main SharePoint settings first
            url = f"{self.graph_api}/admin/sharepoint/settings"
            response = self.make_api_request(url)
            
            if response:
                combined_response.update(response)
                logger.info("SharePoint main settings retrieved")
            else:
                logger.warning("Could not fetch SharePoint main settings - continuing with partial data")
                
            # Also try to fetch SharePoint tenant-wide sharing settings
            # This might work even if the main settings endpoint fails
            try:
                sharing_url = f"{self.graph_api}/admin/sharepoint/settings/sharing"
                sharing_response = self.make_api_request(sharing_url)
                
                if sharing_response:
                    combined_response["sharing"] = sharing_response
                    logger.info("SharePoint sharing settings retrieved")
                else:
                    logger.warning("Could not fetch SharePoint sharing settings")
            except Exception as sharing_e:
                logger.warning(f"Error fetching SharePoint sharing settings: {str(sharing_e)}")
            
            # Return whatever data we could retrieve
            if combined_response:
                logger.info("Partial or complete SharePoint settings retrieved")
                return combined_response
            else:
                logger.error("Failed to fetch any SharePoint settings")
                return {"error": "Missing required permissions for SharePoint settings"}
            
        except Exception as e:
            logger.error(f"Error fetching SharePoint settings: {str(e)}")
            return {"error": "Error fetching SharePoint settings"}
            
    def get_exchange_settings(self):
        """Fetch Exchange settings"""
        logger.info("Fetching Exchange settings...")
        
        exchange_settings = {}
        
        try:
            # Using the ServiceActivity-Exchange.Read.All permission
            
            # Keep track of successful and failed requests
            successful_requests = 0
            failed_requests = 0
            
            # Fetch Exchange antispam settings
            try:
                antispam_url = f"{self.graph_api_beta}/admin/exchange/settings/antispam"
                antispam_response = self.make_api_request(antispam_url)
                
                if antispam_response:
                    exchange_settings["antispam"] = antispam_response
                    logger.info("Exchange antispam settings retrieved")
                    successful_requests += 1
                else:
                    logger.warning("Failed to fetch Exchange antispam settings")
                    failed_requests += 1
            except Exception as e:
                logger.warning(f"Error fetching Exchange antispam settings: {str(e)}")
                failed_requests += 1
            
            # Fetch Exchange malware settings
            try:
                malware_url = f"{self.graph_api_beta}/admin/exchange/settings/malware"
                malware_response = self.make_api_request(malware_url)
                
                if malware_response:
                    exchange_settings["malware"] = malware_response
                    logger.info("Exchange malware settings retrieved")
                    successful_requests += 1
                else:
                    logger.warning("Failed to fetch Exchange malware settings")
                    failed_requests += 1
            except Exception as e:
                logger.warning(f"Error fetching Exchange malware settings: {str(e)}")
                failed_requests += 1
                
            # Fetch Exchange outbound spam settings
            try:
                outbound_url = f"{self.graph_api_beta}/admin/exchange/settings/outboundspam"
                outbound_response = self.make_api_request(outbound_url)
                
                if outbound_response:
                    exchange_settings["outboundSpam"] = outbound_response
                    logger.info("Exchange outbound spam settings retrieved")
                    successful_requests += 1
                else:
                    logger.warning("Failed to fetch Exchange outbound spam settings")
                    failed_requests += 1
            except Exception as e:
                logger.warning(f"Error fetching Exchange outbound spam settings: {str(e)}")
                failed_requests += 1
            
            # Fetch Exchange transport rules
            try:
                # This requires more careful pagination handling due to potentially large number of rules
                transport_url = f"{self.graph_api_beta}/admin/exchange/transportRules"
                transport_response = self.make_api_request(transport_url)
                
                if transport_response and "value" in transport_response:
                    exchange_settings["transportRules"] = transport_response["value"]
                    logger.info(f"Retrieved {len(transport_response['value'])} Exchange transport rules")
                    successful_requests += 1
                else:
                    logger.warning("Failed to fetch Exchange transport rules")
                    failed_requests += 1
            except Exception as e:
                logger.warning(f"Error fetching Exchange transport rules: {str(e)}")
                failed_requests += 1
            
            # Log summary
            if successful_requests > 0:
                if failed_requests > 0:
                    logger.info(f"Retrieved {successful_requests} Exchange setting types, {failed_requests} failed")
                    # Add metadata about partial retrieval
                    exchange_settings["_metadata"] = {
                        "partial_retrieval": True,
                        "successful_requests": successful_requests,
                        "failed_requests": failed_requests
                    }
                else:
                    logger.info("All Exchange settings retrieved successfully")
            else:
                logger.error("Failed to retrieve any Exchange settings")
                exchange_settings["_metadata"] = {
                    "error": "Failed to retrieve any Exchange settings",
                    "likely_cause": "Missing required permissions: ServiceActivity-Exchange.Read.All"
                }
                
            return exchange_settings
            
        except Exception as e:
            logger.error(f"Error fetching Exchange settings: {str(e)}")
            return {
                "_metadata": {
                    "error": f"Error fetching Exchange settings: {str(e)}",
                    "likely_cause": "Missing required permissions or API endpoint issues"
                }
            }
            
    def get_authentication_methods_policy(self):
        """Fetch authentication methods policy"""
        logger.info("Fetching authentication methods policy...")
        
        try:
            url = f"{self.graph_api}/policies/authenticationMethodsPolicy"
            response = self.make_api_request(url)
            
            if not response:
                logger.error("Failed to fetch authentication methods policy")
                return {}
                
            logger.info("Authentication methods policy retrieved")
            return response
            
        except Exception as e:
            logger.error(f"Error fetching authentication methods policy: {str(e)}")
            return {}
            
    def fetch_all_configurations(self):
        """Fetch all configurations needed for SCuBA baseline comparison"""
        logger.info("Fetching all configurations for baseline comparison...")
        
        # Test permissions first
        permissions = self.test_permissions()
        missing_permissions = [name for name, result in permissions.items() if not result["success"]]
        
        if missing_permissions:
            logger.warning(f"Missing permissions for: {', '.join(missing_permissions)}")
            logger.warning("Some configurations may not be available for comparison")
        
        # Initialize configurations dictionary
        configurations = {
            "permissionStatus": permissions,
            "missingConfigurations": []
        }
        
        # Fetch tenant info
        tenant_info = self.get_tenant_info()
        if tenant_info:
            configurations["tenant"] = tenant_info
        else:
            logger.warning("Unable to fetch tenant information")
            configurations["missingConfigurations"].append("tenant")
        
        # Fetch conditional access policies
        ca_policies = self.get_conditional_access_policies()
        if ca_policies:
            configurations["conditionalAccessPolicies"] = ca_policies
        else:
            logger.warning("Unable to fetch conditional access policies")
            configurations["missingConfigurations"].append("conditionalAccessPolicies")
        
        # Fetch security defaults
        security_defaults = self.get_security_defaults()
        if security_defaults:
            configurations["securityDefaults"] = security_defaults
        else:
            logger.warning("Unable to fetch security defaults")
            configurations["missingConfigurations"].append("securityDefaults")
        
        # Fetch SharePoint settings
        sharepoint_settings = self.get_sharepoint_settings()
        if sharepoint_settings and not sharepoint_settings.get("error"):
            configurations["sharepointSettings"] = sharepoint_settings
        else:
            logger.warning("Unable to fetch complete SharePoint settings")
            configurations["missingConfigurations"].append("sharepointSettings")
            # Store partial data if available
            if sharepoint_settings:
                configurations["partialSharePointSettings"] = sharepoint_settings
        
        # Fetch Exchange settings
        exchange_settings = self.get_exchange_settings()
        if exchange_settings:
            configurations["exchangeSettings"] = exchange_settings
        else:
            logger.warning("Unable to fetch Exchange settings")
            configurations["missingConfigurations"].append("exchangeSettings")
        
        # Fetch authentication methods policy
        auth_methods_policy = self.get_authentication_methods_policy()
        if auth_methods_policy:
            configurations["authenticationMethodsPolicy"] = auth_methods_policy
        else:
            logger.warning("Unable to fetch authentication methods policy")
            configurations["missingConfigurations"].append("authenticationMethodsPolicy")
        
        # Log summary of fetched configurations
        fetched_configs = len(configurations) - 2  # Subtract permissionStatus and missingConfigurations
        expected_configs = 6  # Number of main configuration categories we try to fetch
        
        if fetched_configs == expected_configs:
            logger.info("All configurations fetched successfully")
        else:
            logger.info(f"Fetched {fetched_configs} out of {expected_configs} configuration categories")
            logger.info(f"Missing configurations: {', '.join(configurations['missingConfigurations'])}")
        
        return configurations
        
    def save_configurations(self, configurations, output_file):
        """Save configurations to a file"""
        logger.info(f"Saving configurations to {output_file}...")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(configurations, f, indent=2, default=str)
            logger.info(f"Configurations saved to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving configurations: {str(e)}")
            return False

# Example usage
if __name__ == "__main__":
    fetcher = M365ConfigFetcher()
    configurations = fetcher.fetch_all_configurations()
    fetcher.save_configurations(configurations, "m365_configurations.json")