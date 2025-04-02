"""
AccessAnalyzer - Conditional Access Policy and MFA Analyzer for Microsoft 365
"""

import os
import json
import time
import random
import datetime
import requests
from msal import ConfidentialClientApplication

# === CONFIG ===
# Read from environment variables if available, otherwise use defaults
client_id = os.environ.get("MS_CLIENT_ID", "")
client_secret = os.environ.get("MS_CLIENT_SECRET", "")
tenant_id = os.environ.get("MS_TENANT_ID", "")

# Constants for error handling
MAX_RETRIES = 3
INITIAL_RETRY_DELAY = 1  # seconds

class AccessAnalyzer:
    """
    Analyzes Microsoft 365 conditional access policies, MFA implementation, 
    and identifies security gaps in identity management.
    """
    def __init__(self, client_id=None, client_secret=None, tenant_id=None):
        """Initialize the analyzer with authentication credentials"""
        self.client_id = client_id or os.environ.get("MS_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("MS_CLIENT_SECRET", "")
        self.tenant_id = tenant_id or os.environ.get("MS_TENANT_ID", "")
        
        # Branding for reports
        self.brand_name = "SecurePulse"
        self.module_name = "AccessWatch"
        
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
        print(f"\n🔐 {self.brand_name} - {self.module_name}")
        print("Initializing authentication...")
        
        if not all([self.client_id, self.client_secret, self.tenant_id]):
            print("❌ Missing authentication credentials")
            print("Please set MS_CLIENT_ID, MS_CLIENT_SECRET, and MS_TENANT_ID environment variables")
            return False
        
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
            print("✅ Successfully acquired application token")
            return True
        else:
            print("❌ Failed to acquire token")
            print(f"Error: {token_response.get('error_description', 'Unknown error')}")
            print("\nPlease check your client_id, client_secret, and tenant_id.")
            return False

    def make_api_request(self, url, method="GET", json_data=None, params=None):
        """
        Make a request to the Graph API with built-in error handling and retries
        """
        if not self.headers:
            print("❌ Authentication headers not initialized")
            return None
            
        retry_count = 0
        delay = INITIAL_RETRY_DELAY
        
        while retry_count < MAX_RETRIES:
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
                    print(f"⚠️ Rate limited. Waiting {retry_after} seconds before retrying...")
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                    
                # Handle token expiration (HTTP 401)
                if response.status_code == 401:
                    print("⚠️ Auth token expired. Refreshing token...")
                    self.refresh_auth_token()
                    retry_count += 1
                    continue
                    
                response.raise_for_status()  # Raise exception for 4XX/5XX responses
                
                # Return the JSON response if successful
                if response.status_code in (200, 201, 204):
                    if response.status_code == 204 or not response.text:
                        return {}  # Empty response
                    return response.json()
                    
            except requests.exceptions.RequestException as e:
                print(f"⚠️ API request error: {e}")
                
                # Add jitter to prevent thundering herd problem
                jitter = random.uniform(0, 0.1) * delay
                wait_time = delay + jitter
                
                print(f"Retrying in {wait_time:.1f} seconds... (Attempt {retry_count + 1}/{MAX_RETRIES})")
                time.sleep(wait_time)
                
                # Exponential backoff
                delay *= 2
            
            retry_count += 1
        
        print(f"❌ Failed to complete request after {MAX_RETRIES} attempts: {url}")
        return None

    def refresh_auth_token(self):
        """Refresh the authentication token"""
        print("Refreshing authentication token...")
        token_response = self.app.acquire_token_for_client(scopes=self.scope)
        
        if "access_token" in token_response:
            self.headers = {
                'Authorization': f"Bearer {token_response['access_token']}",
                'Content-Type': 'application/json',
                'ConsistencyLevel': 'eventual'
            }
            print("✅ Successfully refreshed application token")
            return True
        else:
            print("❌ Failed to refresh token")
            print(f"Error: {token_response.get('error_description', 'Unknown error')}")
            return False
            
    def test_permissions(self):
        """Test various Graph API endpoints to determine which permissions are working"""
        # Test endpoints and their required permissions
        endpoints = [
            {"url": f"{self.graph_api}/users?$top=1", "name": "List users", "permission": "User.Read.All"},
            {"url": f"{self.graph_api_beta}/reports/authenticationMethods/userRegistrationDetails", "name": "User registration details", "permission": "Reports.Read.All"},
            {"url": f"{self.graph_api}/auditLogs/signIns?$top=1", "name": "Sign-in logs", "permission": "AuditLog.Read.All"},
            {"url": f"{self.graph_api}/identity/conditionalAccess/policies", "name": "Conditional Access policies", "permission": "Policy.Read.All"},
            {"url": f"{self.graph_api}/directoryRoles", "name": "Directory roles", "permission": "Directory.Read.All"}
        ]
        
        results = []
        permission_map = {}
        
        for endpoint in endpoints:
            try:
                # Use our improved API request function with retries
                response_data = self.make_api_request(endpoint["url"])
                status = "✅ Working" if response_data is not None else f"❌ Failed"
                results.append({
                    "name": endpoint["name"],
                    "permission": endpoint["permission"],
                    "status": status
                })
                permission_map[endpoint["name"]] = response_data is not None
            except Exception as e:
                results.append({
                    "name": endpoint["name"],
                    "permission": endpoint["permission"],
                    "status": f"❌ Error: {str(e)}"
                })
                permission_map[endpoint["name"]] = False
        
        # Print results
        print("\n🔑 Testing API access and permissions...")
        for result in results:
            print(f"{result['status']} - {result['name']} - Requires: {result['permission']}")
            
        return permission_map
    
    def get_users(self, limit=None):
        """Get all users with basic profile information"""
        print("\n👥 Fetching users...")
        
        users = []
        query_params = {"$select": "id,displayName,userPrincipalName,accountEnabled"}
        
        if limit:
            query_params["$top"] = min(limit, 999)  # API limit is 999
            
        # Use more detailed query
        next_link = f"{self.graph_api}/users?{self._build_query_string(query_params)}"
        
        try:
            # Use pagination to get all users
            while next_link:
                data = self.make_api_request(next_link)
                
                if not data or "value" not in data:
                    print("⚠️ Error fetching users or unexpected response format")
                    return []
                
                users.extend(data.get('value', []))
                
                # Check for more pages and respect the limit
                next_link = data.get('@odata.nextLink', None)
                
                if limit and len(users) >= limit:
                    users = users[:limit]
                    break
                    
                if next_link and len(users) % 500 == 0:
                    print(f"Retrieved {len(users)} users so far...")
            
            print(f"Retrieved {len(users)} users")
            return users
            
        except Exception as e:
            print(f"Error fetching users: {e}")
            return []

    def get_conditional_access_policies(self):
        """Get all Conditional Access policies"""
        print("\n🔒 Fetching Conditional Access policies...")
        
        ca_url = f"{self.graph_api}/identity/conditionalAccess/policies"
        policies_data = self.make_api_request(ca_url)
        
        if not policies_data or "value" not in policies_data:
            print("⚠️ Unable to retrieve Conditional Access policies")
            return []
        
        policies = []
        for policy in policies_data["value"]:
            # Extract key policy details
            policy_info = {
                "id": policy.get("id"),
                "displayName": policy.get("displayName"),
                "state": policy.get("state"),
                "createdDateTime": policy.get("createdDateTime"),
                "modifiedDateTime": policy.get("modifiedDateTime"),
                "conditions": {},
                "grantControls": {}
            }
            
            # Extract relevant conditions
            if "conditions" in policy:
                conditions = policy["conditions"]
                
                # User inclusions/exclusions
                if "users" in conditions:
                    user_conditions = conditions.get("users") or {}
                    policy_info["conditions"]["users"] = {
                        "includeUsers": user_conditions.get("includeUsers", []),
                        "excludeUsers": user_conditions.get("excludeUsers", []),
                        "includeGroups": user_conditions.get("includeGroups", []),
                        "excludeGroups": user_conditions.get("excludeGroups", []),
                        "includeRoles": user_conditions.get("includeRoles", []),
                        "excludeRoles": user_conditions.get("excludeRoles", [])
                    }
                
                # Applications
                if "applications" in conditions:
                    app_conditions = conditions.get("applications") or {}
                    policy_info["conditions"]["applications"] = {
                        "includeApplications": app_conditions.get("includeApplications", [])
                    }
                    
                # Location conditions
                if "locations" in conditions:
                    policy_info["conditions"]["locations"] = {
                        "includeLocations": (conditions.get("locations") or {}).get("includeLocations", []),
                        "excludeLocations": (conditions.get("locations") or {}).get("excludeLocations", [])
                    }
            
            # Extract grant controls (e.g., MFA requirements)
            if "grantControls" in policy:
                grant_controls = policy.get("grantControls") or {}
                
                policy_info["grantControls"] = {
                    "operator": grant_controls.get("operator"),
                    "builtInControls": grant_controls.get("builtInControls", []),
                    "customAuthenticationFactors": grant_controls.get("customAuthenticationFactors", []),
                    "termsOfUse": grant_controls.get("termsOfUse", [])
                }
            
            policies.append(policy_info)
        
        print(f"Retrieved {len(policies)} conditional access policies")
        return policies
        
    def get_user_mfa_status(self, users=None, limit=1000):
        """Get MFA status for users"""
        if users is None:
            users = self.get_users(limit=limit)
            
        print(f"\n🔐 Analyzing MFA status for {len(users)} users...")
        
        user_mfa_statuses = []
        count = 0
        
        for user in users:
            count += 1
            if count % 50 == 0:
                print(f"Processing user {count} of {len(users)}...")
                
            user_id = user.get('id')
            user_upn = user.get('userPrincipalName')
            
            if not user_id or not user_upn:
                continue
                
            # Get authentication methods
            auth_methods_url = f"{self.graph_api}/users/{user_id}/authentication/methods"
            auth_methods_data = self.make_api_request(auth_methods_url)
            
            # Initialize MFA variables
            has_mfa = False
            mfa_methods = []
            
            if auth_methods_data and 'value' in auth_methods_data:
                # Extract methods from the response
                for method in auth_methods_data.get('value', []):
                    method_type = method.get('@odata.type', '')
                    if method_type:
                        mfa_methods.append(method_type)
                
                # Check for strong authentication methods
                strong_mfa_method_types = [
                    "#microsoft.graph.microsoftAuthenticatorMethod",
                    "#microsoft.graph.fido2AuthenticationMethod", 
                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
                    "#microsoft.graph.softwareOathAuthenticationMethod"
                ]
                
                # Check for phone methods
                phone_methods = [m for m in auth_methods_data.get('value', []) if m.get('@odata.type') == "#microsoft.graph.phoneAuthenticationMethod"]
                has_strong_phone_method = any(phone.get('phoneType') == 'authenticatorApp' for phone in phone_methods)
                
                # Check for Microsoft Authenticator registration
                has_authenticator_method = any("microsoftAuthenticatorAuthenticationMethod" in method_type for method_type in mfa_methods)
                
                # User has MFA if they have ANY strong authentication method
                has_mfa = (
                    any(method_type in mfa_methods for method_type in strong_mfa_method_types) or 
                    has_strong_phone_method or 
                    has_authenticator_method
                )
            
            # Add to the status list
            user_mfa_statuses.append({
                "id": user_id,
                "userPrincipalName": user_upn,
                "displayName": user.get('displayName', ''),
                "accountEnabled": user.get('accountEnabled', True),
                "hasMfa": has_mfa,
                "mfaMethods": mfa_methods,
                "methodCount": len(mfa_methods)
            })
        
        return user_mfa_statuses
        
    def get_admin_roles(self):
        """Get all available admin roles and their member counts"""
        print("\n👑 Fetching admin roles...")
        
        roles_url = f"{self.graph_api}/directoryRoles"
        roles_data = self.make_api_request(roles_url)
        
        if not roles_data or "value" not in roles_data:
            print("⚠️ Unable to retrieve directory roles")
            return {}
        
        roles = {}
        for role in roles_data["value"]:
            role_id = role.get("id")
            role_name = role.get("displayName")
            
            if role_id and role_name:
                # Get members of this role
                members_url = f"{self.graph_api}/directoryRoles/{role_id}/members"
                members_data = self.make_api_request(members_url)
                
                if members_data and "value" in members_data:
                    member_count = len(members_data["value"])
                    members_list = [
                        m.get("userPrincipalName", m.get("displayName", "Unknown")) 
                        for m in members_data["value"]
                    ]
                    
                    roles[role_name] = {
                        "count": member_count,
                        "members": members_list
                    }
        
        print(f"Retrieved {len(roles)} admin roles")
        return roles
    
    def analyze_mfa_compliance(self, users_mfa_status, admin_roles=None):
        """Analyze MFA compliance across users"""
        if admin_roles is None:
            admin_roles = self.get_admin_roles()
            
        # Flatten the admin members list for easier searching
        admin_members = set()
        for role_name, role_data in admin_roles.items():
            admin_members.update(role_data.get("members", []))
        
        # Analyze compliance
        total_users = len(users_mfa_status)
        enabled_users = [u for u in users_mfa_status if u.get("accountEnabled", True)]
        users_with_mfa = [u for u in users_mfa_status if u.get("hasMfa", False)]
        enabled_with_mfa = [u for u in enabled_users if u.get("hasMfa", False)]
        
        # Admin-specific analysis
        admin_users = [u for u in users_mfa_status if u.get("userPrincipalName", "").lower() in {m.lower() for m in admin_members}]
        admins_with_mfa = [u for u in admin_users if u.get("hasMfa", False)]
        
        # Calculate metrics
        compliance_metrics = {
            "totalUsers": total_users,
            "enabledUsers": len(enabled_users),
            "usersWithMfa": len(users_with_mfa),
            "enabledWithMfa": len(enabled_with_mfa),
            "mfaAdoptionRate": (len(enabled_with_mfa) / max(len(enabled_users), 1)) * 100,
            "adminUsers": len(admin_users),
            "adminsWithMfa": len(admins_with_mfa),
            "adminMfaAdoptionRate": (len(admins_with_mfa) / max(len(admin_users), 1)) * 100,
            "atRiskUsers": [
                {
                    "userPrincipalName": u.get("userPrincipalName"),
                    "displayName": u.get("displayName"),
                    "isAdmin": u.get("userPrincipalName", "").lower() in {m.lower() for m in admin_members},
                    "riskLevel": "High" if u.get("userPrincipalName", "").lower() in {m.lower() for m in admin_members} else "Medium"
                }
                for u in enabled_users if not u.get("hasMfa", False)
            ]
        }
        
        return compliance_metrics
        
    def analyze_conditional_access(self, policies, user_mfa_statuses=None):
        """Analyze conditional access policy coverage and effectiveness"""
        mfa_policies = []
        mfa_gaps = []
        
        # Filter to only enabled policies that require MFA
        for policy in policies:
            if policy["state"] != "enabled":
                continue
                
            # Check for MFA requirements in this policy
            requires_mfa = False
            grant_controls = policy.get("grantControls", {})
            built_in_controls = grant_controls.get("builtInControls", [])
            
            if "mfa" in built_in_controls:
                requires_mfa = True
                mfa_policies.append(policy)
                
                # Analyze policy coverage - are there gaps?
                conditions = policy.get("conditions", {})
                users_condition = conditions.get("users", {})
                
                # Check for full coverage (All users)
                includes_all_users = "All" in users_condition.get("includeUsers", [])
                has_exclusions = (
                    users_condition.get("excludeUsers", []) or 
                    users_condition.get("excludeGroups", []) or
                    users_condition.get("excludeRoles", [])
                )
                
                if includes_all_users and not has_exclusions:
                    # This policy covers everyone with no exclusions
                    pass
                else:
                    # Policy either has exclusions or doesn't cover all users
                    mfa_gaps.append({
                        "policyId": policy.get("id"),
                        "policyName": policy.get("displayName"),
                        "coverage": "Partial",
                        "excludesUsers": bool(users_condition.get("excludeUsers", [])),
                        "excludesGroups": bool(users_condition.get("excludeGroups", [])),
                        "excludesRoles": bool(users_condition.get("excludeRoles", [])),
                        "includesAllUsers": includes_all_users,
                        "description": "This policy doesn't cover all users or has exclusions."
                    })
        
        # If there are no MFA policies, that's a major gap
        if not mfa_policies:
            mfa_gaps.append({
                "policyId": None,
                "policyName": None,
                "coverage": "None",
                "description": "No conditional access policies enforce MFA."
            })
            
        # Check for admin-specific MFA policies
        admin_specific_policies = []
        for policy in mfa_policies:
            conditions = policy.get("conditions", {})
            users_condition = conditions.get("users", {})
            
            if users_condition.get("includeRoles", []):
                admin_specific_policies.append(policy)
                
        # Calculate metrics and return analysis
        analysis = {
            "totalPolicies": len(policies),
            "enabledPolicies": len([p for p in policies if p["state"] == "enabled"]),
            "mfaPolicies": len(mfa_policies),
            "adminSpecificPolicies": len(admin_specific_policies),
            "mfaPolicyGaps": mfa_gaps,
            "hasComprehensiveMfaPolicy": len(mfa_gaps) == 0,
            "mfaPolicyCoverage": "Complete" if len(mfa_gaps) == 0 else "Partial" if mfa_policies else "None"
        }
        
        return analysis
        
    def generate_report(self, file_path=None):
        """Generate a comprehensive access report"""
        print("\n📊 Generating comprehensive access report...")
        
        # First test permissions
        permissions = self.test_permissions()
        
        # Gather data based on available permissions
        users = self.get_users() if permissions.get("List users", False) else []
        ca_policies = self.get_conditional_access_policies() if permissions.get("Conditional Access policies", False) else []
        admin_roles = self.get_admin_roles() if permissions.get("Directory roles", False) else {}
        
        # Get MFA status for users (if we have permission)
        user_mfa_statuses = []
        if permissions.get("List users", False):
            user_mfa_statuses = self.get_user_mfa_status(users)
            
        # Generate analysis
        mfa_compliance = self.analyze_mfa_compliance(user_mfa_statuses, admin_roles)
        ca_analysis = self.analyze_conditional_access(ca_policies)
        
        # Build the final report
        report = {
            "reportDate": datetime.datetime.now().isoformat(),
            "tenantId": self.tenant_id,
            "permissions": permissions,
            "mfaCompliance": mfa_compliance,
            "conditionalAccessAnalysis": ca_analysis,
            "adminRoles": admin_roles,
            "rawData": {
                "userMfaStatuses": user_mfa_statuses,
                "conditionalAccessPolicies": ca_policies
            }
        }
        
        # Save the report if a file path is provided
        if file_path:
            print(f"Saving report to {file_path}...")
            try:
                with open(file_path, "w") as f:
                    json.dump(report, f, indent=2, default=str)
                print(f"Report saved to {file_path}")
            except Exception as e:
                print(f"Error saving report: {e}")
        
        return report
    
    def _build_query_string(self, params):
        """Utility to build an API query string from parameters"""
        return "&".join([f"${key}={value}" for key, value in params.items()])


# Example usage
if __name__ == "__main__":
    analyzer = AccessAnalyzer()
    report = analyzer.generate_report("access_report.json")
    
    print("\n🔒 AccessWatch Analysis Summary:")
    print(f"MFA Adoption Rate: {report['mfaCompliance']['mfaAdoptionRate']:.1f}%")
    print(f"Admin MFA Adoption: {report['mfaCompliance']['adminMfaAdoptionRate']:.1f}%")
    print(f"At-Risk Users: {len(report['mfaCompliance']['atRiskUsers'])}")
    print(f"MFA Policy Coverage: {report['conditionalAccessAnalysis']['mfaPolicyCoverage']}")