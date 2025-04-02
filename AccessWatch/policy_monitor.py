"""
PolicyMonitor - Monitoring and alerting on changes to Conditional Access policies
"""

import os
import json
import datetime
import time
from pathlib import Path
from .access_analyzer import AccessAnalyzer

class PolicyMonitor:
    """
    Monitors changes to Conditional Access policies and provides alerting
    capabilities when policies are modified or deleted.
    """
    def __init__(self, 
                client_id=None, 
                client_secret=None, 
                tenant_id=None,
                state_dir="./state"):
        """Initialize the policy monitor"""
        self.analyzer = AccessAnalyzer(client_id, client_secret, tenant_id)
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "policy_state.json"
        
    def get_current_policies(self):
        """Get current conditional access policies"""
        return self.analyzer.get_conditional_access_policies()
        
    def get_previous_policies(self):
        """Load previously saved policy state"""
        if not self.state_file.exists():
            return None
            
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
                return state.get('policies', [])
        except Exception as e:
            print(f"Error loading previous policy state: {e}")
            return None
            
    def save_current_state(self, policies):
        """Save current policy state for future comparison"""
        state = {
            'timestamp': datetime.datetime.now().isoformat(),
            'policies': policies
        }
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            print(f"Saved policy state to {self.state_file}")
            return True
        except Exception as e:
            print(f"Error saving policy state: {e}")
            return False
            
    def compare_policies(self, current_policies, previous_policies):
        """
        Compare current and previous policies to identify changes
        
        Returns:
            Dictionary with added, modified, and deleted policies
        """
        if not previous_policies:
            return {
                'added': current_policies,
                'modified': [],
                'deleted': [],
                'first_run': True
            }
            
        # Create lookup dictionaries by policy ID
        current_dict = {p['id']: p for p in current_policies}
        previous_dict = {p['id']: p for p in previous_policies}
        
        # Find added, modified, and deleted policies
        added = [p for p in current_policies if p['id'] not in previous_dict]
        deleted = [p for p in previous_policies if p['id'] not in current_dict]
        
        # For modified policies, compare state and key attributes
        modified = []
        for policy_id, current_policy in current_dict.items():
            if policy_id in previous_dict:
                prev_policy = previous_dict[policy_id]
                
                # Check key attributes for changes
                if (current_policy['state'] != prev_policy['state'] or
                    current_policy['displayName'] != prev_policy['displayName'] or
                    current_policy.get('modifiedDateTime') != prev_policy.get('modifiedDateTime')):
                    
                    # Create a record of what changed
                    changes = {
                        'id': policy_id,
                        'displayName': current_policy['displayName'],
                        'previous_state': prev_policy.get('state'),
                        'current_state': current_policy.get('state'),
                        'previous_modified': prev_policy.get('modifiedDateTime'),
                        'current_modified': current_policy.get('modifiedDateTime')
                    }
                    
                    modified.append(changes)
        
        return {
            'added': added,
            'modified': modified,
            'deleted': deleted,
            'first_run': False
        }
        
    def detect_policy_drift(self, save_state=True):
        """
        Detect changes to conditional access policies since last check
        
        Args:
            save_state: Whether to save the current state after checking
            
        Returns:
            Dictionary with changes detected
        """
        print("\n🔍 Checking for changes to Conditional Access policies...")
        
        # Get current and previous policies
        current_policies = self.get_current_policies()
        previous_policies = self.get_previous_policies()
        
        # Compare policies
        changes = self.compare_policies(current_policies, previous_policies)
        
        # Report on changes
        if changes['first_run']:
            print("First run - no previous state to compare against")
            print(f"Found {len(current_policies)} policies")
        else:
            print(f"Added policies: {len(changes['added'])}")
            print(f"Modified policies: {len(changes['modified'])}")
            print(f"Deleted policies: {len(changes['deleted'])}")
            
            # Print details of changes if any
            if changes['added']:
                print("\nNew policies:")
                for policy in changes['added']:
                    print(f"  • {policy['displayName']} ({policy['state']})")
                    
            if changes['modified']:
                print("\nModified policies:")
                for policy in changes['modified']:
                    if policy['previous_state'] != policy['current_state']:
                        print(f"  • {policy['displayName']}: State changed from {policy['previous_state']} to {policy['current_state']}")
                    else:
                        print(f"  • {policy['displayName']}: Modified")
                        
            if changes['deleted']:
                print("\nDeleted policies:")
                for policy in changes['deleted']:
                    print(f"  • {policy['displayName']} ({policy['state']})")
        
        # Save current state if requested
        if save_state:
            self.save_current_state(current_policies)
            
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'changes': changes,
            'current_policies': current_policies
        }
        
    def continuous_monitoring(self, interval_minutes=60, max_runs=None):
        """
        Continuously monitor policies at specified intervals
        
        Args:
            interval_minutes: Time between checks in minutes
            max_runs: Maximum number of runs (None for infinite)
        """
        run_count = 0
        
        try:
            while True:
                print(f"\n=== Policy Monitor Check: {datetime.datetime.now().isoformat()} ===")
                
                # Detect and report changes
                drift_result = self.detect_policy_drift(save_state=True)
                
                # Increment run counter
                run_count += 1
                if max_runs is not None and run_count >= max_runs:
                    print(f"Reached maximum number of runs ({max_runs})")
                    break
                    
                # Sleep until next check
                next_check = datetime.datetime.now() + datetime.timedelta(minutes=interval_minutes)
                print(f"Next check at {next_check.strftime('%Y-%m-%d %H:%M:%S')}")
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")

# Example usage
if __name__ == "__main__":
    monitor = PolicyMonitor()
    monitor.continuous_monitoring(interval_minutes=10, max_runs=1)