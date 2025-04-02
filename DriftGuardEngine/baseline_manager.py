"""
BaselineManager - Module for managing SCuBA baselines in JSON format
"""

import os
import json
import logging
import requests
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('BaselineManager')

class BaselineManager:
    """
    Manages SCuBA baselines in JSON format for comparison against actual configurations
    """
    def __init__(self, baselines_dir="./baselines"):
        """Initialize the baseline manager"""
        self.baselines_dir = Path(baselines_dir)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        # The baseline files in ScubaGear are .md files, not .json files
        self.scuba_github_url = "https://raw.githubusercontent.com/tier3tech/ScubaGear/main/PowerShell/ScubaGear/baselines"
        
    def download_baseline(self, baseline_name, force=False):
        """
        Download a baseline from the SCuBA GitHub repository
        
        Args:
            baseline_name: Name of the baseline file (e.g., 'defender.json')
            force: Whether to override existing file
            
        Returns:
            Path to the downloaded baseline file
        """
        baseline_path = self.baselines_dir / baseline_name
        
        # Check if baseline already exists
        if baseline_path.exists() and not force:
            logger.info(f"Baseline {baseline_name} already exists at {baseline_path}")
            return baseline_path
            return baseline_path
            
        # Download the baseline
        logger.info(f"Downloading baseline {baseline_name} from CISA SCuBA GitHub repository")
        try:
            url = f"{self.scuba_github_url}/{baseline_name}"
            response = requests.get(url)
            response.raise_for_status()
            
            # Save the baseline
            with open(baseline_path, 'wb') as f:
                f.write(response.content)
                
            logger.info(f"Baseline {baseline_name} downloaded to {baseline_path}")
            return baseline_path
            
        except Exception as e:
            logger.error(f"Error downloading baseline {baseline_name}: {str(e)}")
            return None
            
    def download_all_baselines(self, force=False):
        """
        Download all SCuBA baselines
        
        Args:
            force: Whether to override existing files
            
        Returns:
            Dictionary of baseline names to their file paths
        """
        # Core SCuBA baseline files as of 2023
        baseline_files = [
            "aad.md",
            "defender.md",
            "exo.md",
            "powerbi.md",
            "powerplatform.md",
            "sharepoint.md",
            "teams.md"
        ]
        
        baselines = {}
        for baseline_name in baseline_files:
            baseline_path = self.download_baseline(baseline_name, force)
            if baseline_path:
                baselines[baseline_name] = baseline_path
                
        logger.info(f"Downloaded {len(baselines)} baselines")
        return baselines
        
    def load_baseline(self, baseline_name):
        """
        Load a baseline from the baselines directory
        
        Args:
            baseline_name: Name of the baseline file (e.g., 'defender.json')
            
        Returns:
            Baseline data as a dictionary
        """
        baseline_path = self.baselines_dir / baseline_name
        
        if not baseline_path.exists():
            logger.warning(f"Baseline {baseline_name} does not exist at {baseline_path}")
            # Try to download it
            baseline_path = self.download_baseline(baseline_name)
            
            if not baseline_path:
                logger.error(f"Could not load or download baseline {baseline_name}")
                return None
                
        try:
            with open(baseline_path, 'r') as f:
                baseline_data = json.load(f)
                
            logger.info(f"Loaded baseline {baseline_name}")
            return baseline_data
            
        except Exception as e:
            logger.error(f"Error loading baseline {baseline_name}: {str(e)}")
            return None
            
    def load_all_baselines(self):
        """
        Load all available baselines
        
        Returns:
            Dictionary of baseline names to their data
        """
        baselines = {}
        
        # Ensure we have the baseline files
        self.download_all_baselines()
        
        # Load each baseline file
        for baseline_file in self.baselines_dir.glob('*.json'):
            baseline_name = baseline_file.name
            baseline_data = self.load_baseline(baseline_name)
            
            if baseline_data:
                baselines[baseline_name] = baseline_data
                
        logger.info(f"Loaded {len(baselines)} baselines")
        return baselines
        
    def get_baseline_requirements(self, baseline_name):
        """
        Extract requirements from a baseline
        
        Args:
            baseline_name: Name of the baseline file (e.g., 'defender.json')
            
        Returns:
            List of requirements from the baseline
        """
        baseline_data = self.load_baseline(baseline_name)
        
        if not baseline_data:
            return []
            
        # Extract requirements from baseline
        requirements = []
        
        try:
            # SCuBA baselines have different structures depending on the workload
            if "requirements" in baseline_data:
                # Custom JSON format for our baselines
                requirements = baseline_data.get("requirements", [])
            elif "MS.AAD" in baseline_data:
                # AAD baseline
                for _, section in baseline_data.items():
                    if isinstance(section, dict) and "Requirements" in section:
                        requirements.extend(section["Requirements"])
            elif "ProductVersion" in baseline_data:
                # New format baselines
                for section in baseline_data.get("Sections", []):
                    requirements.extend(section.get("Requirements", []))
            else:
                # Old format baselines
                for section in baseline_data:
                    if isinstance(section, dict) and "Requirements" in section:
                        requirements.extend(section["Requirements"])
                        
            logger.info(f"Extracted {len(requirements)} requirements from {baseline_name}")
            return requirements
            
        except Exception as e:
            logger.error(f"Error extracting requirements from {baseline_name}: {str(e)}")
            return []
            
    def get_all_requirements(self):
        """
        Get all requirements from all baselines
        
        Returns:
            Dictionary of baseline names to their requirements
        """
        all_requirements = {}
        
        baselines = self.load_all_baselines()
        for baseline_name, baseline_data in baselines.items():
            requirements = self.get_baseline_requirements(baseline_name)
            all_requirements[baseline_name] = requirements
            
        return all_requirements

# Example usage
if __name__ == "__main__":
    manager = BaselineManager()
    # Download all baselines from CISA's SCuBA GitHub repository
    manager.download_all_baselines()
    # Load requirements from AAD baseline
    aad_requirements = manager.get_baseline_requirements("aad.json")
    print(f"Found {len(aad_requirements)} requirements in AAD baseline")