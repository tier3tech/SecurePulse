"""
VectorReportStore - Uses vector embeddings to store and retrieve tenant-specific scan results
"""

import os
import json
import time
import uuid
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.utils import embedding_functions

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('VectorReportStore')

class VectorReportStore:
    """
    Stores scan results in a vector database to enable tracking changes over time
    and comparing results across different scan types and tenants.
    """

    def __init__(self, 
                 db_path: str = "./vector_db",
                 model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the vector store with a path to the database directory.
        
        Args:
            db_path: Path to store the vector database files
            model_name: The sentence transformer model to use for embeddings
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB client
        logger.info(f"Initializing vector database at {db_path}")
        self.client = chromadb.PersistentClient(path=str(self.db_path))
        
        # Setup embedding function
        logger.info(f"Initializing embedding model: {model_name}")
        self.embedding_func = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=model_name)
        
        # Create collections for different scan types
        self._create_collections()
        
    def _create_collections(self):
        """Create collections for different scan types if they don't exist"""
        # Collection for DriftGuard findings
        self.drift_collection = self._get_or_create_collection("drift_findings")
        
        # Collection for AccessWatch findings
        self.access_collection = self._get_or_create_collection("access_findings")
        
        # Collection for LicenseLogic findings
        self.license_collection = self._get_or_create_collection("license_findings")
        
        # Collection for overall tenant metrics
        self.metrics_collection = self._get_or_create_collection("tenant_metrics")
        
    def _get_or_create_collection(self, name):
        """Get or create a collection with the given name"""
        try:
            return self.client.get_collection(
                name=name, 
                embedding_function=self.embedding_func
            )
        except Exception:
            return self.client.create_collection(
                name=name, 
                embedding_function=self.embedding_func
            )

    def store_drift_findings(self, 
                            tenant_id: str, 
                            scan_date: str, 
                            findings: List[Dict[str, Any]]) -> int:
        """
        Store drift detection findings in the vector database.
        
        Args:
            tenant_id: The ID of the tenant these findings belong to
            scan_date: The date of the scan in ISO format
            findings: List of individual drift findings
            
        Returns:
            Number of stored findings
        """
        if not findings:
            logger.info(f"No drift findings to store for tenant {tenant_id}")
            return 0
            
        # Create documents and metadata for each finding
        documents = []
        metadatas = []
        ids = []
        
        for i, finding in enumerate(findings):
            # Create a text representation of the finding for embedding
            text_repr = self._create_text_representation(finding)
            documents.append(text_repr)
            
            # Store the full finding in metadata
            metadata = {
                "tenant_id": tenant_id,
                "scan_date": scan_date,
                "finding_type": "drift",
                "workload": finding.get("workload", "Unknown"),
                "requirement_id": finding.get("requirementId", "Unknown"),
                "status": finding.get("status", "Unknown"),
                "severity": self._calculate_severity(finding),
                "full_finding": json.dumps(finding)
            }
            metadatas.append(self._sanitize_metadata(metadata))
            
            # Create a unique ID for this finding
            finding_id = f"drift_{tenant_id}_{scan_date}_{i}"
            ids.append(finding_id)
        
        # Store in the database
        self.drift_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        logger.info(f"Stored {len(documents)} drift findings for tenant {tenant_id}")
        return len(documents)
        
    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize metadata to ensure all values are compatible with ChromaDB requirements.
        
        Args:
            metadata: The metadata dictionary to sanitize
            
        Returns:
            Sanitized metadata with all None values replaced with appropriate defaults
        """
        sanitized = {}
        for key, value in metadata.items():
            if value is None:
                # Replace None with appropriate default based on key type
                if key.lower().endswith('_id') or key.lower() == 'id':
                    sanitized[key] = ""  # Empty string for IDs
                elif key.lower().endswith('name'):
                    sanitized[key] = ""  # Empty string for names
                elif key.lower() in ('is_admin', 'enabled', 'active'):
                    sanitized[key] = False  # False for boolean flags
                elif key.lower() in ('count', 'total', 'value'):
                    sanitized[key] = 0  # 0 for numeric values
                else:
                    sanitized[key] = ""  # Default to empty string
            else:
                sanitized[key] = value
        return sanitized

    def store_access_findings(self, 
                             tenant_id: str, 
                             scan_date: str, 
                             compliance_data: Dict[str, Any],
                             ca_analysis: Dict[str, Any]) -> int:
        """
        Store AccessWatch findings in the vector database.
        
        Args:
            tenant_id: The ID of the tenant these findings belong to
            scan_date: The date of the scan in ISO format
            compliance_data: MFA compliance data
            ca_analysis: Conditional Access analysis data
            
        Returns:
            Number of stored findings
        """
        documents = []
        metadatas = []
        ids = []
        
        # Store at-risk users
        for i, user in enumerate(compliance_data.get("atRiskUsers", [])):
            # Create text representation
            text_repr = f"User {user.get('displayName')} ({user.get('userPrincipalName')}) does not have MFA enabled. Risk level: {user.get('riskLevel')}"
            documents.append(text_repr)
            
            # Store metadata
            metadata = {
                "tenant_id": tenant_id,
                "scan_date": scan_date,
                "finding_type": "access_mfa",
                "user": user.get("userPrincipalName", ""),
                "is_admin": user.get("isAdmin", False),
                "risk_level": user.get("riskLevel", "Medium"),
                "full_finding": json.dumps(user)
            }
            metadatas.append(self._sanitize_metadata(metadata))
            
            # Create ID
            finding_id = f"access_mfa_{tenant_id}_{scan_date}_{i}"
            ids.append(finding_id)
        
        # Store conditional access policy gaps
        for i, gap in enumerate(ca_analysis.get("mfaPolicyGaps", [])):
            # Create text representation
            policy_name = gap.get('policyName')
            text_repr = f"Conditional Access gap: {gap.get('description')} Policy: {policy_name or 'No policy'}"
            documents.append(text_repr)
            
            # Store metadata
            metadata = {
                "tenant_id": tenant_id,
                "scan_date": scan_date,
                "finding_type": "access_ca",
                "policy_name": gap.get("policyName", ""),
                "coverage": gap.get("coverage", "Unknown"),
                "full_finding": json.dumps(gap)
            }
            metadatas.append(self._sanitize_metadata(metadata))
            
            # Create ID
            finding_id = f"access_ca_{tenant_id}_{scan_date}_{i}"
            ids.append(finding_id)
            
        # Store in the database if we have findings
        if documents:
            self.access_collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
        logger.info(f"Stored {len(documents)} access findings for tenant {tenant_id}")
        return len(documents)
        
    def store_license_findings(self, 
                              tenant_id: str, 
                              scan_date: str, 
                              license_data: Dict[str, Any]) -> int:
        """
        Store LicenseLogic findings in the vector database.
        
        Args:
            tenant_id: The ID of the tenant these findings belong to
            scan_date: The date of the scan in ISO format
            license_data: License findings and recommendations
            
        Returns:
            Number of stored findings
        """
        documents = []
        metadatas = []
        ids = []
        
        # Process license optimization recommendations
        for i, rec in enumerate(license_data.get("recommendations", [])):
            # Create text representation
            text_repr = f"License recommendation: {rec.get('description')}"
            documents.append(text_repr)
            
            # Store metadata
            metadata = {
                "tenant_id": tenant_id,
                "scan_date": scan_date,
                "finding_type": "license",
                "impact": rec.get("impact", "Unknown"),
                "estimated_savings": rec.get("estimatedSavings", 0),
                "license_type": rec.get("licenseType", ""),
                "full_finding": json.dumps(rec)
            }
            metadatas.append(self._sanitize_metadata(metadata))
            
            # Create ID
            finding_id = f"license_{tenant_id}_{scan_date}_{i}"
            ids.append(finding_id)
            
        # Store in the database if we have findings
        if documents:
            self.license_collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
        logger.info(f"Stored {len(documents)} license findings for tenant {tenant_id}")
        return len(documents)
        
    def store_tenant_metrics(self,
                            tenant_id: str,
                            tenant_name: str,
                            scan_date: str,
                            metrics: Dict[str, Any]) -> str:
        """
        Store overall tenant metrics in the vector database.
        
        Args:
            tenant_id: The ID of the tenant
            tenant_name: The name of the tenant
            scan_date: The date of the scan in ISO format
            metrics: Dictionary of metrics to store
            
        Returns:
            ID of the stored metrics document
        """
        # Create a text representation of the metrics
        metrics_text = f"Tenant: {tenant_name}, ID: {tenant_id}, Date: {scan_date}\n"
        for key, value in metrics.items():
            metrics_text += f"{key}: {value}\n"
            
        # Create a unique ID
        metrics_id = f"metrics_{tenant_id}_{scan_date}"
        
        # Store in the database
        metadata = {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "scan_date": scan_date,
            "scan_type": metrics.get("scan_type", "Unknown"),
            "full_metrics": json.dumps(metrics)
        }
        
        self.metrics_collection.add(
            documents=[metrics_text],
            metadatas=[self._sanitize_metadata(metadata)],
            ids=[metrics_id]
        )
        
        logger.info(f"Stored metrics for tenant {tenant_id} from {scan_date}")
        return metrics_id
        
    def get_tenant_findings(self, 
                           tenant_id: str, 
                           finding_type: str = None,
                           start_date: str = None,
                           end_date: str = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get findings for a specific tenant with optional filters.
        
        Args:
            tenant_id: The ID of the tenant
            finding_type: Optional type of finding to filter by
            start_date: Optional start date for date range filtering
            end_date: Optional end date for date range filtering
            limit: Maximum number of results to return
            
        Returns:
            List of findings matching the criteria
        """
        # Build the filter
        filter_dict = {"tenant_id": tenant_id}
        if finding_type:
            filter_dict["finding_type"] = finding_type
            
        # Handle date range filtering
        if start_date or end_date:
            date_filters = []
            if start_date:
                date_filters.append({"scan_date": {"$gte": start_date}})
            if end_date:
                date_filters.append({"scan_date": {"$lte": end_date}})
                
            if date_filters:
                filter_dict["$and"] = date_filters
                
        # Query the appropriate collection based on finding type
        collection = self._get_collection_for_finding_type(finding_type)
        
        # Execute the query
        results = collection.query(
            query_texts=["finding"],  # Need to provide a query text
            where=filter_dict,
            n_results=limit
        )
        
        # Process the results
        findings = []
        for i, meta in enumerate(results.get("metadatas", [])):
            # Parse the full finding from the metadata
            full_finding = json.loads(meta.get("full_finding", "{}"))
            
            # Add the finding with its metadata
            findings.append({
                "id": results["ids"][i],
                "metadata": {k: v for k, v in meta.items() if k != "full_finding"},
                "finding": full_finding
            })
            
        return findings
        
    def get_tenant_metrics_over_time(self, 
                                    tenant_id: str,
                                    metric_names: List[str] = None,
                                    start_date: str = None,
                                    end_date: str = None) -> Dict[str, List[Tuple[str, float]]]:
        """
        Get metrics for a tenant over time for trend analysis.
        
        Args:
            tenant_id: The ID of the tenant
            metric_names: Optional list of metric names to retrieve
            start_date: Optional start date for date range filtering
            end_date: Optional end date for date range filtering
            
        Returns:
            Dictionary mapping metric names to lists of (date, value) tuples
        """
        # Build the filter
        filter_dict = {"tenant_id": tenant_id}
            
        # Handle date range filtering - ChromaDB doesn't support complex filters with $and
        # so we'll have to do date filtering in memory after getting all results
        # if start_date:
        #     filter_dict["scan_date"] = {"$gte": start_date}
        # if end_date:
        #     filter_dict["scan_date"] = {"$lte": end_date}
                
        # Execute the query
        results = self.metrics_collection.query(
            query_texts=["metrics"],  # Need to provide a query text
            where=filter_dict,
            n_results=1000  # High limit to get all historical data
        )
        
        # Process the results
        metrics_over_time = {}
        
        # ChromaDB returns results with metadatas as a list of lists
        # Each inner list corresponds to one result
        metadatas = results.get("metadatas", [])
        
        for meta_list in metadatas:
            # Each meta_list is a list of metadata dictionaries for each result
            for meta in meta_list if isinstance(meta_list, list) else [meta_list]:
                # Parse the full metrics
                scan_date = meta.get("scan_date")
                
                # Apply date filtering in memory since ChromaDB doesn't support complex filters
                if start_date and scan_date < start_date:
                    continue
                if end_date and scan_date > end_date:
                    continue
                    
                full_metrics = json.loads(meta.get("full_metrics", "{}"))
                
                # Filter to requested metrics if specified
                if metric_names:
                    filtered_metrics = {k: v for k, v in full_metrics.items() if k in metric_names}
                else:
                    filtered_metrics = full_metrics
                    
                # Add to the time series for each metric
                for metric_name, value in filtered_metrics.items():
                    if metric_name not in metrics_over_time:
                        metrics_over_time[metric_name] = []
                        
                    # Only add numeric values or convert to numeric if possible
                    try:
                        numeric_value = float(value)
                        metrics_over_time[metric_name].append((scan_date, numeric_value))
                    except (ValueError, TypeError):
                        # Skip non-numeric values
                        pass
                    
        # Sort each metric series by date
        for metric_name in metrics_over_time:
            metrics_over_time[metric_name].sort(key=lambda x: x[0])
            
        return metrics_over_time
        
    def compare_findings(self,
                        tenant_id: str,
                        current_date: str,
                        previous_date: str,
                        finding_type: str = None) -> Dict[str, Any]:
        """
        Compare findings between two scan dates to identify resolved and new issues.
        
        Args:
            tenant_id: The ID of the tenant
            current_date: The current scan date in ISO format
            previous_date: The previous scan date to compare against
            finding_type: Optional type of finding to filter by
            
        Returns:
            Dictionary with resolved and new issues
        """
        # Get findings from both dates
        current_findings = self.get_tenant_findings(
            tenant_id=tenant_id,
            finding_type=finding_type,
            start_date=current_date,
            end_date=current_date,
            limit=1000
        )
        
        previous_findings = self.get_tenant_findings(
            tenant_id=tenant_id,
            finding_type=finding_type,
            start_date=previous_date,
            end_date=previous_date,
            limit=1000
        )
        
        # Find resolved issues (in previous but not in current)
        resolved_issues = []
        for prev in previous_findings:
            # Check if this finding is still present in current findings
            is_resolved = True
            prev_text = self._create_text_representation(prev["finding"])
            
            for curr in current_findings:
                curr_text = self._create_text_representation(curr["finding"])
                similarity = self._calculate_similarity(prev_text, curr_text)
                
                if similarity > 0.85:  # Threshold for considering findings the same
                    is_resolved = False
                    break
                    
            if is_resolved:
                resolved_issues.append(prev)
                
        # Find new issues (in current but not in previous)
        new_issues = []
        for curr in current_findings:
            # Check if this finding is new
            is_new = True
            curr_text = self._create_text_representation(curr["finding"])
            
            for prev in previous_findings:
                prev_text = self._create_text_representation(prev["finding"])
                similarity = self._calculate_similarity(curr_text, prev_text)
                
                if similarity > 0.85:  # Threshold for considering findings the same
                    is_new = False
                    break
                    
            if is_new:
                new_issues.append(curr)
                
        return {
            "tenant_id": tenant_id,
            "current_date": current_date,
            "previous_date": previous_date,
            "finding_type": finding_type,
            "total_previous_findings": len(previous_findings),
            "total_current_findings": len(current_findings),
            "resolved_issues": resolved_issues,
            "new_issues": new_issues,
            "total_resolved": len(resolved_issues),
            "total_new": len(new_issues)
        }
        
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts using the embedding model"""
        # Use the embedding function to get vectors
        embedding1 = self.embedding_func([text1])[0]
        embedding2 = self.embedding_func([text2])[0]
        
        # Calculate cosine similarity
        dot_product = np.dot(embedding1, embedding2)
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)
        
        return dot_product / (norm1 * norm2)
        
    def _create_text_representation(self, finding: Dict[str, Any]) -> str:
        """Create a text representation of a finding for embedding"""
        # This will vary based on the finding type
        if "requirementId" in finding:
            # It's a drift finding
            return f"{finding.get('workload', 'Unknown')}: {finding.get('requirementId', 'Unknown')} - {finding.get('title', 'Unknown')}. Status: {finding.get('status', 'Unknown')}. Description: {finding.get('description', '')}. Current value: {finding.get('currentValue')}. Required value: {finding.get('requiredValue')}."
        elif "userPrincipalName" in finding:
            # It's a user MFA finding
            return f"User {finding.get('displayName', '')} ({finding.get('userPrincipalName', '')}) does not have MFA enabled. Risk level: {finding.get('riskLevel', 'Medium')}."
        elif "policyName" in finding:
            # It's a CA policy finding
            return f"Conditional Access gap: {finding.get('description', '')} Policy: {finding.get('policyName', '')}"
        elif "description" in finding and "licenseType" in finding:
            # It's a license finding
            return f"License recommendation: {finding.get('description', '')} for {finding.get('licenseType', '')}. Impact: {finding.get('impact', 'Unknown')}. Estimated savings: {finding.get('estimatedSavings', 0)}."
        else:
            # Generic fallback
            return json.dumps(finding)
            
    def _calculate_severity(self, finding: Dict[str, Any]) -> str:
        """Calculate severity for a finding based on its properties"""
        # For drift findings
        if "impact" in finding:
            impact = finding.get("impact", "Medium").lower()
            if "high" in impact:
                return "High"
            elif "medium" in impact:
                return "Medium"
            elif "low" in impact:
                return "Low"
                
        # For access findings
        if "riskLevel" in finding:
            return finding.get("riskLevel", "Medium")
            
        # For license findings
        if "estimatedSavings" in finding:
            savings = finding.get("estimatedSavings", 0)
            if isinstance(savings, (int, float)):
                if savings > 1000:
                    return "High"
                elif savings > 300:
                    return "Medium"
                else:
                    return "Low"
                    
        # Default
        return "Medium"
        
    def _get_collection_for_finding_type(self, finding_type: str = None):
        """Get the appropriate collection based on finding type"""
        if finding_type in ("drift", None):
            return self.drift_collection
        elif finding_type in ("access_mfa", "access_ca"):
            return self.access_collection
        elif finding_type == "license":
            return self.license_collection
        else:
            return self.drift_collection  # Default