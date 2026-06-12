import hashlib
from typing import List, Dict, Any, Tuple
from services.entity_resolution import ResolvedEntity

class CorrelationEngine:
    @staticmethod
    def correlate(
        subject_id: str, 
        resolved_entities: List[ResolvedEntity], 
        implicit_links: List[Tuple[str, str, str, float]]
    ) -> List[Dict[str, Any]]:
        """
        Processes resolved entities and linkages to build the Cytoscape graph payload.
        Computes edge confidence scores.
        
        Returns a list of Cytoscape element dicts:
        [
          {"data": {"id": "...", "label": "...", "type": "subject"}},
          {"data": {"source": "...", "target": "...", "label": "...", "confidence": 0.85, "type": "inferred"}}
        ]
        """
        elements = []
        node_ids = set()

        # Helper to safely add unique nodes
        def add_node(node_id: str, label: str, node_type: str, metadata: dict = None):
            if node_id not in node_ids:
                elements.append({
                    "data": {
                        "id": node_id,
                        "label": label,
                        "type": node_type,
                        **(metadata or {})
                    }
                })
                node_ids.add(node_id)

        # 1. Add Core Subject node
        add_node(subject_id, subject_id.split("::")[-1], "subject")

        # 2. Add Resolved Identifier nodes and OBSERVED_IN source links
        for entity in resolved_entities:
            entity_id = f"indicator::{entity.entity_type}::{entity.value}"
            node_type = entity.entity_type # 'username', 'email', 'domain', 'phone', 'ip', etc.

            # Special Handling for Usernames to build Identity Clusters
            if entity.entity_type == "username":
                # Create an IdentityCluster node for the username
                cluster_id = f"cluster::username::{hashlib.sha256(entity.value.encode('utf-8')).hexdigest()[:12]}"
                add_node(cluster_id, f"Cluster: {entity.value}", "identity_cluster")

                # Link Subject -> IdentityCluster
                elements.append({
                    "data": {
                        "source": subject_id,
                        "target": cluster_id,
                        "label": "INFERRED_IDENTITY",
                        "confidence": 1.0,
                        "type": "raw"
                    }
                })

                # Link the IdentityCluster to each discovered profile on specific sites
                for obs in entity.observations:
                    if "whatsmyname" in obs.source:
                        site_name = obs.source.split("::")[-1]
                        profile_id = f"profile::{site_name}::{obs.value}"
                        
                        # Add individual profile node
                        add_node(profile_id, f"{obs.value} ({site_name.capitalize()})", "username")

                        # Link IdentityCluster -> Discovered Profile
                        elements.append({
                            "data": {
                                "source": cluster_id,
                                "target": profile_id,
                                "label": "BELONGS_TO",
                                "confidence": obs.confidence,
                                "type": "inferred" if obs.confidence < 0.85 else "raw"
                            }
                        })
                    else:
                        # Fallback for non-WMS username observations
                        add_node(entity_id, entity.value, node_type)
                        elements.append({
                            "data": {
                                "source": subject_id,
                                "target": entity_id,
                                "label": f"HAS_{entity.entity_type.upper()}",
                                "confidence": entity.confidence,
                                "type": "raw"
                            }
                        })
            else:
                # Normal indicators (emails, domains, phones, IPs)
                add_node(entity_id, entity.value, node_type)
                elements.append({
                    "data": {
                        "source": subject_id,
                        "target": entity_id,
                        "label": f"HAS_{entity.entity_type.upper()}",
                        "confidence": entity.confidence,
                        "type": "raw"
                    }
                })

                # Add Source nodes and OBSERVED_IN edges
                for src in entity.sources:
                    src_clean = src.split("::")[-1].lower()
                    src_node_id = f"source::{hashlib.sha256(src_clean.encode('utf-8')).hexdigest()[:12]}"
                    add_node(src_node_id, src_clean.capitalize(), "source")
                    
                    # Link Identifier -> Source
                    elements.append({
                        "data": {
                            "source": entity_id,
                            "target": src_node_id,
                            "label": "OBSERVED_IN",
                            "confidence": entity.confidence,
                            "type": "raw"
                        }
                    })

        # 3. Add Implicit Links discovered from text scraping
        for src_val, src_type, tgt_val, tgt_type, rel_label, conf in implicit_links:
            src_id = f"indicator::{src_type}::{src_val}"
            tgt_id = f"indicator::{tgt_type}::{tgt_val}"
            
            if src_id in node_ids and tgt_id in node_ids:
                elements.append({
                    "data": {
                        "source": src_id,
                        "target": tgt_id,
                        "label": rel_label,
                        "confidence": conf,
                        "type": "inferred"
                    }
                })

        return elements

