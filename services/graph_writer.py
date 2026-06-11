import logging
from config.database import db_graph

logger = logging.getLogger("looker.graph_writer")

class GraphWriter:
    @staticmethod
    def write_to_neo4j(elements: list) -> bool:
        """
        Writes normalized elements to Neo4j if available.
        Returns True if successful, False otherwise.
        """
        driver = db_graph._ensure_driver()
        if not driver:
            return False

        try:
            with db_graph.get_session() as session:
                for elem in elements:
                    data = elem.get("data", {})
                    
                    # 1. Process Nodes
                    if "id" in data and "source" not in data:
                        node_id = data["id"]
                        label = data.get("label", "")
                        node_type = data.get("type", "unknown")
                        
                        # Map type to Neo4j label capitalization
                        neo4j_label = node_type.capitalize()
                        if neo4j_label == "Ip":
                            neo4j_label = "IP"
                        
                        # Merge the node
                        query = f"""
                        MERGE (n:{neo4j_label} {{id: $id}})
                        SET n.label = $label, n.type = $type
                        RETURN count(n) as nodes
                        """
                        session.run(query, id=node_id, label=label, type=node_type)

                    # 2. Process Edges
                    elif "source" in data and "target" in data:
                        source = data["source"]
                        target = data["target"]
                        edge_label = data.get("label", "LINKED_TO").replace(" ", "_").upper()
                        confidence = data.get("confidence", 1.0)
                        edge_type = data.get("type", "raw")

                        # Determine labels for source and target
                        # For clean cypher MERGE, we look up based on id prefix or search dynamically
                        # A generic MERGE across arbitrary node types:
                        query = f"""
                        MATCH (a {{id: $source}}), (b {{id: $target}})
                        MERGE (a)-[r:{edge_label}]->(b)
                        SET r.confidence = $confidence, r.type = $edge_type
                        RETURN count(r) as relationships
                        """
                        session.run(query, source=source, target=target, confidence=confidence, edge_type=edge_type)
            return True
        except Exception as e:
            logger.error(f"Error writing to Neo4j: {e}")
            return False

    @staticmethod
    def write_in_memory(elements: list, graph_store: dict, lock) -> None:
        """
        Fallback writer to append elements to Looker's local in-memory GRAPH_STORE.
        """
        with lock:
            for elem in elements:
                data = elem.get("data", {})
                if "id" in data and "source" not in data:
                    node_id = data["id"]
                    # Add node
                    graph_store["nodes"][node_id] = elem
                elif "source" in data and "target" in data:
                    # Avoid duplicate edges
                    source = data["source"]
                    target = data["target"]
                    label = data.get("label", "")
                    
                    edge_exists = False
                    for existing in graph_store["edges"]:
                        ex_data = existing.get("data", {})
                        if (ex_data.get("source") == source and 
                            ex_data.get("target") == target and 
                            ex_data.get("label") == label):
                            edge_exists = True
                            # Update confidence
                            ex_data["confidence"] = data.get("confidence", 1.0)
                            ex_data["type"] = data.get("type", "raw")
                            break
                    
                    if not edge_exists:
                        graph_store["edges"].append(elem)
