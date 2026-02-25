#!/usr/bin/env python3
"""Generate benchmark data files for cortex test-fixtures.

Run: python3 gen_benchmarks.py
Outputs: memories_100.json, memories_1k.json, memories_10k.json, causal_graph_1k_edges.json
"""
import json
import random
import uuid
import hashlib
from datetime import datetime, timedelta, timezone

MEMORY_TYPES = [
    "core", "tribal", "procedural", "semantic", "episodic",
    "decision", "insight", "reference", "preference",
    "pattern_rationale", "constraint_override", "decision_context", "code_smell",
    "agent_spawn", "entity", "goal", "feedback", "workflow",
    "conversation", "incident", "meeting", "skill", "environment"
]

IMPORTANCE_LEVELS = ["low", "normal", "high", "critical"]
TAGS_POOL = [
    "rust", "typescript", "database", "api", "security", "performance",
    "testing", "deployment", "monitoring", "caching", "auth", "config",
    "error-handling", "logging", "architecture", "refactoring",
    "documentation", "ci-cd", "docker", "kubernetes"
]

TOPICS = [
    "database connection pooling", "error handling patterns", "authentication flow",
    "caching strategy with moka", "deployment pipeline configuration",
    "SQLite WAL mode optimization", "embedding model selection",
    "token budget management", "memory consolidation pipeline",
    "causal graph traversal", "privacy sanitization patterns",
    "compression level selection", "decay formula tuning",
    "session deduplication logic", "cloud sync conflict resolution",
    "HDBSCAN clustering parameters", "validation healing actions",
    "learning from user corrections", "prediction signal gathering",
    "observability and health checks"
]

def make_content(mtype, idx):
    topic = TOPICS[idx % len(TOPICS)]
    if mtype == "episodic":
        return {"type": "episodic", "data": {"interaction": f"Worked on {topic} — iteration {idx}", "context": f"Development session #{idx}", "outcome": f"Progress on {topic}"}}
    elif mtype == "semantic":
        return {"type": "semantic", "data": {"knowledge": f"The system uses {topic} for optimal performance. Key insight #{idx}.", "source_episodes": [f"ep-{idx}"], "consolidation_confidence": round(random.uniform(0.6, 0.95), 2)}}
    elif mtype == "tribal":
        return {"type": "tribal", "data": {"knowledge": f"Important: {topic} must follow established patterns. Rule #{idx}.", "severity": random.choice(["normal", "high", "critical"]), "warnings": [f"Warning about {topic}"], "consequences": [f"Impact on {topic}"]}}
    elif mtype == "decision":
        return {"type": "decision", "data": {"decision": f"Decision #{idx} regarding {topic}", "rationale": f"Based on analysis of {topic}", "alternatives": [{"description": f"Alternative approach to {topic}", "reason_rejected": "Did not meet requirements"}]}}
    elif mtype == "procedural":
        return {"type": "procedural", "data": {"title": f"How to {topic}", "steps": [{"order": 1, "instruction": f"Step 1 for {topic}", "completed": False}], "prerequisites": ["Basic setup"]}}
    elif mtype == "insight":
        return {"type": "insight", "data": {"observation": f"Observation #{idx} about {topic}", "evidence": [f"Evidence from {topic} analysis"]}}
    elif mtype == "preference":
        return {"type": "preference", "data": {"preference": f"Prefer {topic} approach", "scope": "workspace", "value": idx}}
    elif mtype == "reference":
        return {"type": "reference", "data": {"title": f"Reference for {topic}", "url": f"https://docs.example.com/{topic.replace(' ', '-')}", "citation": f"See documentation on {topic}"}}
    elif mtype == "incident":
        return {"type": "incident", "data": {"title": f"Incident #{idx}: {topic} failure", "root_cause": f"Root cause in {topic}", "resolution": f"Fixed {topic} issue", "severity": random.choice(["low", "medium", "high", "critical"]), "timeline": [f"T+0: {topic} alert"], "lessons_learned": [f"Lesson from {topic}"]}}
    elif mtype == "core":
        return {"type": "core", "data": {"project_name": "cortex", "description": f"Core config #{idx} for {topic}", "metadata": {"version": idx}}}
    else:
        return {"type": "episodic", "data": {"interaction": f"Generic memory #{idx} about {topic}", "context": "general", "outcome": None}}

def gen_memory(idx):
    mtype = MEMORY_TYPES[idx % len(MEMORY_TYPES)]
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=idx)
    content = make_content(mtype, idx)
    content_str = json.dumps(content)
    content_hash = hashlib.blake2b(content_str.encode(), digest_size=32).hexdigest()
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"bench-{idx}")),
        "memory_type": mtype,
        "content": content,
        "summary": f"Benchmark memory #{idx}: {TOPICS[idx % len(TOPICS)][:50]}",
        "transaction_time": base_time.isoformat(),
        "valid_time": base_time.isoformat(),
        "valid_until": None,
        "confidence": round(random.uniform(0.3, 1.0), 3),
        "importance": random.choice(IMPORTANCE_LEVELS),
        "last_accessed": (base_time + timedelta(days=random.randint(0, 30))).isoformat(),
        "access_count": random.randint(0, 50),
        "linked_patterns": [],
        "linked_constraints": [],
        "linked_files": [],
        "linked_functions": [],
        "tags": random.sample(TAGS_POOL, k=random.randint(1, 4)),
        "archived": False,
        "superseded_by": None,
        "supersedes": None,
        "content_hash": content_hash
    }

def gen_causal_graph(num_edges):
    nodes = [{"memory_id": f"causal-{i}", "memory_type": "domain_agnostic", "summary": f"Causal node {i}: {TOPICS[i % len(TOPICS)]}"} for i in range(num_edges + 100)]
    edges = []
    relations = ["caused", "enabled", "prevented", "supports", "derived_from", "triggered_by"]
    for i in range(num_edges):
        src = random.randint(0, len(nodes) - 2)
        tgt = random.randint(src + 1, min(src + 50, len(nodes) - 1))
        edges.append({
            "source": nodes[src]["memory_id"],
            "target": nodes[tgt]["memory_id"],
            "relation": random.choice(relations),
            "strength": round(random.uniform(0.2, 1.0), 3),
            "evidence": []
        })
    return {"nodes": nodes, "edges": edges}

if __name__ == "__main__":
    random.seed(42)

    for count, fname in [(100, "memories_100.json"), (1000, "memories_1k.json"), (10000, "memories_10k.json")]:
        memories = [gen_memory(i) for i in range(count)]
        with open(fname, "w") as f:
            json.dump({"description": f"{count} benchmark memories", "count": count, "memories": memories}, f, indent=None if count > 1000 else 2)
        print(f"Generated {fname} ({count} memories)")

    graph = gen_causal_graph(1000)
    with open("causal_graph_1k_edges.json", "w") as f:
        json.dump({"description": "1K-edge causal graph for traversal benchmarks", "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]), **graph}, f, indent=2)
    print(f"Generated causal_graph_1k_edges.json ({len(graph['edges'])} edges)")
