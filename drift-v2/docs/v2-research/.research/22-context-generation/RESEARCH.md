# 22 Context Generation — External Research

> Targeted external research to find verifiable best practices from trusted, authoritative sources. Each finding is documented with source, tier, access date, key findings, applicability to Drift, and confidence level.
>
> **Research Date**: February 2026
> **Methodology**: Per RESEARCH_METHODOLOGY.md — Tier 1 (authoritative) through Tier 4 (reference only)

---

## R1: Context Rot — Why Shorter, Focused Context Outperforms Long Context

**Source**: Chroma Research — "Context Rot: How Increasing Input Tokens Impacts LLM Performance" (Hong, Troynikov, Huber, July 2025)
**Coverage**: [PromptLayer analysis](https://blog.promptlayer.com/why-llms-get-distracted-and-how-to-write-shorter-prompts/), [PromptHub analysis](https://www.prompthub.us/blog/why-long-context-windows-still-dont-work), [Hamel Husain analysis](https://hamel.dev/notes/llm/rag/p6-context_rot.html)
**Type**: Tier 1 (peer-reviewed research)
**Accessed**: February 2026

**Key Findings**:
- Chroma tested 18 state-of-the-art LLMs and found performance degrades significantly as input length grows, even on trivially simple tasks like "repeat this string"
- The phenomenon is called "context rot" — accuracy drops consistently as context windows fill, contradicting the marketing pitch of million-token windows
- Lower semantic similarity between query and supporting content causes faster degradation — loosely related context actively hurts performance
- The research demonstrates that selective, high-relevance context consistently outperforms dumping everything into the prompt

**Applicability to Drift**:
This is the foundational justification for Drift's entire context generation approach. Rather than giving AI agents raw access to everything, Drift curates exactly what's relevant. V2 must double down on this: every token in the context window must earn its place through relevance scoring. The current approach of sorting by occurrences and trimming by priority is too crude — v2 needs semantic relevance ranking to ensure the highest-signal tokens survive trimming.

**Confidence**: High — multiple independent analyses confirm the findings across 18 models.

---

## R2: LangChain Deep Agents — Context Compression Techniques

**Source**: [LangChain Blog — Context Management for Deep Agents](https://www.blog.langchain.com/context-management-for-deepagents/) (January 2026)
**Type**: Tier 2 (industry expert — major framework)
**Accessed**: February 2026

**Key Findings**:
- Deep Agents implements three compression techniques triggered at different frequencies:
  1. **Offloading large tool results**: When a tool response exceeds 20,000 tokens, it's offloaded to filesystem with a file path reference and 10-line preview
  2. **Offloading large tool inputs**: At 85% context capacity, older write/edit tool call arguments are truncated and replaced with file pointers
  3. **Summarization**: When offloading is exhausted, an LLM generates a structured summary (session intent, artifacts created, next steps) that replaces full conversation history
- Compression is triggered at threshold fractions of the model's context window size
- Uses LangChain's model profiles to access token thresholds per model
- Complete original messages are preserved on filesystem for recovery via search

**Applicability to Drift**:
Drift's context generation should adopt a similar tiered compression strategy. Instead of greedy section-cutting, v2 should implement progressive compression: first reduce low-value details (examples, dependency patterns), then compress remaining content via summarization, then offload to reference-only format. The key insight is that compression should be model-aware — different models have different context windows and different degradation curves.

**Confidence**: High — production-tested framework with benchmark validation.

---

## R3: Anthropic & Karpathy — Context Engineering as a Discipline

**Source**: [Anthropic Engineering Blog](https://howaiworks.ai/blog/anthropic-context-engineering-for-agents) (September 2025), Andrej Karpathy (quoted in [multiple sources](https://github.com/davidkimai/Context-Engineering))
**Type**: Tier 1 (authoritative — model provider + leading researcher)
**Accessed**: February 2026

**Key Findings**:
- Karpathy frames LLMs as "a new kind of operating system where the model is the CPU and its context window is the RAM" — context engineering is about what's loaded into that RAM
- Anthropic's engineering team states the core question is: "What configuration of context is most likely to generate our model's desired behavior?"
- Three core strategies identified by OpenAI's Build Hour on Agent Memory Patterns:
  1. **Reshape and fit** to the context window
  2. **Isolate and route** the right amount of context to the right agent
  3. **Extract high-quality memories** to retrieve at the right time
- Context engineering is described as "the delicate art and science of filling the context window with just the right information for the next step"

**Applicability to Drift**:
Drift's context generation IS context engineering. V2 should explicitly adopt this framing: the context generator is an operating system's memory manager. It must decide what to load (relevance scoring), how much to load (token budgeting), when to evict (trimming), and how to compress (summarization). The "isolate and route" principle maps directly to intent-aware context — different intents need different context configurations.

**Confidence**: High — foundational framing from the field's leading researchers.

---

## R4: Cursor — Semantic Codebase Indexing Architecture

**Source**: [Cursor Blog — Securely Indexing Large Codebases](https://cursor.com/blog/secure-codebase-indexing) (January 2026), [Cursor Docs — Codebase Indexing](https://docs.cursor.com/context/codebase-indexing)
**Type**: Tier 2 (industry expert — leading AI code editor)
**Accessed**: February 2026

**Key Findings**:
- Cursor uses Merkle trees for incremental change detection — cryptographic hash of every file, with folder hashes derived from children
- Semantic search improved response accuracy by 12.5% on average and produced code changes more likely to be retained
- Files are split into syntactic chunks, then converted to embeddings for semantic search
- Embeddings are cached by chunk content — unchanged chunks hit cache
- For large repos, Cursor reuses teammate indexes (92% similarity across clones of same codebase)
- Time-to-first-query drops from hours to seconds via index reuse (median: 7.87s → 525ms)

**Applicability to Drift**:
Drift's context generation should adopt Merkle-tree-based change detection for incremental context invalidation. When patterns, constraints, or call graph data change, only affected context sections need regeneration. The syntactic chunking + embedding approach is directly applicable to semantic ranking of patterns — embed patterns and queries, rank by cosine similarity. The 12.5% accuracy improvement from semantic search validates the need for semantic ranking in Drift's context output.

**Confidence**: High — production system serving millions of developers with measured improvements.

---

## R5: Augment Code — Context Engine Architecture

**Source**: [Augment Code — Context Engine](https://www.augmentcode.com/context-engine), [Augment Code — AI Context Engines vs Traditional Code Search](https://www.augmentcode.com/guides/ai-context-engines-vs-traditional-enterprise-code-search-the-definitive-comparison-guide)
**Type**: Tier 2 (industry expert — enterprise AI coding tool)
**Accessed**: February 2026

**Key Findings**:
- Augment's Context Engine processes 400,000+ files through semantic dependency graph analysis
- Achieves 70.6% accuracy on SWE-bench vs 54% for traditional assistants — a 30% improvement attributed to context quality
- Maintains a real-time index tracking not just what code exists but how pieces relate to each other
- Uses persistent codebase indexing optimized for "passive architectural understanding"
- Semantic dependency graphs trace connections across services, enabling cross-repository context
- New engineers can contribute complex multi-file PRs within six weeks using context-aware suggestions

**Applicability to Drift**:
Drift already has the dependency graph (call graph) and pattern relationships. V2 should leverage these for semantic dependency-aware context generation — when generating context for a package, include not just patterns within that package but patterns from packages it depends on, weighted by dependency distance. The 70.6% vs 54% SWE-bench result validates that context quality is the primary driver of AI agent effectiveness.

**Confidence**: High — validated on enterprise codebases with measurable benchmarks.

---

## R6: NVIDIA — Two-Stage Retrieval with Re-Ranking

**Source**: [NVIDIA Developer Blog — Enhancing RAG Pipelines with Re-Ranking](https://developer.nvidia.com/blog/enhancing-rag-pipelines-with-re-ranking/) (October 2024), [Pinecone — Rerankers and Two-Stage Retrieval](https://www.pinecone.io/learn/series/rag/rerankers/), [Maxim AI — Advanced RAG Techniques](https://www.getmaxim.ai/articles/solving-the-lost-in-the-middle-problem-advanced-rag-techniques-for-long-context-llms/)
**Type**: Tier 1/2 (NVIDIA engineering blog + vector DB documentation)
**Accessed**: February 2026

**Key Findings**:
- Two-stage retrieval: broad recall (bi-encoder, fast) → precise re-ranking (cross-encoder, accurate)
- Cross-encoders analyze query-document pairs jointly, producing more accurate relevance scores than bi-encoders
- Production recommendation: retrieve top-K candidates (K=50-100) with fast search, then re-rank with cross-encoder to top-N (N=5-10)
- Hybrid search (semantic + BM25/keyword) with Reciprocal Rank Fusion outperforms either alone
- Strategic ordering matters: place top evidence at start and end of context (addresses "lost in the middle" problem)
- Keep only the most relevant 3-5 documents in the final prompt

**Applicability to Drift**:
V2 context generation should implement two-stage pattern ranking:
1. Fast stage: Score all patterns by metadata (category match, confidence, occurrences) + optional embedding similarity
2. Re-rank stage: For top-K candidates, compute detailed relevance score considering intent, file proximity, dependency distance, and recency
3. Strategic ordering: Place highest-relevance patterns at the beginning and end of the context output, with lower-relevance in the middle

**Confidence**: High — well-established technique with extensive production validation.

---

## R7: Accurate Token Counting — tiktoken-rs and Alternatives

**Source**: [tiktoken-rs on lib.rs](https://www.lib.rs/crates/tiktoken-rs), [Splintr — 12x faster BPE tokenizer](https://lib.rs/crates/splintr), [bpe crate](https://lib.rs/crates/bpe), [Galileo — tiktoken in production](https://galileo.ai/blog/tiktoken-guide-production-ai), [PropelCode — Token Counting Guide 2025](https://www.propelcode.ai/blog/token-counting-tiktoken-anthropic-gemini-guide-2025)
**Type**: Tier 1/2 (official libraries + production guides)
**Accessed**: February 2026

**Key Findings**:
- `tiktoken-rs` provides exact BPE token counting matching OpenAI's models, available as a Rust crate
- `splintr` achieves ~111 MB/s batch throughput vs ~9 MB/s for tiktoken (12x faster) — pure Rust
- `bpe` crate provides novel algorithms for BPE tokenization that are both correct and significantly faster than existing solutions
- Token counts are model-specific — different models tokenize differently (GPT-4 uses cl100k_base, GPT-4o uses o200k_base, Claude uses its own tokenizer)
- Character-based estimation (length/4) can be off by 20-40% depending on content type — code tokenizes differently than prose
- Token counting is essential for accurate budget management: prevents both truncation (budget overflow) and waste (budget underutilization)

**Applicability to Drift**:
V2 must replace the `length × 0.25` estimation with actual BPE tokenization. Use `tiktoken-rs` or `bpe` crate in Rust for accurate counting. Since Drift serves multiple AI models, implement a model-aware token counter that selects the appropriate tokenizer based on the consuming model. Cache token counts per content hash — patterns and constraints don't change between requests.

**Confidence**: High — well-maintained Rust crates with production usage.

---

## R8: OpenAI Agents SDK — Session Memory Management

**Source**: [OpenAI Cookbook — Short-Term Memory Management with Sessions](https://cookbook.openai.com/examples/agents_sdk/session_memory), [OpenAI Cookbook — State Management with Long-Term Memory](https://cookbook.openai.com/examples/agents_sdk/context_personalization)
**Type**: Tier 1 (model provider official documentation)
**Accessed**: February 2026

**Key Findings**:
- Focused context improves function selection and argument filling, reducing retries and cascading failures
- Smaller, sharper prompts cut tokens per turn and attention load
- Session memory tracks what's been loaded to avoid re-sending (deduplication)
- RunContextWrapper allows structured state objects that persist across runs
- The leap from "responding" to "remembering" defines the new frontier of context engineering
- Context should be shaped by what the model needs at any given moment, not what's available

**Applicability to Drift**:
V2 context generation should implement session-aware context. When an AI agent makes multiple `drift_context` calls in a session, the second call should not re-send patterns already delivered in the first call. This maps to Cortex's session deduplication (already implemented for memory) but needs to extend to the context generation layer. Track what's been sent per session, deliver only deltas.

**Confidence**: High — official guidance from the model provider.

---

## R9: Nx — Project Graph and Affected Analysis

**Source**: [Nx Docs — Run Only Tasks Affected by a PR](https://nx.dev/using-nx/affected), [Nx Docs — Workspace Optimization](https://nx.dev/node-tutorial/4-workspace-optimization), [Deep Dive into Nx Affected](https://gelinjo.hashnode.dev/deep-dive-into-nx-affected)
**Type**: Tier 2 (leading monorepo tool documentation)
**Accessed**: February 2026

**Key Findings**:
- Nx builds a project graph that maps dependencies between all projects in a workspace
- Uses git metadata to determine which files changed, then maps changes to affected projects via the dependency graph
- The "affected" mechanism enables running only tasks for projects impacted by changes
- Project graph is computed from package.json dependencies, TypeScript imports, and explicit configuration
- Supports implicit dependencies (e.g., changes to shared config affect all projects)
- Graph visualization helps developers understand project relationships

**Applicability to Drift**:
Drift's PackageDetector should adopt Nx's project graph concept. Beyond detecting packages, v2 should build a dependency graph between packages. This enables:
1. When generating context for package A, automatically include relevant patterns from packages that A depends on
2. "Affected context" — when patterns change in a shared library, invalidate context for all dependent packages
3. Cross-package context generation for changes that span multiple packages

**Confidence**: High — battle-tested in thousands of enterprise monorepos.

---

## R10: Package Manager Detection — Existing Libraries

**Source**: [package-manager-detector on npm](https://www.npmjs.com/package/package-manager-detector), [package_manager_detector_rs on lib.rs](https://lib.rs/crates/package_manager_detector_rs), [Bun Workspaces](https://bun.sh/docs/install/workspaces), [Deno Workspaces](https://deno.com/blog/v1.45)
**Type**: Tier 2/3 (open source libraries + official documentation)
**Accessed**: February 2026

**Key Findings**:
- `package-manager-detector` (npm) detects package managers based on lock files and the `packageManager` field in package.json
- `package_manager_detector_rs` is a Rust port of the same library
- Bun supports workspaces via `package.json` workspaces field (same as npm), detected by `bun.lockb` or `bun.lock`
- Deno supports workspaces via `deno.json` configuration, detected by `deno.lock` or `deno.json`/`deno.jsonc`
- Lock file detection order commonly used: `pnpm-lock.yaml` → `yarn.lock` → `package-lock.json` → `bun.lockb` → `deno.lock`
- Swift Package Manager uses `Package.swift` for workspace definition

**Applicability to Drift**:
V2 should extend PackageDetector to support Bun and Deno (both now have workspace support). Consider using `package_manager_detector_rs` as a foundation for the Rust implementation, or at minimum align detection logic with its well-tested heuristics. Add Swift Package Manager support for iOS/macOS projects. The detection order should be updated to include these new managers.

**Confidence**: High — official documentation from runtime providers.

---

## R11: Agentic Context Engineering (ACE) — Self-Improving Context

**Source**: [ACE Paper Analysis](https://arxiviq.substack.com/p/agentic-context-engineering-evolving) (February 2026), [Context Engineering for AI Agents in Open-Source Software](https://arxiv.org/html/2510.21413v1)
**Type**: Tier 1 (academic research)
**Accessed**: February 2026

**Key Findings**:
- ACE treats context not as a static prompt but as a "comprehensive, evolving playbook"
- Uses a modular architecture with three roles: Generator, Reflector, Curator
- Context is composed of small, structured "bullets" — reusable strategies, pitfalls, code snippets, formatting schemas
- The system iteratively accumulates, refines, and organizes strategies based on outcomes
- AI agents require contextual information aligned with target architecture, interface specifications, coding guidelines, and project-specific policies
- Repository exploration via knowledge graphs reduces complexity and enables agents to understand entire repositories

**Applicability to Drift**:
Drift's guidance generation (insights, common patterns, warnings) is a primitive version of ACE's "playbook" concept. V2 should evolve this into a structured, versioned context playbook per package that improves over time based on AI agent feedback. When an agent reports that a pattern was helpful or unhelpful, that signal should feed back into context ranking. The knowledge graph approach maps to Drift's call graph + pattern relationships.

**Confidence**: Medium-High — academic research with strong theoretical foundation, limited production validation.

---

## R12: DeepCode — Source Compression and Structured Indexing

**Source**: [DeepCode: Open Agentic Coding](https://huggingface.co/papers/2512.07921)
**Type**: Tier 1 (academic research — peer-reviewed)
**Accessed**: February 2026

**Key Findings**:
- DeepCode optimizes information flow through four stages: source compression, structured indexing, knowledge injection, and error correction
- Achieves state-of-the-art performance on document-to-codebase synthesis, surpassing human experts
- Source compression reduces input volume while preserving critical information
- Structured indexing organizes compressed information for efficient retrieval
- Knowledge injection provides domain-specific context at the right moment
- Error correction validates and fixes generated output against the indexed knowledge

**Applicability to Drift**:
Drift's context generation pipeline maps directly to DeepCode's four stages:
1. Source compression → Token trimming (needs improvement)
2. Structured indexing → Pattern/constraint/call graph storage (moving to SQLite)
3. Knowledge injection → Context generation pipeline (the core of this category)
4. Error correction → Quality gates (category 09)

V2 should adopt the structured indexing approach more aggressively — pre-compute context-ready summaries of patterns and constraints rather than formatting them at query time.

**Confidence**: High — peer-reviewed with reproducible benchmarks.

---

## R13: Inkeep/Anthropic — Fighting Context Rot with Attention Budgets

**Source**: [Inkeep Blog — Fighting Context Rot](https://inkeep.com/blog/fighting-context-rot) (August 2025)
**Type**: Tier 2 (industry expert analysis of Anthropic research)
**Accessed**: February 2026

**Key Findings**:
- AI agents have an "attention budget" — a finite resource that degrades with irrelevant content
- Transformer architecture creates n² pairwise relationships between tokens: 10K tokens = 100M relationships, 100K tokens = 10B relationships
- Two failure modes: too prescriptive (brittle) vs too vague (no signal)
- The "Goldilocks zone": specific enough to guide behavior, flexible enough to adapt
- Just-in-time context retrieval outperforms upfront loading — maintain lightweight references, load on demand
- Claude Code exemplifies this: writes targeted SQL queries, uses `head`/`tail` to sample files, maintains only the most relevant working set
- Progressive disclosure: each interaction yields more specific context

**Applicability to Drift**:
V2 context generation should implement progressive disclosure. Instead of generating a single monolithic context blob, provide a layered context:
- Layer 0: Package overview + top 5 patterns + critical constraints (always included, ~2K tokens)
- Layer 1: Full pattern list + entry points + data accessors (on demand, ~4K tokens)
- Layer 2: Code examples + dependency patterns + detailed guidance (on demand, ~4K tokens)

AI agents can request deeper layers as needed, keeping initial context focused and high-signal.

**Confidence**: High — grounded in transformer architecture fundamentals and production experience.

---

## R14: Manus — Context Compaction for Long-Running Agents

**Source**: [LangChain Analysis of Manus Context Engineering](https://rlancemartin.github.io/2025/10/15/manus/) (October 2025)
**Type**: Tier 2 (industry expert analysis)
**Accessed**: February 2026

**Key Findings**:
- Manus applies compaction to older ("stale") tool results — swaps full result for compact version
- Agents can still fetch the full result if needed, but saves tokens by removing stale results
- The key insight: results the agent has already used to make decisions can be safely compacted
- Compaction preserves the decision trail while reducing token cost

**Applicability to Drift**:
For multi-turn context generation (session-aware), v2 should compact previously delivered context. If an agent received full pattern details in turn 1, turn 2 can reference those patterns by ID with a one-line summary instead of repeating the full details. This is the "session deduplication" concept from Cortex applied to context generation.

**Confidence**: Medium-High — production system but limited public documentation.

---

## R15: Multi-Agent Context Isolation

**Source**: [LangChain Deep Agents Framework](https://blockchain.news/news/langchain-deep-agents-multi-agent-framework-release) (January 2026)
**Type**: Tier 2 (major framework release)
**Accessed**: February 2026

**Key Findings**:
- Deep Agents uses subagents with isolated context windows to prevent context bloat
- When a main agent needs exploratory work (e.g., 20 web searches), it delegates to a subagent
- The main agent receives only the final summary, not intermediate noise
- This prevents the "dumb zone" where agents lose effectiveness as context fills
- Enterprise adoption of multi-agent AI is accelerating

**Applicability to Drift**:
V2 should support context generation for multi-agent workflows. When a main agent delegates to a subagent, the subagent should receive focused context for its specific task (e.g., security review context for a security subagent), not the full context the main agent has. This means context generation needs a "scope" parameter that can narrow context to a specific concern.

**Confidence**: High — addresses a well-documented problem with a practical solution.

---

## R16: Context Engineering for Multi-Agent Code Assistants

**Source**: [arxiv.org — Context Engineering for Multi-Agent LLM Code Assistants](https://arxiv.org/html/2508.08322v1) (August 2025)
**Type**: Tier 1 (academic paper)
**Accessed**: February 2026

**Key Findings**:
- Multi-agent context engineering significantly improves accuracy and reliability of code assistants in real-world repositories
- Higher single-shot success rates when context is properly engineered
- Better adherence to project context than baseline single-agent approaches
- The method works across different LLM providers (tested with Elicit, NotebookLM, ChatGPT, Claude Code)

**Applicability to Drift**:
Drift's context generation is exactly what this paper validates — pre-computed, structured context improves AI code assistant performance. V2 should ensure context output is optimized for multi-agent consumption, where different agents may need different slices of the same context.

**Confidence**: High — peer-reviewed with reproducible methodology.

---

## R17: Repository Knowledge Graphs for Issue Resolution

**Source**: [arxiv.org — Improving Automated Issue Resolution via Comprehensive Repository Exploration](https://arxiv.org/abs/2406.01422)
**Type**: Tier 1 (academic paper)
**Accessed**: February 2026

**Key Findings**:
- Condenses critical repository information into a knowledge graph, reducing complexity
- Uses Monte Carlo tree search strategy for agents to explore and understand entire repositories
- Top-down approach: start with high-level structure, drill into details as needed
- Knowledge graph enables efficient navigation of large codebases

**Applicability to Drift**:
Drift already has the building blocks for a repository knowledge graph: patterns (nodes), call graph (edges), constraints (annotations), and package structure (hierarchy). V2 context generation should expose this as a navigable graph rather than a flat list. The AI agent can start with the package overview, then drill into specific patterns, then follow call graph edges to related code — all within the context budget.

**Confidence**: Medium-High — academic research with promising results but limited production validation.

---

## R18: Agenta — Top Techniques for Context Length Management

**Source**: [Agenta Blog — Top Techniques to Manage Context Lengths in LLMs](https://agenta.ai/blog/top-6-techniques-to-manage-context-length-in-llms) (December 2025)
**Type**: Tier 3 (well-maintained technical blog)
**Accessed**: February 2026

**Key Findings**:
- Six practical techniques: truncation, RAG, memory buffering, compression, map-reduce, and refinement
- Truncation should be intelligent (preserve structure) not naive (cut at character limit)
- Memory buffering: maintain a sliding window of recent context + summarized older context
- Compression: use LLM to compress verbose content while preserving key information
- Map-reduce: process large inputs in chunks, then combine results
- Refinement: iteratively improve context quality through multiple passes

**Applicability to Drift**:
V2 trimming should adopt intelligent truncation — instead of cutting entire sections, compress each section proportionally. The map-reduce approach is applicable to cross-package context: generate context per package, then combine with a merge step that deduplicates and ranks across packages.

**Confidence**: Medium — practical techniques but no rigorous benchmarking.


---

## R19: Particula — Four-Layer Memory Architecture for AI Agents

**Source**: [Particula Blog — How to Make AI Agents Remember Context Across Conversations](https://particula.tech/blog/ai-agent-memory-context-management) (December 2025)
**Type**: Tier 3 (technical blog with practical architecture)
**Accessed**: February 2026

**Key Findings**:
- Four-layer memory architecture:
  1. **Working Memory**: Current conversation in context window
  2. **Session Memory**: Redis/cache for recent history
  3. **Episodic Memory**: Vector database for semantic retrieval of past conversations
  4. **Semantic Memory**: Structured database for facts and preferences
- Each layer has different access patterns, latency characteristics, and retention policies
- Working memory is the most constrained (context window) and must be carefully managed
- Semantic memory provides the stable foundation that working memory draws from

**Applicability to Drift**:
Drift's context generation maps to the "Working Memory" layer — it's what gets loaded into the AI agent's context window. Cortex provides the "Episodic Memory" and "Semantic Memory" layers. V2 should make this layering explicit: context generation draws from Cortex's semantic memory (patterns, constraints) and episodic memory (recent interactions, corrections) to populate the agent's working memory. The session layer maps to Drift's session deduplication.

**Confidence**: Medium — practical architecture but limited scale validation.

---

## R20: Comet — Context Engineering Best Practices for Agentic Systems

**Source**: [Comet Blog — Context Engineering Best Practices](https://www.comet.com/site/blog/context-engineering/) (October 2025)
**Type**: Tier 2 (MLOps platform — industry expert)
**Accessed**: February 2026

**Key Findings**:
- Model outputs depend on the full set of instructions, facts, tools, and policies — the "context"
- Context engineering is designing, governing, and optimizing that surrounding information
- Key principles:
  1. **Minimize noise**: Every irrelevant token degrades performance
  2. **Maximize signal**: Include only information that directly contributes to the task
  3. **Structure matters**: Well-organized context outperforms unstructured dumps
  4. **Freshness matters**: Stale context can be worse than no context
  5. **Governance**: Track what context was used and whether it helped

**Applicability to Drift**:
V2 should implement context governance — track which patterns, constraints, and guidance items were included in each context generation, and correlate with AI agent outcomes (if feedback is available). This creates a feedback loop: patterns that consistently help get boosted, patterns that don't get demoted. The "freshness" principle maps to Drift's scan timestamps — context should indicate how fresh the underlying data is.

**Confidence**: High — well-articulated principles with broad industry consensus.

---

## R21: Phil Schmid — Context Engineering for AI Agents (Practical Guide)

**Source**: [Phil Schmid — Context Engineering for AI Agents](https://www.philschmid.de/context-engineering-part-2) (December 2025)
**Type**: Tier 2 (Hugging Face staff, recognized expert)
**Accessed**: February 2026

**Key Findings**:
- Context engineering is "the discipline of designing a system that provides the right information and tools, in the right format, to give an LLM everything it needs to accomplish a task"
- Key components of effective context:
  1. **System instructions**: Define the agent's role and constraints
  2. **Tools**: Available actions with clear descriptions
  3. **Knowledge**: Retrieved facts and data
  4. **Memory**: Past interactions and learned preferences
  5. **Structure**: How all components are organized within the window
- Format matters: XML tags, markdown headers, and clear section boundaries help models parse context
- Tool descriptions should be concise — verbose tool docs waste context budget

**Applicability to Drift**:
V2's AI context format should be redesigned with these principles. The current 4-section format (systemPrompt, conventions, examples, constraints) is good but should be extended to include:
- Clear section boundaries (XML tags or markdown headers)
- Tool-aware formatting (if the AI agent has Drift MCP tools available, context should reference them)
- Memory integration (Cortex memories relevant to the current context)
- Concise pattern descriptions (current format may be too verbose)

**Confidence**: High — practical guide from a recognized expert with production experience.

---

## R22: OpenTyphoon — 20 Principles for Agentic Workflows

**Source**: [OpenTyphoon — Mastering Agentic Workflows](https://opentyphoon.ai/blog/en/agentic-workflows-principles) (December 2025)
**Type**: Tier 2 (industry expert — AI research lab)
**Accessed**: February 2026

**Key Findings**:
- Context management is central to system reliability and performance in agentic systems
- Key principles relevant to context generation:
  1. **Principle of Least Context**: Include only what's needed for the current step
  2. **Progressive Enrichment**: Start minimal, add context as the task demands
  3. **Context Isolation**: Different agents/steps should have isolated context
  4. **Context Versioning**: Track what context was available at each decision point
  5. **Graceful Degradation**: System should work with partial context, not fail

**Applicability to Drift**:
These principles should be the design axioms for v2 context generation:
- Least Context → Intent-aware filtering (only include patterns relevant to the intent)
- Progressive Enrichment → Layered context (overview → details → examples)
- Context Isolation → Scoped context per agent/task
- Context Versioning → Include metadata about when patterns were last updated
- Graceful Degradation → Generate useful context even when some data sources are unavailable

**Confidence**: High — well-articulated principles with broad applicability.

---

## Research Summary

### Source Distribution

| Tier | Count | Sources |
|------|-------|---------|
| Tier 1 (Authoritative) | 7 | Chroma Research, Anthropic, OpenAI, NVIDIA, arxiv papers (×3) |
| Tier 2 (Industry Expert) | 12 | LangChain, Cursor, Augment Code, Nx, Pinecone, Comet, Phil Schmid, OpenTyphoon, Inkeep, Manus |
| Tier 3 (Community) | 3 | Agenta, Particula, package-manager-detector |
| **Total** | **22** | |

### Key Themes

1. **Context rot is real and measurable** (R1, R13) — shorter, focused context consistently outperforms long context. This validates Drift's entire approach.

2. **Semantic ranking is essential** (R4, R5, R6) — sorting by occurrences is insufficient. Embedding-based similarity + re-ranking produces significantly better results.

3. **Accurate token counting is non-negotiable** (R7) — character-based estimation is 20-40% off. Rust BPE tokenizers are fast and accurate.

4. **Intent-aware context is the state of the art** (R3, R8, R11, R22) — different tasks need different context configurations. One-size-fits-all is wasteful.

5. **Progressive/layered context outperforms monolithic** (R2, R13, R14, R18, R22) — start minimal, enrich on demand.

6. **Session awareness prevents redundancy** (R8, R14, R15) — track what's been sent, deliver only deltas.

7. **Dependency graphs enable smarter context** (R5, R9, R17) — understanding package relationships improves context relevance.

8. **Context engineering is a discipline, not a feature** (R3, R20, R21) — it requires governance, feedback loops, and continuous optimization.

### Research Gaps

- No authoritative source found for optimal context section ordering for code-specific tasks
- Limited research on context generation for polyglot monorepos specifically
- No benchmarks comparing different context trimming strategies for code analysis tools
- Limited research on context generation performance at enterprise scale (500K+ files)
