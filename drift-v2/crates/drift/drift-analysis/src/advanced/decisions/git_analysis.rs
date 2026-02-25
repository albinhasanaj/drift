//! git2 crate integration for commit history analysis.
//!
//! High-performance pipeline for extracting decisions from git history.

use std::path::Path;

use super::types::{CommitSummary, Decision};
use super::categorizer::DecisionCategorizer;

/// Git history analyzer using git2.
pub struct GitAnalyzer {
    categorizer: DecisionCategorizer,
    max_commits: usize,
}

impl GitAnalyzer {
    pub fn new() -> Self {
        Self {
            categorizer: DecisionCategorizer::new(),
            max_commits: 1000,
        }
    }

    pub fn with_max_commits(mut self, max: usize) -> Self {
        self.max_commits = max;
        self
    }

    /// Analyze git history at the given repo path and extract decisions.
    pub fn analyze(&self, repo_path: &Path) -> Result<Vec<Decision>, String> {
        let repo = git2::Repository::open(repo_path)
            .map_err(|e| format!("Failed to open repository: {}", e))?;

        let commits = self.walk_commits(&repo)?;
        let mut decisions = Vec::new();

        for commit in &commits {
            if let Some(decision) = self.categorizer.categorize_commit(commit) {
                decisions.push(decision);
            }
        }

        Ok(decisions)
    }

    /// Walk commits from HEAD, collecting summaries.
    fn walk_commits(&self, repo: &git2::Repository) -> Result<Vec<CommitSummary>, String> {
        let mut revwalk = repo.revwalk()
            .map_err(|e| format!("Failed to create revwalk: {}", e))?;

        revwalk.push_head()
            .map_err(|e| format!("Failed to push HEAD: {}", e))?;

        revwalk.set_sorting(git2::Sort::TIME)
            .map_err(|e| format!("Failed to set sorting: {}", e))?;

        let mut summaries = Vec::new();

        for (i, oid_result) in revwalk.enumerate() {
            if i >= self.max_commits {
                break;
            }

            let oid = match oid_result {
                Ok(oid) => oid,
                Err(_) => continue,
            };

            let commit = match repo.find_commit(oid) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let message = commit.message().unwrap_or("").to_string();
            let author = commit.author().name().unwrap_or("unknown").to_string();
            let timestamp = commit.time().seconds();
            let sha = oid.to_string();

            // Get diff stats
            let (files_changed, insertions, deletions) = self.diff_stats(repo, &commit);

            summaries.push(CommitSummary {
                sha,
                message,
                author,
                timestamp,
                files_changed,
                insertions,
                deletions,
            });
        }

        Ok(summaries)
    }

    /// Get diff stats for a commit.
    fn diff_stats(
        &self,
        repo: &git2::Repository,
        commit: &git2::Commit,
    ) -> (Vec<String>, u32, u32) {
        let tree = match commit.tree() {
            Ok(t) => t,
            Err(_) => return (vec![], 0, 0),
        };

        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let diff = match repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&tree),
            None,
        ) {
            Ok(d) => d,
            Err(_) => return (vec![], 0, 0),
        };

        let mut files = Vec::new();
        let _ = diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    files.push(path.to_string_lossy().to_string());
                }
                true
            },
            None,
            None,
            None,
        );

        let (insertions, deletions) = match diff.stats() {
            Ok(stats) => (stats.insertions() as u32, stats.deletions() as u32),
            Err(_) => (0, 0),
        };

        (files, insertions, deletions)
    }

    /// Analyze commits from pre-collected summaries (for testing without git2).
    pub fn analyze_summaries(&self, summaries: &[CommitSummary]) -> Vec<Decision> {
        let mut decisions = Vec::new();
        for commit in summaries {
            if let Some(decision) = self.categorizer.categorize_commit(commit) {
                decisions.push(decision);
            }
        }
        decisions
    }
}

impl Default for GitAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_summaries_extracts_decisions() {
        let analyzer = GitAnalyzer::new();
        let summaries = vec![
            CommitSummary {
                sha: "abc123".to_string(),
                message: "feat: migrate from Express to Fastify for better performance".to_string(),
                author: "dev".to_string(),
                timestamp: 1700000000,
                files_changed: vec!["src/server.ts".to_string()],
                insertions: 200,
                deletions: 150,
            },
            CommitSummary {
                sha: "def456".to_string(),
                message: "chore: update README".to_string(),
                author: "dev".to_string(),
                timestamp: 1700001000,
                files_changed: vec!["README.md".to_string()],
                insertions: 5,
                deletions: 2,
            },
            CommitSummary {
                sha: "ghi789".to_string(),
                message: "security: add rate limiting to API endpoints".to_string(),
                author: "dev".to_string(),
                timestamp: 1700002000,
                files_changed: vec!["src/middleware/rate-limit.ts".to_string()],
                insertions: 80,
                deletions: 5,
            },
        ];

        let decisions = analyzer.analyze_summaries(&summaries);
        assert!(!decisions.is_empty(), "Should extract at least one decision");
    }
}
