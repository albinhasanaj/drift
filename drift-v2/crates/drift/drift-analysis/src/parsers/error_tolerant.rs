//! Error-tolerant parsing: extract partial results from trees with ERROR nodes.

use tree_sitter::Node;

use super::types::Range;

/// Count ERROR nodes in a tree-sitter tree.
pub fn count_errors(root: Node) -> (u32, Vec<Range>) {
    let mut count = 0u32;
    let mut ranges = Vec::new();
    collect_errors(root, &mut count, &mut ranges);
    (count, ranges)
}

fn collect_errors(node: Node, count: &mut u32, ranges: &mut Vec<Range>) {
    if node.is_error() || node.is_missing() {
        *count += 1;
        ranges.push(Range::from_ts_node(&node));
    }
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            collect_errors(child, count, ranges);
        }
    }
}

/// Check if a node is inside an ERROR subtree.
pub fn is_in_error(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.is_error() {
            return true;
        }
        current = parent.parent();
    }
    false
}
