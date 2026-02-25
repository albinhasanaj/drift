//! ONNX Runtime embedding provider.
//!
//! Loads ONNX models via the `ort` crate (v2). Default: Jina Code v2 (1024-dim),
//! quantized INT8, batch inference with padding.

use std::path::Path;
use std::sync::Mutex;

use cortex_core::errors::{CortexResult, EmbeddingError};
use cortex_core::traits::IEmbeddingProvider;
use ort::session::Session;
use ort::value::Tensor;
use tracing::debug;

/// ONNX-based embedding provider using the `ort` crate.
///
/// Wraps an ort `Session` and handles tokenization, inference, and
/// mean-pooling of the output tensor.
pub struct OnnxProvider {
    /// Session requires `&mut self` for `run`, so we wrap in Mutex
    /// to satisfy the `&self` trait requirement.
    session: Mutex<Session>,
    dimensions: usize,
    model_name: String,
}

// Safety: Session is Send but not Sync by default. The Mutex provides Sync.
unsafe impl Sync for OnnxProvider {}

impl OnnxProvider {
    /// Load an ONNX model from the given path.
    ///
    /// # Errors
    /// Returns `EmbeddingError::ModelLoadFailed` if the model cannot be loaded.
    pub fn load(model_path: &str, dimensions: usize) -> CortexResult<Self> {
        let path = Path::new(model_path);
        if !path.exists() {
            return Err(EmbeddingError::ModelLoadFailed {
                path: model_path.to_string(),
                reason: "model file not found".to_string(),
            }
            .into());
        }

        let session = Session::builder()
            .map_err(|e| EmbeddingError::ModelLoadFailed {
                path: model_path.to_string(),
                reason: e.to_string(),
            })?
            .with_intra_threads(2)
            .map_err(|e| EmbeddingError::ModelLoadFailed {
                path: model_path.to_string(),
                reason: e.to_string(),
            })?
            .commit_from_file(model_path)
            .map_err(|e| EmbeddingError::ModelLoadFailed {
                path: model_path.to_string(),
                reason: e.to_string(),
            })?;

        let model_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("onnx-model")
            .to_string();

        debug!(model = %model_name, dims = dimensions, "ONNX model loaded");

        Ok(Self {
            session: Mutex::new(session),
            dimensions,
            model_name,
        })
    }

    /// Run inference on a single text, returning the embedding vector.
    fn infer(&self, text: &str) -> CortexResult<Vec<f32>> {
        let token_ids = Self::simple_tokenize(text);
        let seq_len = token_ids.len();

        let input_ids: Vec<i64> = token_ids.iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = vec![1i64; seq_len];

        let ids_tensor =
            Tensor::from_array((vec![1i64, seq_len as i64], input_ids)).map_err(|e| {
                EmbeddingError::InferenceFailed {
                    reason: format!("tensor creation error: {e}"),
                }
            })?;

        let mask_tensor = Tensor::from_array((vec![1i64, seq_len as i64], attention_mask))
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("tensor creation error: {e}"),
            })?;

        let mut session = self
            .session
            .lock()
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("session lock poisoned: {e}"),
            })?;

        let outputs = session
            .run(ort::inputs![ids_tensor, mask_tensor])
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: e.to_string(),
            })?;

        // Extract the first output tensor.
        let (_name, output) =
            outputs
                .iter()
                .next()
                .ok_or_else(|| EmbeddingError::InferenceFailed {
                    reason: "no output tensor".to_string(),
                })?;

        let (shape, data) =
            output
                .try_extract_tensor::<f32>()
                .map_err(|e| EmbeddingError::InferenceFailed {
                    reason: format!("tensor extraction failed: {e}"),
                })?;

        // Mean pool across the sequence dimension.
        let embedding = if shape.len() == 3 {
            // [batch=1, seq, dims]
            let seq = shape[1] as usize;
            let dims = shape[2] as usize;
            let mut pooled = vec![0.0f32; dims];
            for s in 0..seq {
                for d in 0..dims {
                    pooled[d] += data[s * dims + d];
                }
            }
            for v in &mut pooled {
                *v /= seq as f32;
            }
            pooled
        } else if shape.len() == 2 {
            // [batch=1, dims] — already pooled.
            let dims = shape[1] as usize;
            data[..dims].to_vec()
        } else {
            return Err(EmbeddingError::InferenceFailed {
                reason: format!("unexpected output shape: {shape:?}"),
            }
            .into());
        };

        // L2 normalize.
        let mut result = embedding;
        let norm: f32 = result.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > f32::EPSILON {
            for v in &mut result {
                *v /= norm;
            }
        }

        // Resize to expected dimensions.
        result.resize(self.dimensions, 0.0);
        Ok(result)
    }

    /// Simple tokenizer: split on whitespace/punctuation, hash to vocab range.
    fn simple_tokenize(text: &str) -> Vec<u32> {
        if text.is_empty() {
            return vec![101, 102]; // [CLS] [SEP]
        }
        let mut ids = vec![101u32]; // [CLS]
        for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if word.is_empty() {
                continue;
            }
            let mut h: u32 = 0x811c9dc5;
            for b in word.to_lowercase().as_bytes() {
                h ^= *b as u32;
                h = h.wrapping_mul(0x01000193);
            }
            ids.push(1 + (h % 29999));
        }
        ids.push(102); // [SEP]
        ids
    }
}

impl IEmbeddingProvider for OnnxProvider {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        self.infer(text)
    }

    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        // D-01: Batched inference with tensor padding.
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        // For very small batches, sequential is fine (avoids padding overhead).
        if texts.len() == 1 {
            return Ok(vec![self.infer(&texts[0])?]);
        }

        // Tokenize all texts and find max sequence length.
        let tokenized: Vec<Vec<u32>> = texts.iter().map(|t| Self::simple_tokenize(t)).collect();
        let max_len = tokenized.iter().map(|t| t.len()).max().unwrap_or(2);
        let batch_size = texts.len();

        // Build padded input_ids and attention_mask tensors.
        let mut flat_ids: Vec<i64> = Vec::with_capacity(batch_size * max_len);
        let mut flat_mask: Vec<i64> = Vec::with_capacity(batch_size * max_len);

        for tokens in &tokenized {
            for &id in tokens {
                flat_ids.push(id as i64);
                flat_mask.push(1);
            }
            // Pad remaining positions with 0.
            for _ in tokens.len()..max_len {
                flat_ids.push(0);
                flat_mask.push(0);
            }
        }

        let shape = vec![batch_size as i64, max_len as i64];

        let ids_tensor = Tensor::from_array((shape.clone(), flat_ids)).map_err(|e| {
            EmbeddingError::InferenceFailed {
                reason: format!("batch tensor creation error: {e}"),
            }
        })?;

        let mask_tensor =
            Tensor::from_array((shape, flat_mask)).map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("batch mask tensor creation error: {e}"),
            })?;

        let mut session = self
            .session
            .lock()
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("session lock poisoned: {e}"),
            })?;

        let outputs = session
            .run(ort::inputs![ids_tensor, mask_tensor])
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: e.to_string(),
            })?;

        let (_name, output) =
            outputs
                .iter()
                .next()
                .ok_or_else(|| EmbeddingError::InferenceFailed {
                    reason: "no output tensor".to_string(),
                })?;

        let (out_shape, data) =
            output
                .try_extract_tensor::<f32>()
                .map_err(|e| EmbeddingError::InferenceFailed {
                    reason: format!("batch tensor extraction failed: {e}"),
                })?;

        // Extract per-sample embeddings from the batched output.
        let mut results = Vec::with_capacity(batch_size);

        if out_shape.len() == 3 {
            // [batch, seq, dims]
            let seq_out = out_shape[1] as usize;
            let dims = out_shape[2] as usize;

            for (b, tokens) in tokenized.iter().enumerate().take(batch_size) {
                let actual_len = tokens.len();
                let offset = b * seq_out * dims;
                let mut pooled = vec![0.0f32; dims];

                // Mean pool only over non-padded tokens.
                for s in 0..actual_len.min(seq_out) {
                    for d in 0..dims {
                        pooled[d] += data[offset + s * dims + d];
                    }
                }
                let count = actual_len.min(seq_out).max(1) as f32;
                for v in &mut pooled {
                    *v /= count;
                }

                // L2 normalize.
                let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
                if norm > f32::EPSILON {
                    for v in &mut pooled {
                        *v /= norm;
                    }
                }

                pooled.resize(self.dimensions, 0.0);
                results.push(pooled);
            }
        } else if out_shape.len() == 2 {
            // [batch, dims] — already pooled.
            let dims = out_shape[1] as usize;
            for b in 0..batch_size {
                let offset = b * dims;
                let mut embedding = data[offset..offset + dims].to_vec();

                // L2 normalize.
                let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
                if norm > f32::EPSILON {
                    for v in &mut embedding {
                        *v /= norm;
                    }
                }

                embedding.resize(self.dimensions, 0.0);
                results.push(embedding);
            }
        } else {
            // Unexpected output shape — report error rather than silent fallback.
            return Err(EmbeddingError::InferenceFailed {
                reason: format!("unexpected batch output shape: {out_shape:?}"),
            }
            .into());
        }

        Ok(results)
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn name(&self) -> &str {
        &self.model_name
    }

    fn is_available(&self) -> bool {
        true
    }
}
