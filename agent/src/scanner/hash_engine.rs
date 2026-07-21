use sha2::{Sha256, Digest};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use super::verdict::Verdict;

// Simple bounded LRU cache to avoid re-sending known files rapidly.
pub struct LocalCache {
    cache: HashMap<String, Verdict>,
    order: VecDeque<String>,
    capacity: usize,
}

impl LocalCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }
    
    pub fn get(&mut self, hash: &str) -> Option<Verdict> {
        if let Some(value) = self.cache.get(hash).cloned() {
            self.touch(hash);
            return Some(value);
        }
        None
    }
    
    pub fn insert(&mut self, hash: String, verdict: Verdict) {
        if self.cache.contains_key(&hash) {
            self.cache.insert(hash.clone(), verdict);
            self.touch(&hash);
            return;
        }

        if self.cache.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.cache.remove(&oldest);
            }
        }

        self.order.push_back(hash.clone());
        self.cache.insert(hash, verdict);
    }

    fn touch(&mut self, hash: &str) {
        if let Some(idx) = self.order.iter().position(|h| h == hash) {
            self.order.remove(idx);
        }
        self.order.push_back(hash.to_string());
    }
}

pub fn compute_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(hex::encode(hasher.finalize()))
}
