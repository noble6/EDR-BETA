#[derive(Clone, Debug)]
pub struct Verdict {
    pub classification: String,
    pub risk_score: f64,
}
