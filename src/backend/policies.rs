//! Hand-written parts of the policy acceptance surface that the generated
//! catalog cannot express: the CSV export of a policy's acceptances.

use crate::http::HttpMethod;

use super::catalog::Policies;
use super::error::BackendError;
use super::pagination::Query;
use super::resources::seg;

impl Policies<'_> {
    /// `GET /v1/policies/{id}/acceptances?format=csv` — every acceptance of the
    /// policy as CSV text (up to 100,000 rows). `query` may carry `version` (an id
    /// or label) and `status` (`accepted`, `withdrawn` or `all`); `format` is set
    /// for you.
    pub async fn export_acceptances_csv(&self, id: &str, query: &Query) -> Result<String, BackendError> {
        let path = format!("/v1/policies/{}/acceptances", seg(id));
        let mut pairs: Vec<(&str, String)> = query.as_pairs().into_iter().filter(|(k, _)| *k != "format").collect();
        pairs.push(("format", "csv".to_string()));
        let bytes = self.client.request_bytes(HttpMethod::Get, &path, &pairs, None).await?;
        String::from_utf8(bytes).map_err(|e| BackendError::Malformed(e.to_string()))
    }
}
