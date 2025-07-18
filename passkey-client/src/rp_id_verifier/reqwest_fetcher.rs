use reqwest::{Client, header::ACCEPT};

use crate::{Fetcher, WebauthnError};

use super::RelatedOriginResponse;

impl Fetcher for Client {
    async fn fetch_related_origins(
        &self,
        url: url::Url,
    ) -> Result<RelatedOriginResponse, WebauthnError> {
        let response = self
            .get(url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| WebauthnError::FetcherError)?;

        if !response.status().is_success() {
            return Err(WebauthnError::FetcherError);
        }

        let final_url = response.url().clone();

        let body = response
            .bytes()
            .await
            .map_err(|_| WebauthnError::FetcherError)?;

        Ok(RelatedOriginResponse {
            payload: serde_json::from_slice(&body).map_err(|_| WebauthnError::SyntaxError)?,
            final_url,
        })
    }
}
