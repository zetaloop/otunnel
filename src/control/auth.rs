use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, Method};
use serde::Deserialize;
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{Instant, timeout},
};

use crate::{
    config::ControlPlane,
    net::{Http, Options},
};

pub(super) enum Auth {
    Key(String),
    Aws(Arc<Identity>),
}
impl Auth {
    pub fn new(config: &ControlPlane) -> Result<Self> {
        config.validate_auth()?;
        if !config.workload_identity() {
            return Ok(Self::Key(crate::config::resolve(&config.api_key)?));
        }
        let url = "https://auth.openai.com/oauth/token".parse()?;
        Ok(Self::Aws(Arc::new(Identity {
            provider: config.aws_identity_provider_id.clone(),
            account: config.aws_service_account_id.clone(),
            client: Http::new(url, Options::default())?,
            state: Mutex::new(State::default()),
        })))
    }
    pub async fn token(&self) -> Result<String> {
        match self {
            Self::Key(key) => Ok(key.clone()),
            Self::Aws(identity) => identity.token().await,
        }
    }
    pub fn dynamic(&self) -> bool {
        matches!(self, Self::Aws(_))
    }
}

pub(super) struct Identity {
    provider: String,
    account: String,
    client: Http,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    token: Option<Token>,
    refresh: Option<JoinHandle<Result<Token>>>,
}
#[derive(Clone)]
struct Token {
    value: String,
    expires: Instant,
}

impl Identity {
    async fn token(self: &Arc<Self>) -> Result<String> {
        let mut state = self.state.lock().await;
        let current = state
            .token
            .as_ref()
            .filter(|token| token.expires > Instant::now())
            .cloned();
        if let Some(token) = &current
            && !state.refresh.as_ref().is_some_and(JoinHandle::is_finished)
        {
            if token.expires <= Instant::now() + Duration::from_secs(60) && state.refresh.is_none()
            {
                state.refresh = Some(self.refresh());
            }
            return Ok(token.value.clone());
        }
        if state.refresh.is_none() {
            state.refresh = Some(self.refresh());
        }
        // The handle stays in state if the waiting request is cancelled.
        let result = state
            .refresh
            .as_mut()
            .expect("token refresh")
            .await
            .map_err(|_| anyhow::anyhow!("AWS workload identity refresh stopped"))
            .and_then(|result| result);
        state.refresh = None;
        match result {
            Ok(token) => {
                let value = token.value.clone();
                state.token = Some(token);
                Ok(value)
            }
            Err(_)
                if current
                    .as_ref()
                    .is_some_and(|token| token.expires > Instant::now()) =>
            {
                Ok(current.expect("unexpired token").value)
            }
            Err(error) => Err(error),
        }
    }
    fn refresh(self: &Arc<Self>) -> JoinHandle<Result<Token>> {
        let identity = self.clone();
        tokio::spawn(async move {
            timeout(Duration::from_secs(30), identity.exchange())
                .await
                .context("AWS workload identity authentication timed out")?
        })
    }
    async fn exchange(&self) -> Result<Token> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let assertion = aws_sdk_sts::Client::new(&config)
            .get_web_identity_token()
            .audience("https://api.openai.com/v1")
            .signing_algorithm("RS256")
            .duration_seconds(300)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("AWS workload identity STS assertion failed"))?;
        let subject = assertion
            .web_identity_token()
            .filter(|token| !token.is_empty())
            .context("AWS workload identity STS returned an empty assertion")?;
        let body = serde_json::to_vec(&serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "identity_provider_id": self.provider,
            "service_account_id": self.account,
        }))?;
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse()?);
        let response = self
            .client
            .send(
                Method::POST,
                &"https://auth.openai.com/oauth/token".parse()?,
                headers,
                Bytes::from(body),
            )
            .await
            .map_err(|_| anyhow::anyhow!("AWS workload identity token exchange failed"))?;
        anyhow::ensure!(
            response.status.as_u16() == 200,
            "AWS workload identity token exchange failed (HTTP {})",
            response.status.as_u16()
        );
        let body = response
            .limited(1024 * 1024)
            .await
            .map_err(|_| anyhow::anyhow!("read AWS workload identity token response"))?;
        anyhow::ensure!(
            body.len() <= 1024 * 1024,
            "AWS workload identity token response exceeds its size limit"
        );
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            expires_in: Option<i64>,
        }
        let response: Response = serde_json::from_slice(&body)
            .map_err(|_| anyhow::anyhow!("invalid AWS workload identity token response"))?;
        let token = response.access_token.trim_end_matches('=');
        anyhow::ensure!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._~+/-".contains(&byte)),
            "workload identity returned a malformed bearer token"
        );
        let lifetime = Duration::from_secs(response.expires_in.unwrap_or(3600).max(0) as u64);
        let expires = Instant::now()
            .checked_add(lifetime)
            .context("invalid workload identity token lifetime")?;
        Ok(Token {
            value: response.access_token,
            expires,
        })
    }
}
