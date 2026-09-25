use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Deserializer};

use crate::protocol::Json;

#[derive(Clone)]
pub(super) struct Correction {
    revision: u64,
    token: HeaderValue,
}

impl Correction {
    pub fn parse(headers: &HeaderMap, body: &[u8]) -> Result<Option<Self>, ()> {
        #[derive(Deserialize)]
        struct Envelope {
            #[serde(default, deserialize_with = "present")]
            error: Option<Json>,
        }
        #[derive(Deserialize)]
        struct Metadata {
            #[serde(default, deserialize_with = "present")]
            code: Option<Json>,
            #[serde(default, deserialize_with = "present")]
            policy_revision: Option<Json>,
            #[serde(default, deserialize_with = "present")]
            shard_token: Option<Json>,
        }
        fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Json>, D::Error> {
            Json::deserialize(deserializer).map(Some)
        }

        let envelope: Envelope = serde_json::from_slice(body).map_err(|_| ())?;
        let Some(error) = envelope.error else {
            return Ok(None);
        };
        let metadata: Metadata = serde_json::from_str(error.get()).map_err(|_| ())?;
        let code = metadata
            .code
            .as_deref()
            .and_then(|code| serde_json::from_str::<String>(code.get()).ok());
        if code.as_deref() != Some("wrong_cluster") {
            return Ok(None);
        }
        let mut values = headers.get_all("x-tunnel-shard-token").iter();
        let mut token = values.next().ok_or(())?.clone();
        let bytes = token.as_bytes();
        if values.next().is_some()
            || !(1..=4096).contains(&bytes.len())
            || !bytes
                .iter()
                .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b',')
        {
            return Err(());
        }
        if let Some(copy) = metadata.shard_token {
            let copy: String = serde_json::from_str(copy.get()).map_err(|_| ())?;
            if copy.as_bytes() != bytes {
                return Err(());
            }
        }
        let revision = metadata.policy_revision.ok_or(())?;
        let raw = revision.get();
        if raw.len() > 16 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        let revision = raw.parse::<u64>().map_err(|_| ())?;
        if revision > 9_007_199_254_740_991 {
            return Err(());
        }
        token.set_sensitive(true);
        Ok(Some(Self { revision, token }))
    }
}

#[derive(Default)]
pub(super) struct State {
    generation: u64,
    token: Option<HeaderValue>,
    accepted: Option<Correction>,
    failures: u8,
    corrections: u8,
}

pub(super) struct Attempt {
    generation: u64,
    pub token: Option<HeaderValue>,
}

impl State {
    pub fn snapshot(&self) -> Attempt {
        Attempt {
            generation: self.generation,
            token: self.token.clone(),
        }
    }

    pub fn complete(
        &mut self,
        attempt: &Attempt,
        correction: Option<Correction>,
        available: bool,
        failed_destination: bool,
    ) {
        if self.generation != attempt.generation
            || (correction.is_none() && !available && !failed_destination)
        {
            return;
        }
        self.generation += 1;
        if available {
            self.failures = 0;
            self.corrections = 0;
        } else if let Some(correction) = correction {
            self.failures = 0;
            self.corrections += 1;
            match &self.accepted {
                Some(accepted) if correction.revision < accepted.revision => {}
                Some(accepted) if correction.revision == accepted.revision => {
                    self.token = (correction.token == accepted.token).then_some(correction.token);
                }
                _ => {
                    self.token = Some(correction.token.clone());
                    self.accepted = Some(correction);
                }
            }
            if self.corrections == 3 {
                self.token = None;
                self.corrections = 0;
            }
        } else if failed_destination && attempt.token.is_some() {
            self.failures += 1;
            if self.failures == 3 {
                self.token = None;
                self.failures = 0;
            }
        }
    }
}
