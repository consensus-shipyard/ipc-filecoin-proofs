// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use cid::Cid;
use fvm_ipld_encoding::{to_vec, RawBytes, DAG_CBOR};
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use multihash_codetable::MultihashDigest;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::str::FromStr;
use tokio::time::Duration;
use url::Url;

use crate::types::{
    CIDMap, ChainGetBlockMessagesResponse, ChainGetMessageResponse, ChainGetParentReceiptsResponse,
    ChainHeadResponse, ChainReadObjResponse, EthGetMessageCidByTransactionHashResponse, EthLog,
    EthTransactionReceipt, GetTipSetByHeightResponse, GetTipSetResponse, Message,
    MpoolGetByCidResponse, NetworkVersion, ReadStateResponse, StateSearchMsgResponse,
};

/// Request timeout of the RPC client
const DEFAULT_REQ_TIMEOUT: Duration = Duration::from_secs(250);

/// A simple Lotus RPC client
#[derive(Clone)]
pub struct LotusClient {
    http_client: reqwest::Client,
    url: Url,
    bearer_token: Option<String>,
}

impl LotusClient {
    /// Creates a new Lotus client that sends requests to `url`
    pub fn new(url: Url, bearer_token: Option<&str>) -> Self {
        Self {
            http_client: reqwest::Client::default(),
            url,
            bearer_token: bearer_token.map(String::from),
        }
    }

    /// Returns the current head of the chain
    pub async fn chain_head(&self) -> Result<ChainHeadResponse> {
        let r = self
            .request::<ChainHeadResponse>("Filecoin.ChainHead", json!([]))
            .await?;
        tracing::debug!("received chain_head response: {r:?}");
        Ok(r)
    }

    /// Returns the current epoch
    pub async fn current_epoch(&self) -> Result<ChainEpoch> {
        Ok(self.chain_head().await?.height as ChainEpoch)
    }

    /// Get tipset by height
    pub async fn get_tipset_by_height(
        &self,
        epoch: ChainEpoch,
        tip_set: Option<Vec<Cid>>, // None -> null tipset; Some(vec) -> explicit tipset key
    ) -> Result<GetTipSetByHeightResponse> {
        let params = match tip_set {
            Some(cids) => json!([
                epoch,
                cids.into_iter().map(CIDMap::from).collect::<Vec<_>>()
            ]),
            None => json!([epoch, serde_json::Value::Null]),
        };
        let r = self
            .request::<GetTipSetByHeightResponse>("Filecoin.ChainGetTipSetByHeight", params)
            .await?;
        tracing::debug!("received get_tipset_by_height response: {r:?}");
        Ok(r)
    }

    /// Get tipset by CIDs
    pub async fn get_tipset(&self, cids: Vec<Cid>) -> Result<GetTipSetResponse> {
        let cid_maps: Vec<CIDMap> = cids.into_iter().map(CIDMap::from).collect();
        let r = self
            .request::<GetTipSetResponse>("Filecoin.ChainGetTipSet", json!([cid_maps]))
            .await?;
        tracing::debug!("received get_tipset response: {r:?}");
        Ok(r)
    }

    /// Get message CID by Ethereum transaction hash
    pub async fn eth_get_message_cid_by_transaction_hash(
        &self,
        tx_hash: &str,
    ) -> Result<EthGetMessageCidByTransactionHashResponse> {
        let r = self
            .request::<EthGetMessageCidByTransactionHashResponse>(
                "Filecoin.EthGetMessageCidByTransactionHash",
                json!([tx_hash]),
            )
            .await?;
        tracing::debug!("received eth_get_message_cid_by_transaction_hash response: {r:?}");
        Ok(r)
    }

    /// Get the canonical unsigned message CID from any input CID
    pub async fn canonicalize_unsigned_cid(&self, candidate_cid: Cid) -> Result<Cid> {
        // First try chain (works for included messages)
        if let Ok(message_response) = self.chain_get_message(candidate_cid).await {
            let canonical_cid = Cid::try_from(&message_response.cid)
                .context("Failed to convert CID from response")?;
            return Ok(canonical_cid);
        }

        // If that fails, try mempool (works for pending signed messages)
        if let Ok(mpool) = self.mpool_get_by_cid(candidate_cid).await {
            let computed = self
                .cid_of_message(&mpool.message)
                .context("Failed to compute CID from mempool message")?;
            tracing::info!("Derived unsigned CID from mempool: {}", computed);
            return Ok(computed);
        }

        anyhow::bail!(
            "ChainGetMessage failed and message not found in mempool; please provide the unsigned message CID"
        )
    }

    /// Get message by CID (returns the message and its canonical CID)
    pub async fn chain_get_message(&self, cid: Cid) -> Result<ChainGetMessageResponse> {
        // Manual JSON-RPC call to avoid parsing issues
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": "Filecoin.ChainGetMessage",
            "params": [CIDMap::from(cid)],
            "id": 1
        });

        let mut builder = self.http_client.post(self.url.as_str()).json(&request_body);
        builder = builder.timeout(DEFAULT_REQ_TIMEOUT);

        if self.bearer_token.is_some() {
            builder = builder.bearer_auth(self.bearer_token.as_ref().unwrap());
        }

        let response = builder.send().await?;
        let response_body = response.text().await?;
        tracing::debug!("ChainGetMessage raw response: {}", response_body);

        // Parse the JSON-RPC response manually
        let value: serde_json::Value = serde_json::from_str(&response_body)?;

        if let Some(result) = value.get("result") {
            let msg: ChainGetMessageResponse = serde_json::from_value(result.clone())?;
            Ok(msg)
        } else if let Some(error) = value.get("error") {
            let error_msg = error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("ChainGetMessage RPC error: {}", error_msg);
        } else {
            anyhow::bail!("ChainGetMessage response has neither result nor error");
        }
    }

    /// Get signed message from mempool by CID
    pub async fn mpool_get_by_cid(&self, cid: Cid) -> Result<MpoolGetByCidResponse> {
        self.request("Filecoin.MpoolGetByCid", json!([CIDMap::from(cid)]))
            .await
    }

    /// Compute CID of a message by DAG-CBOR encoding and hashing
    pub fn cid_of_message(&self, message: &Message) -> Result<Cid> {
        // Convert string addresses to proper Address types
        let from_addr = Address::from_str(&message.from).context("Failed to parse from address")?;
        let to_addr = Address::from_str(&message.to).context("Failed to parse to address")?;

        // Parse token amounts
        let value = fvm_shared::econ::TokenAmount::from_atto(
            message
                .value
                .parse::<u128>()
                .context("Failed to parse value")?,
        );
        let gas_fee_cap = fvm_shared::econ::TokenAmount::from_atto(
            message
                .gas_fee_cap
                .parse::<u128>()
                .context("Failed to parse gas_fee_cap")?,
        );
        let gas_premium = fvm_shared::econ::TokenAmount::from_atto(
            message
                .gas_premium
                .parse::<u128>()
                .context("Failed to parse gas_premium")?,
        );

        // Create the FVM message structure
        let fvm_message = fvm_shared::message::Message {
            version: message.version,
            from: from_addr,
            to: to_addr,
            sequence: message.nonce,
            value,
            method_num: message.method,
            params: RawBytes::from(message.params.clone()),
            gas_limit: message.gas_limit,
            gas_fee_cap,
            gas_premium,
        };

        // Encode to DAG-CBOR using FVM's serialization
        let encoded = to_vec(&fvm_message).context("Failed to encode message to DAG-CBOR")?;

        // Compute CID using Blake2b256
        let mh = multihash_codetable::Code::Blake2b256.digest(&encoded);
        Ok(Cid::new_v1(DAG_CBOR, mh))
    }

    /// Search for a message by CID with limited lookback
    #[allow(dead_code)]
    async fn state_search_msg_limited(
        &self,
        cid: Cid,
        lookback: u64,
    ) -> Result<StateSearchMsgResponse> {
        let r = self
            .request::<StateSearchMsgResponse>(
                "Filecoin.StateSearchMsg",
                json!([null, CIDMap::from(cid), lookback, true]),
            )
            .await?;
        tracing::debug!("received state_search_msg_limited response: {r:?}");
        Ok(r)
    }

    /// Search for a message by CID
    pub async fn state_search_msg(&self, cid: Cid) -> Result<StateSearchMsgResponse> {
        // Use null tipset like in the working curl command
        let r = self
            .request::<StateSearchMsgResponse>(
                "Filecoin.StateSearchMsg",
                json!([null, CIDMap::from(cid), 2_000_000, true]),
            )
            .await?;
        tracing::info!("✅ Found message execution at height: {}", r.height);
        tracing::debug!("received state_search_msg response: {r:?}");
        Ok(r)
    }

    /// Get block messages by CID
    pub async fn chain_get_block_messages(
        &self,
        cid: Cid,
    ) -> Result<ChainGetBlockMessagesResponse> {
        let r = self
            .request::<ChainGetBlockMessagesResponse>(
                "Filecoin.ChainGetBlockMessages",
                json!([CIDMap::from(cid)]),
            )
            .await?;
        tracing::debug!("received chain_get_block_messages response: {r:?}");
        Ok(r)
    }

    /// Get parent receipts by CID
    pub async fn chain_get_parent_receipts(
        &self,
        cid: Cid,
    ) -> Result<ChainGetParentReceiptsResponse> {
        let r = self
            .request::<ChainGetParentReceiptsResponse>(
                "Filecoin.ChainGetParentReceipts",
                json!([CIDMap::from(cid)]),
            )
            .await?;
        tracing::debug!("received chain_get_parent_receipts response: {r:?}");
        Ok(r)
    }

    /// Get parent messages by CID
    pub async fn chain_get_parent_messages(&self, cid: Cid) -> Result<serde_json::Value> {
        let r = self
            .request::<serde_json::Value>(
                "Filecoin.ChainGetParentMessages",
                json!([CIDMap::from(cid)]),
            )
            .await?;
        tracing::debug!("received chain_get_parent_messages response: {r:?}");
        Ok(r)
    }

    /// Make a generic RPC request
    pub async fn request<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        tracing::debug!("{} request: {}", method, serde_json::to_string_pretty(&request_body).unwrap());

        let mut builder = self.http_client.post(self.url.as_str()).json(&request_body);
        builder = builder.timeout(DEFAULT_REQ_TIMEOUT);

        if self.bearer_token.is_some() {
            builder = builder.bearer_auth(self.bearer_token.as_ref().unwrap());
        }

        let response = builder.send().await?;
        let response_body = response.text().await?;
        tracing::debug!("{} raw response: {}", method, response_body);

        // Parse the JSON-RPC response
        let value: serde_json::Value = serde_json::from_str(&response_body)?;

        if let Some(result) = value.get("result") {
            let data: T = serde_json::from_value(result.clone())?;
            Ok(data)
        } else if let Some(error) = value.get("error") {
            let error_msg = error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("{} RPC error: {}", method, error_msg);
        } else {
            anyhow::bail!("{} response has neither result nor error", method);
        }
    }

    /// Read object by CID
    pub async fn chain_read_obj(&self, cid: Cid) -> Result<String> {
        let r = self
            .request::<ChainReadObjResponse>("Filecoin.ChainReadObj", json!([CIDMap::from(cid)]))
            .await?;
        tracing::debug!("received chain_read_obj response");

        let data = match r {
            ChainReadObjResponse::Direct(data) => data,
            ChainReadObjResponse::Wrapped { data } => data,
        };

        Ok(data)
    }

    /// Returns the name of the network
    pub async fn state_network_name(&self) -> Result<String> {
        let r = self
            .request::<String>("Filecoin.StateNetworkName", serde_json::Value::Null)
            .await?;
        tracing::debug!("received state_network_name response: {r:?}");
        Ok(r)
    }

    /// Returns the network version
    pub async fn state_network_version(&self, tip_sets: Vec<Cid>) -> Result<NetworkVersion> {
        let params = json!([tip_sets.into_iter().map(CIDMap::from).collect::<Vec<_>>()]);

        let r = self
            .request::<NetworkVersion>("Filecoin.StateNetworkVersion", params)
            .await?;

        tracing::debug!("received state_network_version response: {r:?}");
        Ok(r)
    }

    /// Read state of an address
    pub async fn read_state<State: DeserializeOwned + std::fmt::Debug>(
        &self,
        address: Address,
        tipset: Cid,
    ) -> Result<ReadStateResponse<State>> {
        let r = self
            .request::<ReadStateResponse<State>>(
                "Filecoin.StateReadState",
                json!([address.to_string(), [CIDMap::from(tipset)]]),
            )
            .await?;
        tracing::debug!("received read_state response: {r:?}");
        Ok(r)
    }

    // ===== Ethereum RPC Methods =====

    /// Get transaction receipt by hash
    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<EthTransactionReceipt> {
        let r = self
            .request::<EthTransactionReceipt>("eth_getTransactionReceipt", json!([tx_hash]))
            .await?;
        tracing::debug!("received eth_get_transaction_receipt response: {r:?}");
        Ok(r)
    }

    /// Get logs with filter
    pub async fn eth_get_logs(
        &self,
        from_block: &str,
        to_block: &str,
        address: &str,
        topics: Vec<String>,
    ) -> Result<Vec<EthLog>> {
        let filter = json!({
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": address,
            "topics": topics
        });
        let r = self
            .request::<Vec<EthLog>>("eth_getLogs", json!([filter]))
            .await?;
        tracing::debug!("received eth_get_logs response: {r:?}");
        Ok(r)
    }

    /// Get block number
    pub async fn eth_block_number(&self) -> Result<String> {
        let r = self.request::<String>("eth_blockNumber", json!([])).await?;
        tracing::debug!("received eth_block_number response: {r:?}");
        Ok(r)
    }
}
