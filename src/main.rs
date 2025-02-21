//! register operator in quorum with avs registry coordinator
use alloy::primitives::{address, Address, U256};
use alloy::primitives::{Bytes, FixedBytes};
use alloy::providers::WalletProvider;
use eigen_types::operator::Operator;
use eigensdk::client_avsregistry::writer::AvsRegistryChainWriter;
use eigensdk::client_elcontracts::reader::ELChainReader;
use eigensdk::client_elcontracts::writer::ELChainWriter;
use eigensdk::common::get_signer;
use eigensdk::crypto_bls::BlsKeyPair;
use eigensdk::logging::get_test_logger;
use eigensdk::testing_utils::m2_holesky_constants::{
    AVS_DIRECTORY_ADDRESS, DELEGATION_MANAGER_ADDRESS, REWARDS_COORDINATOR,
    STRATEGY_MANAGER_ADDRESS,
};
use eyre::Result;
use lazy_static::lazy_static;
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
    /// 1 day
    static ref SIGNATURE_EXPIRY: U256 = U256::from(86400);
}
#[tokio::main]
async fn main() -> Result<()> {
    let holesky_provider = "https://ethereum-holesky-rpc.publicnode.com";
    let pvt_key = "68adc67158ef2a42183f797c9f88e8d8dd9dfe0214f9e781f97f4d163130db0e";
    let OPACITY_REGISTRY_COORDINATOR = address!("3e43AA225b5cB026C5E8a53f62572b10D526a50B");
    let signer = get_signer(&pvt_key, &holesky_provider);
    let test_logger = get_test_logger();

    let avs_registry_writer = AvsRegistryChainWriter::build_avs_registry_chain_writer(
        test_logger.clone(),
        holesky_provider.to_string(),
        pvt_key.to_string(),
        OPACITY_REGISTRY_COORDINATOR,
        Address::ZERO,
    )
    .await
    .expect("avs writer build fail ");

    // Create a new key pair instance using the secret key
    let bls_key_pair = BlsKeyPair::new(
        "12248929636257230549931416853095037629726205319386239410403476017439825112537".to_string(),
    )?;

    let digest_hash: FixedBytes<32> = FixedBytes::from([0x02; 32]);

    // Get the current SystemTime
    let now = SystemTime::now();
    let mut sig_expiry: U256 = U256::from(0);
    // Convert SystemTime to a Duration since the UNIX epoch
    if let Ok(duration_since_epoch) = now.duration_since(UNIX_EPOCH) {
        // Convert the duration to seconds
        let seconds = duration_since_epoch.as_secs(); // Returns a u64

        // Convert seconds to U256
        sig_expiry = U256::from(seconds) + *SIGNATURE_EXPIRY;
    } else {
        println!("System time seems to be before the UNIX epoch.");
    }
    let quorum_nums = Bytes::from([0x00]);

    // A new ElChainReader instance
    let el_chain_reader = ELChainReader::new(
        get_test_logger().clone(),
        None,
        DELEGATION_MANAGER_ADDRESS,
        REWARDS_COORDINATOR,
        AVS_DIRECTORY_ADDRESS,
        None,
        holesky_provider.to_string(),
    );

    // A new ElChainWriter instance
    let el_writer = ELChainWriter::new(
        STRATEGY_MANAGER_ADDRESS,
        REWARDS_COORDINATOR,
        None,
        None,
        OPACITY_REGISTRY_COORDINATOR,
        el_chain_reader,
        holesky_provider.to_string(),
        pvt_key.to_string(),
    );

    let operator_details = Operator {
        address: signer.default_signer_address(),
        delegation_approver_address: Address::ZERO,
        metadata_url: "opacity-eigensdk-rs".to_string(),
        _deprecated_earnings_receiver_address: Some(signer.default_signer_address()),
        staker_opt_out_window_blocks: Some(10),
        allocation_delay: Some(100),
    };
    // Register the address as operator in delegation manager
    let _s = el_writer.register_as_operator(operator_details).await?;

    // Register the operator in registry coordinator
    let tx = avs_registry_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            bls_key_pair,
            digest_hash,
            sig_expiry,
            quorum_nums,
            "65.109.158.181:33078;31078".to_string(), // socket
        )
        .await?;
    dbg!(tx);
    Ok(())
}
