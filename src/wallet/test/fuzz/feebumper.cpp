// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>
#include <wallet/context.h>
#include <wallet/feebumper.cpp>
#include <wallet/feebumper.h>
#include <wallet/test/util.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

namespace wallet {
namespace {

const TestingSetup* g_setup;
static std::unique_ptr<CWallet> g_wallet_ptr;

void initialize_feebumper()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
    const auto& node{g_setup->m_node};
    g_wallet_ptr = std::make_unique<CWallet>(node.chain.get(), "", CreateMockableWalletDatabase());
}

// Function to add new random transactions to the wallet.
static CWalletTx* AddTx(CWallet& wallet, FuzzedDataProvider& fuzzed_data_provider)
{
    const std::optional<CMutableTransaction> opt_mutable_transaction{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider)};
    if (!opt_mutable_transaction) return nullptr;
    CMutableTransaction mtx = *opt_mutable_transaction;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10)
    {
        const std::optional<CMutableTransaction> another_mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
        if (!another_mtx) {
            break;
        }
        const CTransaction another_tx{*another_mtx};
        // Explicitly setting up the nSequence to make some inputs Replace-By-Fee compatible.
        const CTxIn tx_in{COutPoint{another_tx.GetHash(), 0}, ConsumeScript(fuzzed_data_provider), ConsumeSequence(fuzzed_data_provider)};
        mtx.vin.emplace_back(tx_in);
    }

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    // Note: if the generated Transaction is already existing
    // in the wallet, then recalling `AddToWallet`
    // will attempt to update it but will result in asserts false 
    // because the transaction's state is not changing.
    const uint256 txid = tx->GetHash();
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.GetWalletTx(txid);
        if (wtx != nullptr) return nullptr;
    }

    // Adds a new Transaction to the wallet.
    return wallet.AddToWallet(tx, TxStateInactive{});
}

FUZZ_TARGET_INIT(feebumper, initialize_feebumper)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const auto& node{g_setup->m_node};
    Chainstate* chainstate = &node.chainman->ActiveChainstate();
    CWallet& wallet = *g_wallet_ptr;
    {
        LOCK(wallet.cs_wallet);
        wallet.SetLastBlockProcessed(chainstate->m_chain.Height(), chainstate->m_chain.Tip()->GetBlockHash());
    }
    
    // Adding a new Transaction to the wallet and also 
    // updating these values inside the `CallOneOf` function.
    CWalletTx* wtx = AddTx(wallet, fuzzed_data_provider);
    if(wtx == nullptr) return;
    uint256 txid = wtx->GetHash();

    CCoinControl coin_control;
    if (fuzzed_data_provider.ConsumeBool()) {
        coin_control.m_feerate = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
    }
    if (fuzzed_data_provider.ConsumeBool()) {
        coin_control.m_confirm_target = fuzzed_data_provider.ConsumeIntegralInRange<unsigned int>(0, 999'000);
    }
    // Marking the new fee-bumped transaction as BIP-125 replaceable sometimes.
    if (fuzzed_data_provider.ConsumeBool()) {
        coin_control.m_signal_bip125_rbf = true;
    }

    std::vector<bilingual_str> errors;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Sometimes adding a new Transaction to the Wallet and updating the `wtx`.
                const auto new_wtx = AddTx(wallet, fuzzed_data_provider);
                if(new_wtx == nullptr) return;
                wtx = new_wtx;
                txid = wtx->GetHash();
            },
            [&] {
                // Otherwise using a random Transaction to feed the functions for fuzzing.
                txid = ConsumeUInt256(fuzzed_data_provider);
                {
                    LOCK(wallet.cs_wallet);
                    wtx = const_cast<CWalletTx*>(wallet.GetWalletTx(txid));
                }
            },
            [&] {
                if(wtx == nullptr) return;
                {
                    LOCK(wallet.cs_wallet);
                    (void)PreconditionChecks(wallet, *wtx, fuzzed_data_provider.ConsumeBool(), errors);
                }
            },
            [&] {
                (void)CheckFeeRate(/*wallet=*/wallet,
                                   /*newFeerate=*/CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)},
                                   /*maxTxSize=*/fuzzed_data_provider.ConsumeIntegral<int64_t>(),
                                   /*old_fee=*/ConsumeMoney(fuzzed_data_provider),
                                   /*errors=*/errors);
            },
            [&] {
                if(wtx == nullptr) return;
                CAmount old_fee = ConsumeMoney(fuzzed_data_provider);
                {
                    LOCK(wallet.cs_wallet);
                    (void)EstimateFeeRate(wallet, *wtx, /*old_fee=*/ old_fee, coin_control);
                }
            },
            [&] {
                (void)feebumper::TransactionCanBeBumped(wallet, txid);
            },
            [&] {
                CMutableTransaction new_mtx;
                std::vector<CTxOut> outputs;

                // outputs may or may not be empty, hence the feebumped transaction may or may not use the original outputs.
                if (fuzzed_data_provider.ConsumeBool()) {
                    for (int i = 0; i < 100; ++i) {
                        CTxOut tx_out{ConsumeMoney(fuzzed_data_provider), ConsumeScript(fuzzed_data_provider)};
                        outputs.emplace_back(tx_out);
                    }
                }
                CAmount old_fee;
                CAmount new_fee;
                (void)feebumper::CreateRateBumpTransaction(/*wallet=*/wallet,
                                                     /*txid=*/txid,
                                                     /*coin_control=*/coin_control,
                                                     /*errors=*/errors,
                                                     /*old_fee=*/old_fee,
                                                     /*new_fee=*/new_fee,
                                                     /*mtx=*/new_mtx,
                                                     /*require_mine=*/fuzzed_data_provider.ConsumeBool(),
                                                     /*outputs=*/outputs);
                
                (void)feebumper::SignTransaction(wallet, new_mtx);
                
                // Committing the newly fee-bumped transaction to the wallet.
                uint256 bumped_txid;
                (void)feebumper::CommitTransaction(wallet, txid, std::move(new_mtx), errors, bumped_txid);
            },
            [&] {
                std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
                if (!mtx) return;
                (void)feebumper::SignTransaction(wallet, *mtx);
            },
            [&] {
                const std::optional<CMutableTransaction> opt_mutable_transaction{ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider)};
                if (!opt_mutable_transaction) {
                    return;
                }
                uint256 new_txid = ConsumeUInt256(fuzzed_data_provider);
                CMutableTransaction random_mutable_transaction{*opt_mutable_transaction};
                errors.clear();
                uint256 bumped_txid;
                (void)feebumper::CommitTransaction(wallet, new_txid, std::move(random_mutable_transaction), errors, bumped_txid);
            });
    }

    // Covering the Signature Weights.
    feebumper::SignatureWeights weights;
    // Preventing overflow in `GetWeightDiffToMax()` by setting the maximum weight size according to `MAX_STANDARD_SCRIPTSIG_SIZE`
    weights.AddSigWeight(/*weight=*/fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 1650), 
                        /*sigversion=*/fuzzed_data_provider.PickValueInArray({SigVersion::BASE, SigVersion::WITNESS_V0}));

    (void)weights.GetWeightDiffToMax();
}
} // namespace
} // namespace wallet
