// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The Supro developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "bignum.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of (0, uint256("0x000003d3a443a7260e7852e251d9ce6ad0164d60a28b789333925761adf359c9"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1528610400, // * UNIX timestamp of last checkpoint block
    0,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x000002f4440f1cd29910c79780d15bbc1fcdd89f013198a070118e9afe154e48"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1528610401,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x000002db10c27e40380f34fd835d31637ebb8ff08922c0a358469616890a8e85"));
	
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1528610402,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xc4;
        pchMessageStart[1] = 0xd3;
        pchMessageStart[2] = 0xe2;
        pchMessageStart[3] = 0xf1;
        vAlertPubKey = ParseHex("04de3ef24c49797718bb34077bc1997727ce5e79dcd83ed9b1f39110e53bf4c3af61ea4290ca3bc7ab27281ceac3901fa9d4ee1055f6d1b605673c41432f926141");
        nDefaultPort = 47113;
        bnProofOfWorkLimit = ~uint256(0) >> 16;
        nSubsidyHalvingInterval = 1050000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Supro: 1 day
        nTargetSpacing = 1 * 60;  // Supro: 1 minutes
        nMaturity = 60;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 50000000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 201;
        nModifierUpdateBlock = 1; // we use the version 2 for SP

        /**
        * python genesis.py -a quark-hash -z "France slashes cryptocurrency tax rate from 45 percent to a flat rate 19 percent" -t 1528610400 -v 0 -p 04535eca5c7d5366da60759568831550578e46d9c637ac214a66781319785a6e537403ecac89690e377273f6666701cdf9ecb66ca75ad9dbb3708044ff6af6dfd9
		* 04ffff001d01044c504672616e636520736c61736865732063727970746f63757272656e63792074617820726174652066726f6d2034352070657263656e7420746f206120666c617420726174652031392070657263656e74
		* algorithm: quark-hash
		* merkle hash: e0e89d2fcef38755c6233f172f7d5c458d51f417cb504d2d591dcff39f4918cf
		* pszTimestamp: France slashes cryptocurrency tax rate from 45 percent to a flat rate 19 percent
		* pubkey: 04535eca5c7d5366da60759568831550578e46d9c637ac214a66781319785a6e537403ecac89690e377273f6666701cdf9ecb66ca75ad9dbb3708044ff6af6dfd9
		* time: 1528610400
		* bits: 0x1e0ffff0
		* Searching for genesis hash..
		* 44192.0 hash/s, estimate: 27.0 hgenesis hash found!
		* nonce: 2245511
		* genesis hash: 000003d3a443a7260e7852e251d9ce6ad0164d60a28b789333925761adf359c9
         */
        const char* pszTimestamp = "France slashes cryptocurrency tax rate from 45 percent to a flat rate 19 percent";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04535eca5c7d5366da60759568831550578e46d9c637ac214a66781319785a6e537403ecac89690e377273f6666701cdf9ecb66ca75ad9dbb3708044ff6af6dfd9") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1528610400;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 2245511;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000003d3a443a7260e7852e251d9ce6ad0164d60a28b789333925761adf359c9"));
        assert(genesis.hashMerkleRoot == uint256("0xe0e89d2fcef38755c6233f172f7d5c458d51f417cb504d2d591dcff39f4918cf"));

        // DNS Seeding
        vSeeds.push_back(CDNSSeedData("seed1.supro.cc", "seed1.supro.cc"));
        vSeeds.push_back(CDNSSeedData("seed2.supro.cc", "seed2.supro.cc"));
        vSeeds.push_back(CDNSSeedData("seed3.supro.cc", "seed3.supro.cc"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,126);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,125);
        // Supro BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Supro BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04042ead57c84124380416e5fbe26757663c996f028a2e4279e43daecf8fa5076fec6922116c87c31f792e2b241f1091d706b40fac1bf808f3b21233d257d4b116";
        strMasternodePoolDummyAddress = "SNBsAXt1Qs7boz5qiaJxMibXWk7MQkVTEz";
        nStartMasternodePayments = genesis.nTime + 10800; // 3 hours after genesis creation

        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xc4;
        pchMessageStart[1] = 0xd3;
        pchMessageStart[2] = 0xe2;
        pchMessageStart[3] = 0xf1;
        vAlertPubKey = ParseHex("04973905390609daff4defc2703abd848b0f879497c7eee10ef49904456b99e59beca9449f9a5c719065986f7b4c5e8d4fee73f9c6934c0de61d8a615e962a0231");
        nDefaultPort = 48113;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Supro: 1 day
        nTargetSpacing = 1 * 60;  // Supro: 1 minute
        nLastPOWBlock = 20100;
        nMaturity = 30;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1;
        nMaxMoneyOut = 50000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1528610401;
        genesis.nNonce = 921896;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000002f4440f1cd29910c79780d15bbc1fcdd89f013198a070118e9afe154e48"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,141);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,12);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,239);
        // Testnet Supro BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Supro BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet supro BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "047da99497e01e37690c4ea6af77659a88092c740e53afb165c2b2532e6fd1db97e3a1aa5aa4ac86d0a35c8eb9f318d96f1a2f608c8d34d1691dfd6690a36abc41";
        strMasternodePoolDummyAddress = "SNBsAXt1Qs7boz5qiaJxMibXWk7MQkVTEz";
        nStartMasternodePayments = genesis.nTime + 10800; // 3 hours after genesis
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xc2;
        pchMessageStart[1] = 0xd3;
        pchMessageStart[2] = 0xe4;
        pchMessageStart[3] = 0xe1;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Supro: 1 day
        nTargetSpacing = 1 * 60;        // Supro: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1528610402;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 118434;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 49113;
        assert(hashGenesisBlock == uint256("0x000002db10c27e40380f34fd835d31637ebb8ff08922c0a358469616890a8e85"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 50113;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
