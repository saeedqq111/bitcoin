// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_HDKEYSTORE_H
#define BITCOIN_WALLET_HDKEYSTORE_H

#include "keystore.h"
#include "corewallet/crypter.h"
#include "serialize.h"
#include "pubkey.h"

typedef uint256 HDChainID;

namespace CoreWallet {
/** hdpublic key for a persistant store. */
class CHDPubKey
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    CPubKey pubkey; //the acctual pubkey
    unsigned int nChild; //child index
    HDChainID chainHash; //hash of the chains master pubkey
    std::string chainPath; //individual key chainpath like m/44'/0'/0'/0/1
    bool internal;

    CHDPubKey()
    {
        SetNull();
    }

    bool IsValid()
    {
        return pubkey.IsValid();
    }

    void SetNull()
    {
        nVersion = CHDPubKey::CURRENT_VERSION;
        chainHash.SetNull();
        chainPath.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;

        READWRITE(pubkey);
        READWRITE(nChild);
        READWRITE(chainHash);
        READWRITE(chainPath);
        READWRITE(internal);
    }
};

/** class for representing a hd chain of keys. */
class CHDChain
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown

    HDChainID chainHash; //hash() of the masterpubkey
    std::string chainPath; //something like "m'/44'/0'/0'/c"
    CExtPubKey externalPubKey;
    CExtPubKey internalPubKey; // pubkey.IsValid() == false means only use external chain

    CHDChain()
    {
        SetNull();
    }

    CHDChain(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    bool IsValid()
    {
        return externalPubKey.pubkey.IsValid();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;

        READWRITE(nCreateTime);
        READWRITE(chainHash);
        READWRITE(chainPath);
        READWRITE(externalPubKey);
        READWRITE(internalPubKey);
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nCreateTime = 0;
        chainHash.SetNull();
    }
};

class CHDKeyStore : public CCryptoKeyStore
{
protected:
    std::map<HDChainID, CExtKey > mapHDMasterExtendedMasterKey; //extended master private keys are stored outside of CHDChain (crypto)
    std::map<HDChainID, std::vector<unsigned char> > mapHDCryptedExtendedMasterKeys;
    std::map<CKeyID, CHDPubKey> mapHDPubKeys; //all hd pubkeys of all chains
    std::map<HDChainID, CHDChain> mapChains; //all available chains

    //!derive key from a CHDPubKey object
    bool DeriveKey(const CHDPubKey hdPubKey, CKey& keyOut) const;

public:
    //!add a extended master private key with a given pubkeyhash (memory only)
    virtual bool AddExtendedMasterKey(const HDChainID& pubkeyhash, const CExtKey& extKey);

    //!add a crypted extended master private key with a given pubkeyhash (memory only)
    virtual bool AddCryptedExtendedMasterKey(const HDChainID& hash, const std::vector<unsigned char>& vchCryptedSecret);

    //!encrypt existing uncrypted extended master private key and remove unencrypted data
    virtual bool EncryptExtendedMasterKey(const CKeyingMaterial& vMasterKeyIn);

    //!export the extended master private key from a given chain id (hash of the master pub key)
    virtual bool GetExtendedMasterKey(const HDChainID& hash, CExtKey& extKeyOut) const;

    //!get the encrypted extened master private key of a giveb chain id
    virtual bool GetCryptedExtendedMasterKey(const HDChainID& hash, std::vector<unsigned char>& vchCryptedSecret) const;

    //!writes all available chain ids to a vector
    virtual bool GetAvailableChainIDs(std::vector<HDChainID>& chainIDs);

    //!add a CHDPubKey object to the keystore (memory only)
    bool LoadHDPubKey(const CHDPubKey &pubkey);


    //!add a new chain to the keystore (memory only)
    bool AddChain(const CHDChain& chain);

    //!writes a chain defined by given chainId to chainOut, returns false if not found
    bool GetChain(const HDChainID chainId, CHDChain& chainOut) const;

    //!Derives a hdpubkey object in a given chain defined by chainId from the existing external oder internal chain root pub key
    bool DeriveHDPubKeyAtIndex(const HDChainID chainId, CHDPubKey& hdPubKeyOut, unsigned int nIndex, bool internal) const;

    /**
     * Get next available index for a child key in chain defined by given chain id
     * @return next available index
     * @warning This will "fill gaps". If you have m/0/0, m/0/1, m/0/2, m/0/100 it will return 3 (m/0/3)
     */
    unsigned int GetNextChildIndex(const HDChainID& chainId, bool internal);

    //!check if a wallet has a certain key
    bool HaveKey(const CKeyID &address) const;

    //!get a key with given keyid for signing, etc. (private key operation)
    bool GetKey(const CKeyID &address, CKey &keyOut) const;

    //!get a pubkey with given keyid for verifiying, etc.
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    //!get a hdpubkey
    bool GetHDPubKey(const CKeyID &address, CHDPubKey &pubkeyOut) const;

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);
};
};  //end namespace
#endif // BITCOIN_WALLET_HDKEYSTORE_H