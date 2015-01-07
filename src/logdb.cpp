// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>
#include <unistd.h>

#include "logdb.h"

#define LOGDB_MAX_KEY_SIZE 0x1000
#define LOGDB_MAX_VALUE_SIZE 0x100000

using namespace std;

// Compact integers: least-significant digit first base-128 encoding.
// The high bit in each byte signifies whether another digit follows.
// To avoid redundancy, one is subtracted from all but the first digit.
// Thus, the byte sequence a[] where all but the last has bit 128 set,
// encodes the number (a[0] & 0x7F) + sum(i=1..n, 128^i*((a[i] & 0x7F)+1))

size_t static WriteInt(FILE* file, uint64_t n)
{
    int nRet = 0;
    do
    {
        nRet++;
        putc((n % 128) | (n>127)*128, file);
        if (n<128)
            break;
        n = (n / 128)-1;
    } while(1);
    return nRet;
}

uint64_t static ReadInt(FILE *file)
{
    uint64_t nRet = 0;
    uint64_t nBase = 1;
    while (nBase)
    {
        int nByte = getc(file);
        nRet += nBase * ((nByte & 127) + (nBase>1));
        if (nByte < 128)
            break;
        nBase *= 128;
    }
    return nRet;
}

// File format
// 
// The file consists of a list of frames, each of which consists of:
// 4 bytes magic: 0xCC 0xC4 0xE6 0xB0
// N records, each of which consists of:
//   1 byte mode: 1=insert/overwrite, 2=erase
//   integer: key length (max 4 KiB)
//   key
//   if mode==1: integer: data length (max 1 MiB)
//   if mode==1: data
// 0 byte
// 8 bytes checksum: first 8 bytes of running SHA256

class CModEntry
{
public:
    unsigned char nMode;
    data_t key;
    data_t value;
};

void CLogDBFile::Init_()
{
    file = NULL;
    ctxState.Reset();
    mapData.clear();
    nUsed = 0;
    nWritten = 0;
    setDirty.clear();
}

bool CLogDBFile::Write_(const data_t &key, const data_t &value, bool fOverwrite, bool fLoad)
{
    // update nUsed
    std::map<data_t, data_t>::iterator it = mapData.find(key);
    if (it != mapData.end())
    {
        if ((*it).second == value)
            return true;

        if (!fOverwrite)
            return false;
        nUsed -= (*it).first.size() + (*it).second.size();
    }
    nUsed += key.size() + value.size();

    // update data
    mapData.erase(key);
    mapData.insert(make_pair(key, value));
    if (!fLoad)
        setDirty.insert(key);

    return true;
}

bool CLogDBFile::Read_(const data_t &key, data_t &value) const
{
    std::map<data_t, data_t>::const_iterator it = mapData.find(key);
    if (it == mapData.end())
        return false;

    value = (*it).second;

    return true;
}

bool CLogDBFile::Exists_(const data_t &key) const
{
    return mapData.count(key) > 0;
}

bool CLogDBFile::Erase_(const data_t &key, bool fLoad)
{
    std::map<data_t, data_t>::iterator it = mapData.find(key);
    if (it != mapData.end())
    {
        nUsed -= (*it).first.size() + (*it).second.size();
        mapData.erase(it);
        if (!fLoad)
            setDirty.insert(key);
    }

    return true;
}

bool CLogDBFile::Close_()
{
    if (file)
    {
        Flush_();
        
        LogPrintf("CLogDBFile::Close(): closing file\n");
        fclose(file);
        Init_();
    }
    return true;
}

bool CLogDBFile::Load_()
{
    do
    {
        if (feof(file))
            return true;
        if (getc(file) != 0xCC) return feof(file);
        if (getc(file) != 0xC4) return false;
        if (getc(file) != 0xE6) return false;
        if (getc(file) != 0xB0) return false;

        LogPrintf("CLogDB::Load(): frame header found\n");

        vector<CModEntry> vMod;

        // update a copy of the state, so we can revert in case of error
        CSHA256 ctx = ctxState;

        do
        {
            if (feof(file))
            {
                LogPrintf("CLogDBFile::Load(): unexpected eof at record start\n");
                return false;
            }

            CModEntry entry;
            entry.nMode = getc(file);
            if (entry.nMode > 2)
            {
                LogPrintf("CLogDBFile::Load(): unknown record mode\n");
                return false;
            }

            ctx.Write((const unsigned char *)&entry.nMode, 1);
            
            if (entry.nMode == 0)
                break;

            LogPrintf("CLogDBFile::Load(): loading record mode %i\n", entry.nMode);

            uint32_t nKeySize = ReadInt(file);
            if (nKeySize >= LOGDB_MAX_KEY_SIZE)
            {
                LogPrintf("CLogDBFile::Load(): oversizes key (%lu bytes)\n", (unsigned long)nKeySize);
                return false;
            }
            entry.key.resize(nKeySize);
            if (fread(&entry.key[0], nKeySize, 1, file) != 1)
            {
                LogPrintf("CLogDBFile::Load(): unable to read key (%lu bytes)\n", (unsigned long)nKeySize);
                return false;
            }

            LogPrintf("CLogDBFile::load(): loading key (%.*s)\n", nKeySize, &entry.key[0]);

            ctx.Write((const unsigned char *)&nKeySize, 4);
            ctx.Write((const unsigned char *)&entry.key[0], nKeySize);

            if (entry.nMode == 1)
            {
                int nValueSize = ReadInt(file);
                if (nValueSize >= LOGDB_MAX_VALUE_SIZE)
                {
                    LogPrintf("CLogDBFile::Load(): oversized value (%lu bytes)\n", (unsigned long)nValueSize);
                    return false;
                }
                entry.value.resize(nValueSize);
                if (fread(&entry.value[0], nValueSize, 1, file) != 1)
                {
                    LogPrintf("CLogDBFile::Load(): unable to read value (%lu bytes)\n", (unsigned long)nValueSize);
                    return false;
                }

                ctx.Write((const unsigned char *)&nValueSize, 4);
                ctx.Write((const unsigned char *)&entry.value[0], nValueSize);
            }

            vMod.push_back(entry);
        } while(true);

        unsigned char check[8];
        if (fread(check, 8, 1, file)!=1)
        {
            LogPrintf("CLogDBFile::Load(): unable to read checksum\n");
            return false;
        }

        CSHA256 ctxFinal = ctx;

        unsigned char checkx[32];
        ctxFinal.Finalize(checkx);
        if (memcmp(check,checkx,8))
        {
            LogPrintf("CLogDBFile::Load(): checksum failed\n");
            return false;
        }
        else
        {
            LogPrintf("CLogDBFile::Load(): checksum OK\n");
        }

        // if we reach this point, the entire read frame was valid
        ctxState = ctx;

        for (vector<CModEntry>::iterator it = vMod.begin(); it != vMod.end(); it++)
        {
            CModEntry &mod = *it;
            nWritten += mod.key.size() + mod.value.size();
            switch (mod.nMode)
            {
                case 1:
                    Write_(mod.key, mod.value, true, true);
                    break;

                case 2:
                    Erase_(mod.key, true);
                    break;
            }
        }

    } while(true);

    LogPrintf("CLogDBFile::Load(): done\n");
}

bool CLogDBFile::Flush_()
{
    LogPrintf("CLogDBFile::Flush_()\n");

    if (setDirty.empty())
        return true;

    LogPrintf("CLogDBFile::Flush_(): dirty entries found\n");

    unsigned char magic[4]={0xCC,0xC4,0xE6,0xB0};

    if (fwrite(magic, 4, 1, file) != 1)
    {
        LogPrintf("CLogDBFile::Flush_(): error writing magic: %s\n", strerror(errno));
    }

    CSHA256 ctx = ctxState;

    for (set<data_t>::iterator it = setDirty.begin(); it != setDirty.end(); it++)
    {
        map<data_t, data_t>::iterator it2 = mapData.find(*it);

        if (it2 != mapData.end())
        {
            // update
            unsigned char nMode = 1;
            uint32_t nKeySize = (*it).size();
            uint32_t nDataSize = (*it2).second.size();
            nWritten += nKeySize + nDataSize;

            LogPrintf("CLogDBFile::Flush(): writing update(%.*s)\n", nKeySize, &(*it)[0]);

            putc(nMode, file);
            WriteInt(file, nKeySize);
            fwrite(&(*it)[0], nKeySize, 1, file);
            WriteInt(file, nDataSize);
            fwrite(&(*it2).second[0], nDataSize, 1, file);

            ctx.Write((const unsigned char *)&nMode, 1);
            ctx.Write((const unsigned char *)&nKeySize, 4);
            ctx.Write((const unsigned char *)&(*it)[0], nKeySize);
            ctx.Write((const unsigned char *)&nDataSize, 4);
            ctx.Write((const unsigned char *)&(*it2).second[0], nDataSize);
        }
        else
        {
            // erase
            unsigned char nMode = 2;
            uint32_t nKeySize = (*it).size();
            nWritten += nKeySize;

            LogPrintf("CLogDBFile::Flush(): writing erase(%.*s)\n", nKeySize, &(*it)[0]);

            putc(nMode, file);
            WriteInt(file, nKeySize);
            fwrite(&(*it)[0], nKeySize, 1, file);

            ctx.Write((const unsigned char *)&nMode, 1);
            ctx.Write((const unsigned char *)&nKeySize, 4);
            ctx.Write((const unsigned char *)&(*it)[0], nKeySize);
        }
    }

    unsigned char nMode = 0;
    putc(nMode, file);
    ctx.Write((const unsigned char *)&nMode, 1);

    CSHA256 ctxFinal = ctx;
    unsigned char buf[32];
    ctxFinal.Finalize(buf);
    fwrite(buf, 8, 1, file);
    fflush(file);
    FileCommit(file);
    ctxState = ctx;

    LogPrintf("CLogDBFile::Flush(): wrote frame\n");

    setDirty.clear();

    return true;
}

bool CLogDB::TxnAbort() {
    LOCK(cs);

    if (!fTransaction)
        return false;

    mapData.clear();
    setDirty.clear();

    fTransaction = false;
    if (fReadOnly)
        db->mutex.unlock_shared();
    else
        db->mutex.unlock();

    return true;
}

bool CLogDB::TxnBegin() {
    LOCK(cs);

    if (fTransaction)
        return false;

    if (fReadOnly)
        db->mutex.lock_shared();
    else
        db->mutex.lock();

    fTransaction = true;
    return true;
}

bool CLogDB::TxnCommit() {
    LOCK(cs);

    if (!fTransaction)
        return false;

    // commit modifications to backing CLogDBFile
    for (std::set<data_t>::const_iterator it = setDirty.begin(); it != setDirty.end(); it++) {
         std::map<data_t, data_t>::const_iterator it2 = mapData.find(*it);
         if (it2 == mapData.end()) {
             db->Erase_(*it);
         } else {
             db->Write_(*it, (*it2).second);
         }
    }
    mapData.clear();
    setDirty.clear();

    fTransaction = false;
    if (fReadOnly)
        db->mutex.unlock_shared();
    else
        db->mutex.unlock();

    return true;
}

bool CLogDB::Write_(const data_t &key, const data_t &value, bool fOverwrite) {
    if (key.size() >= LOGDB_MAX_KEY_SIZE)
    {
        LogPrintf("CLogDB::Write(): max keysize exceeded\n");
        return false;
    }
    if (value.size() >= LOGDB_MAX_VALUE_SIZE)
    {
        LogPrintf("CLogDB::Write(): max keysize exceeded\n");
        return false;
    }
    if (fReadOnly)
        return false;

    LOCK(cs);

    bool fAutoTransaction = TxnBegin();

    if (!fOverwrite && Exists_(key))
        return false;
    
    mapData[key] = value;
    setDirty.insert(key);

    if (fAutoTransaction)
        return TxnCommit();

    return true;
}

bool CLogDB::Erase_(const data_t &key) {
    if (fReadOnly)
        return false;

    LOCK(cs);

    bool fAutoTransaction = TxnBegin();

    mapData.erase(key);
    setDirty.insert(key);

    if (fAutoTransaction)
        return TxnCommit();
    return true;
}

bool CLogDB::Read_(const data_t &key, data_t &value) {
    LOCK(cs);

    bool fAutoTransaction = TxnBegin();
    bool fOk = true;

    // in readonly mode: no need to check for local modifications
    if (!fReadOnly && setDirty.count(key)) {
        std::map<data_t, data_t>::const_iterator it = mapData.find(key);
        if (it != mapData.end()) {
            value = (*it).second;
        } else {
            fOk = false;
        }
    } else {
        fOk = db->Read_(key, value);
    }

    if (fAutoTransaction)
        fOk &= TxnCommit();

    return fOk;
}

bool CLogDB::Exists_(const data_t &key) {
    LOCK(cs);

    bool fAutoTransaction = TxnBegin();

    bool fRet;
    // in readonly mode: no need to check for local modifications
    if (!fReadOnly && setDirty.count(key) != 0) {
        fRet = (mapData.count(key) != 0);
    } else {
        fRet = db->Exists_(key);
    }

    if (fAutoTransaction)
        TxnCommit();

    return fRet;
}

bool CLogDB::Flush(bool shutdown)
{
    boost::lock_guard<boost::shared_mutex> lock(db->mutex);
    bool state = db->Flush_();
    
    return state;
}
