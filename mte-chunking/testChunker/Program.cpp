/*******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) Eclypses, Inc.
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  define _CRT_SECURE_NO_WARNINGS
#  include <Windows.h>
#  include <NTSecAPI.h>
#  include <bcrypt.h>
#  define strcasecmp _stricmp
#elif defined(linux) || defined (_linux_) || defined(ANDROID) || defined(__APPLE__)
#  include "stdio.h"
#endif


#include "MteBase.h"
#include "MteMkeEnc.h"
#include "MteMkeDec.h"
#include "MteRandom.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <vector>
#include <chrono>

 // The path separator character, for Windows use "\\", other operating systems it will be "/".
    // Platform dependent path separator.
#if defined(WIN32) || defined(_WIN32)
const char Separator = '\\';
#else 
const char Separator = '/';
#endif 

// This sample works with the MKE add-on that uses a cipher block size of 1. Any other
// cipher block sizes are not guaranteed to work.
// The encryption and decryption chunk sizes can be the same or different.
const size_t encryptChunkSize = 1024;
const size_t decryptChunkSize = 516;


class Cbs : public MteBase::EntropyCallback,
    public MteBase::NonceCallback,
    public MteBase::TimestampCallback
{
public:
    Cbs();
    virtual ~Cbs();
private:
    virtual mte_status entropyCallback(mte_drbg_ei_info& info);
    virtual void nonceCallback(mte_drbg_nonce_info& info);
    virtual MTE_UINT64_T timestampCallback();
};

static uint64_t getTimestamp();

uint64_t nonce;
uint8_t* entropy;

int main()
{
    mte_status status;

    // Initialize MTE license. If a license code is not required (e.g., trial
    // mode), this can be skipped.
    if (!MteBase::initLicense("LicenseCompanyName", "LicenseKey"))
    {
        status = mte_status_license_error;
        std::cerr << "There was an error attempting to initialize the MTE License." << std::endl;
        return status;
    }

    // Check encrypt and decrypt chunk sizes.
    size_t blockSize = MteBase::getCiphersBlockBytes(MTE_CIPHER_ENUM);
    if (blockSize > 1)
    {
        std::cerr << "The chunk size must be set to 1." << std::endl;
        return 1;
    }


    // Set personalization string to demo for this sample.
    std::string personal = "demo";

    // Set nonce to the timestamp.
    nonce = getTimestamp();

    // Create the callbacks to get entropy, nonce, and timestamp.
    Cbs cbs;


    size_t minEntropySize = MteBase::getDrbgsEntropyMinBytes(MTE_DRBG_ENUM);
    if (minEntropySize == 0)
    {
        minEntropySize = 1;
    }
    entropy = new uint8_t[minEntropySize];
    // Populate entropy buffer with random bytes.
    int res = MteRandom::getBytes(entropy, minEntropySize);
    if (res != 0)
    {
        std::cerr << "There was an error attempting to create random entropy." << std::endl;
        return mte_status_drbg_catastrophic;
    }

    // Create default MKE encoder.
    MteMkeEnc encoder;
    encoder.setEntropyCallback(&cbs);
    encoder.setNonceCallback(&cbs);
    encoder.setTimestampCallback(&cbs);
    status = encoder.instantiate(personal);
    if (status != mte_status_success)
    {
        std::cerr << "Encoder instantiate error ("
            << MteBase::getStatusName(status)
            << "): "
            << MteBase::getStatusDescription(status)
            << std::endl;
        return status;
    }

    // Create default MKE decoder.
    MteMkeDec decoder;
    decoder.setEntropyCallback(&cbs);
    decoder.setNonceCallback(&cbs);
    decoder.setTimestampCallback(&cbs);
    status = decoder.instantiate(personal);
    if (status != mte_status_success)
    {
        std::cerr << "Decoder instantiate error ("
            << MteBase::getStatusName(status)
            << "): "
            << MteBase::getStatusDescription(status)
            << std::endl;
        return status;
    }

    while (true)
    {
        std::string filePath;

        // Prompt for file path.
        std::cout << "Please enter path to file (To end please type 'quit')" << std::endl;

        std::getline(std::cin, filePath);

        if (strcasecmp(filePath.c_str(), "quit") == 0)
        {
            break;
        }

        // Find the last index of the path separator character.
        std::string baseFileName;
        const char* pathIndexChar = strrchr(filePath.c_str(), Separator);
        if (pathIndexChar == nullptr)
        {
            // No path characters in file name.
            baseFileName = filePath;
        }
        else
        {
            // Get everything after path character.
            baseFileName = pathIndexChar + 1;
        }

        // Get last index of period for file extension.
        std::string fileExtention;
        const char* fileExtensionIndex = strrchr(baseFileName.c_str(), '.');
        if (fileExtensionIndex == nullptr) {
            // No extension in file name.
            fileExtention = "";
        }
        else
        {
            // Include the period in the file extension.
            fileExtention = fileExtensionIndex;
        }

        // Create input file stream for read and binary.
        std::ifstream inputFile;
        inputFile.open(filePath, std::ifstream::in | std::ifstream::binary);
        if (!inputFile.good())
        {
            std::cerr << "Error opening file." << std::endl;
            return -1;
        }

        // Get the input file size by seeking to the end, then return to beginning.
        inputFile.seekg(0, inputFile.end);
        size_t fileLength = inputFile.tellg();
        inputFile.seekg(0, inputFile.beg);

        //=========================================////
        //***** Begin MKE Encryption Process. *****////
        //=========================================////

        // Create encoded file name that includes the same extension.
        std::string encodedFileName = "encoded" + fileExtention;

        // Open the encoded file stream for writing and binary.
        std::ofstream encodedFile;

        // Delete any existing encoded file.       
        if (std::remove(encodedFileName.c_str()) == 0)
        {
            std::cout << "Deleted existing file " << encodedFileName << std::endl;
        }

        encodedFile.open(encodedFileName, std::ofstream::out | std::ofstream::binary);

        // Start chunking session.
        status = encoder.startEncrypt();
        if (status != mte_status_success)
        {
            std::cerr << "Error starting encryption: ("
                << MteBase::getStatusName(status)
                << "): "
                << MteBase::getStatusDescription(status)
                << std::endl;
            return status;
        }

        // Go through until the end of the input file.
        while (!inputFile.eof())
        {
            // Create buffer to hold encrypt chunk size.
            char encryptChunkBuf[encryptChunkSize];

            // Read a portion of the input file of size encryptChunkSize to the encryption buffer.
            inputFile.read(encryptChunkBuf, encryptChunkSize);

            // The amount read from the stream.
            std::streamsize amountRead = inputFile.gcount();

            // Encrypt the chunk buffer.
            status = encoder.encryptChunk(encryptChunkBuf, amountRead);
            if (status != mte_status_success)
            {
                std::cerr << "Error encrypting chunk: ("
                    << MteBase::getStatusName(status)
                    << "): "
                    << MteBase::getStatusDescription(status)
                    << std::endl;
                return status;
            }

            // Write the chunk buffer to the encoded file.
            encodedFile.write(encryptChunkBuf, amountRead);
            encodedFile.flush();
        }

        // Close the input file.
        inputFile.close();

        // Finish the encryption with the encryption buffer.
        size_t finishSize = 0;
        const void* finishBuffer = encoder.finishEncrypt(finishSize, status);
        if (status != mte_status_success)
        {
            std::cerr << "Error finishing encryption: ("
                << MteBase::getStatusName(status)
                << "): "
                << MteBase::getStatusDescription(status)
                << std::endl;
            return status;
        }

        // Write the result bytes from encrypt finish.
        if (finishSize > 0)
        {
            encodedFile.write(static_cast<const char*>(finishBuffer), finishSize);
            encodedFile.flush();
        }

        // Close the encoded file.
        encodedFile.close();

        std::cout << "Successfully encoded file " << encodedFileName << std::endl;

        //=========================================////
        //***** Begin MKE Decryption Process. *****////
        //=========================================////

        // Create decoded file name that includes the same extension.
        std::string decodedFileName = "decoded" + fileExtention;

        // Open the decoded file stream for writing and binary.
        std::ofstream decodedFile;
        // Delete any existing decoded file.      
        if (std::remove(decodedFileName.c_str()) == 0)
        {
            std::cout << "Deleted existing file " << decodedFileName << std::endl;
        }

        decodedFile.open(decodedFileName, std::ofstream::out | std::ofstream::binary);

        // Start decrypt chunking session.
        status = decoder.startDecrypt();
        if (status != mte_status_success)
        {
            std::cerr << "Error starting decryption: ("
                << MteBase::getStatusName(status)
                << "): "
                << MteBase::getStatusDescription(status)
                << std::endl;
            return status;
        }

        // Re-open encoded file, for reading and binary.
        std::ifstream encodedInputFile;
        encodedInputFile.open(encodedFileName, std::ifstream::in | std::ifstream::binary);

        // Go through until the end of the input file.
        while (!encodedInputFile.eof())
        {
            // Create buffer to hold decrypt chunk size.
            char decryptChunkBuf[decryptChunkSize];

            // Read a portion of the encoded file of size decryptChunkSize to the decryption buffer.
            encodedInputFile.read(decryptChunkBuf, decryptChunkSize);

            // The amount read from the stream.
            std::streamsize amountRead = encodedInputFile.gcount();

            // Decrypt the chunk buffer.
            size_t decryptedBytes = 0;
            const void* decryptedChunk = decoder.decryptChunk(decryptChunkBuf, amountRead, decryptedBytes);

            // If there are any bytes decrypted, write that to the decoded file.
            if (decryptedBytes > 0)
            {
                // Write the chunk buffer to the decoded file.
                decodedFile.write(static_cast<const char*>(decryptedChunk), decryptedBytes);
                decodedFile.flush();
            }
        }

        // Finish MKE decryption.
        size_t decryptedBytes = 0;
        const void* decryptedChunk = decoder.finishDecrypt(decryptedBytes, status);
        // If there are any bytes decrypted, write that to the decoded file.
        if (decryptedBytes > 0)
        {
            // Write the chunk buffer to the decoded file.
            decodedFile.write(static_cast<const char*>(decryptedChunk), decryptedBytes);
            decodedFile.flush();
        }

        // Close the encoded file.
        encodedFile.close();

        // Close the decoded file.
        decodedFile.close();

        std::cout << "Successfully decoded file " << decodedFileName << std::endl;

    } // End of main program loop.

    delete[] entropy;

    return 0;

}

Cbs::Cbs() = default;

Cbs::~Cbs() = default;

mte_status Cbs::entropyCallback(mte_drbg_ei_info& info)
{
    // Copy the entropy into the buffer.
    memcpy(info.buff, entropy, info.min_entropy);

    // Set the entropy length.
    info.bytes = info.min_entropy;
    return mte_status_success;
}

void Cbs::nonceCallback(mte_drbg_nonce_info& info)
{
    // Copy the nonce in little-endian format to the nonce buffer.
    union nonce_length
    {
        uint64_t length;
        uint8_t arr[16];
    };
    union nonce_length my_nonce;
    my_nonce.length = nonce;

    info.buff = my_nonce.arr;

    // Set the actual nonce length.
    info.bytes = 16;

}

MTE_UINT64_T Cbs::timestampCallback()
{
    // In this sample, 0 will be returned instead of a real timestamp.
    return 0;
}

static uint64_t getTimestamp()
{
    uint64_t ts;
#if defined(WIN32) || defined(_WIN32)
    FILETIME ftime;
    GetSystemTimeAsFileTime(&ftime);
    ts = (uint64_t)ftime.dwLowDateTime + ((uint64_t)ftime.dwHighDateTime << 32);
#elif defined(linux) || defined(ANDROID) || defined(__APPLE__)
    timeval tv;
    gettimeofday(&tv, NULL);
    ts = ((uint64_t)tv.tv_sec * 1000000ULL) + (uint64_t)tv_usec;
#else
    ts = 0;
#endif 
    return ts;
}