// THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#include "MteEnc.h"
#include "MteDec.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#if defined(_MSC_VER)
#  pragma warning(disable:4996)
#endif

int main(int /*argc*/, char** /*argv*/)
{
    // Status.
    mte_status status;

    // Inputs.
    static const std::string inputs[] =
    {
      "message 0",
      "message 1",
      "message 2",
      "message 3"
    };

    // Personalization string.
    static const std::string personal("demo");

    // Initialize MTE license. If a license code is not required (e.g., trial
    // mode), this can be skipped. This demo attempts to load the license info
    // from the environment if required.
    if (!MteBase::initLicense("YOUR_COMPANY", "YOUR_LICENSE"))
    {
        const char* company = getenv("MTE_COMPANY");
        const char* license = getenv("MTE_LICENSE");
        if (company == NULL || license == NULL ||
            !MteBase::initLicense(company, license))
        {
            std::cerr << "License init error ("
                << MteBase::getStatusName(mte_status_license_error)
                << "): "
                << MteBase::getStatusDescription(mte_status_license_error)
                << std::endl;
            return mte_status_license_error;
        }
    }

    // Create the encoder.
    MteEnc encoder;

    // Create all-zero entropy for this demo. The nonce will also be set to 0.
    // This should never be done in real applications.
    size_t entropyBytes = MteBase::getDrbgsEntropyMinBytes(encoder.getDrbg());
    uint8_t* entropy = new uint8_t[entropyBytes];
    memset(entropy, 0, entropyBytes);

    // Instantiate the encoder.
    encoder.setEntropy(entropy, entropyBytes);
    encoder.setNonce(0);
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

    // Encode the inputs.
    std::vector<std::string> encodings;
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
    {
        const char* encoded = encoder.encodeB64(inputs[i], status);
        if (status != mte_status_success)
        {
            std::cerr << "Encode error ("
                << MteBase::getStatusName(status)
                << "): "
                << MteBase::getStatusDescription(status)
                << std::endl;
            return status;
        }
        encodings.push_back(encoded);
        std::cout << "Encode #" << i << ": " << inputs[i]
            << " -> " << encoded << std::endl;
    }

    // Create decoders with different sequence windows.
    MteDec decoderV(0, 0);
    MteDec decoderF(0, 2);
    MteDec decoderA(0, -2);

    // Instantiate the decoders.
    decoderV.setEntropy(entropy, entropyBytes);
    decoderV.setNonce(0);
    status = decoderV.instantiate(personal);
    if (status == mte_status_success)
    {
        decoderF.setEntropy(entropy, entropyBytes);
        decoderF.setNonce(0);
        status = decoderF.instantiate(personal);
        if (status == mte_status_success)
        {
            decoderA.setEntropy(entropy, entropyBytes);
            decoderA.setNonce(0);
            status = decoderA.instantiate(personal);
        }
    }
    if (status != mte_status_success)
    {
        std::cerr << "Decoder instantiate error ("
            << MteBase::getStatusName(status)
            << "): "
            << MteBase::getStatusDescription(status)
            << std::endl;
        return status;
    }

    // Save the async decoder state.
    size_t stateBytes;
    const void* dsaved = decoderA.saveState(stateBytes);

    // String to decode to.
    std::string decoded;

    // Decode in verification-only mode.
    std::cout << "\nVerification-only mode (sequence window = 0):" << std::endl;
    status = decoderV.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderV.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderV.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderV.decodeB64(encodings[1].c_str(), decoded);
    std::cout << "Decode #1: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderV.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderV.decodeB64(encodings[3].c_str(), decoded);
    std::cout << "Decode #3: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;

    // Decode in forward-only mode.
    std::cout << "\nForward-only mode (sequence window = 2):" << std::endl;
    status = decoderF.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderF.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    ++encodings[2][0];
    status = decoderF.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Corrupt #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    --encodings[2][0];
    status = decoderF.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderF.decodeB64(encodings[1].c_str(), decoded);
    std::cout << "Decode #1: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderF.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderF.decodeB64(encodings[3].c_str(), decoded);
    std::cout << "Decode #3: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;

    // Decode in async mode.
    std::cout << "\nAsync mode (sequence window = -2):" << std::endl;
    status = decoderA.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    ++encodings[2][0];
    status = decoderA.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Corrupt #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    --encodings[2][0];
    status = decoderA.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[1].c_str(), decoded);
    std::cout << "Decode #1: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[3].c_str(), decoded);
    std::cout << "Decode #3: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;

    // Restore and decode again in a different order.
    decoderA.restoreState(dsaved);
    std::cout << "\nAsync mode (sequence window = -2):" << std::endl;
    status = decoderA.decodeB64(encodings[3].c_str(), decoded);
    std::cout << "Decode #3: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[0].c_str(), decoded);
    std::cout << "Decode #0: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[2].c_str(), decoded);
    std::cout << "Decode #2: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;
    status = decoderA.decodeB64(encodings[1].c_str(), decoded);
    std::cout << "Decode #1: " << MteBase::getStatusName(status)
        << ", " << decoded << std::endl;

    // Success.
    delete[] entropy;
    return 0;
}

