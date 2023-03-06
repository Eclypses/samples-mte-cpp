#ifndef DecoderDevice_h
#include "DecoderDevice.h"
#endif

mte_status DecoderDevice::callDecoderDevice(MteJail::Algo jailAlgorithm, std::string encodedInput, uint64_t nonce, std::string personal, std::string& decodedMessage)
{
  // Initialize MTE license. If a license code is not required (e.g., trial
  // mode), this can be skipped. This demo attempts to load the license
  // info from the environment if required.
  if (!MteBase::initLicense("YOUR_COMPANY", "YOUR_LICENSE"))
  {
    status = mte_status_license_error;
    std::cerr << "License initialization error (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
    return status;
  }


  // Create the default Decoder.
  MteDec decoder;

  // Create all-zero entropy for this demo. The nonce will also be set to 0.
  // This should never be done in real applications.
  size_t entropyBytes = MteBase::getDrbgsEntropyMinBytes(decoder.getDrbg());
  uint8_t* entropy = new uint8_t[entropyBytes];
  memset(entropy, 0, entropyBytes);

  // Instantiate the Decoder.
  decoder.setEntropy(entropy, entropyBytes);

  // Set the device type and nonce seed. 
  // Use the jailbreak nonce callback.
  Cbs cb;
  cb.setAlgo(jailAlgorithm);
  cb.setNonceSeed(nonce);
  decoder.setNonceCallback(&cb);

  status = decoder.instantiate(personal);
  if (status != mte_status_success)
  {
    std::cerr << "Decoder instantiate error (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
    return status;
  }

  // Decode the message.
  status = decoder.decodeB64(encodedInput.c_str(), decodedMessage);

  if (decoder.statusIsError(status))
  {
    std::cerr << "Decode error (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
    return status;
  }

  // Return success.
  return status;

}