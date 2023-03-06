#ifndef EncoderDevice_h
#include "EncoderDevice.h"
#endif

mte_status EncoderDevice::callEncoderDevice(MteJail::Algo jailAlgorithm, std::string input, uint64_t nonce, std::string personal, std::string& encodedMessage)
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

  // Output original data.
  std::cout << "Original data: " << input << std::endl;

  // Create the Encoder.
  MteEnc encoder;

  // Create all-zero entropy for this demo. The nonce will also be set to 0.
  // This should never be done in real applications.
  size_t entropyBytes = MteBase::getDrbgsEntropyMinBytes(encoder.getDrbg());
  uint8_t* entropy = new uint8_t[entropyBytes];
  memset(entropy, 0, entropyBytes);

  // Instantiate the Encoder.
  encoder.setEntropy(entropy, entropyBytes);

  // Jailbreak callback
  Cbs cb;
  cb.setAlgo(jailAlgorithm);
  cb.setNonceSeed(nonce);
  encoder.setNonceCallback(&cb);

  status = encoder.instantiate(personal);
  if (status != mte_status_success)
  {
    std::cerr << "Encoder instantiate error (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
    return status;
  }

  // Encode the input.
  encodedMessage = encoder.encodeB64(input, status);
  if (status != mte_status_success)
  {
    std::cerr << "Encode error (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
    return status;
  }



  // Return success.
  return status;

}