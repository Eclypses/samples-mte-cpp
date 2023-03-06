#include "MteJail.h"
#include "EncoderDevice.h"
#include "DecoderDevice.h"
#include <string>

int main()
{
  // Status.
  mte_status status = mte_status_success;

  // Input.
  std::string input = "hello";

  // Personalization string.
  std::string personal = "demo";

  MteJail::Algo mteJailAlgorithm;

  // Nonce.
  int nonce = 123;

  int timesToRun = 2;

  for (int i = 0; i < timesToRun; i++)
  {
    // Use none for the first time.
    // All other times use different algorithm.
    mteJailAlgorithm = i == 0 ? MteJail::aNone : MteJail::aIosX86_64Sim;

    // Call Encoder device.
    EncoderDevice encoder;
    std::string encodedMessage = "";
    mte_status encoderStatus = encoder.callEncoderDevice(mteJailAlgorithm, input, nonce, personal, encodedMessage);
    if (encoderStatus != mte_status_success)
    {
      // Error end.
      return encoderStatus;
    }

    // Display the message.
    std::cout << "Base64 message: " << encodedMessage << std::endl;

    DecoderDevice decoder;
    std::string decodedMessage = "";
    status = decoder.callDecoderDevice(mteJailAlgorithm, encodedMessage, nonce, personal, decodedMessage);
    if (status != mte_status_success)
    {
      // If this specific error happens after first run,
      // we know the Encoder device has been jail broken.
      if (status == mte_status_token_does_not_exist && i > 0)
      {
        std::cerr << "Decode warning (" << MteBase::getStatusName(status) << "): " << MteBase::getStatusDescription(status) << std::endl;
      }
    }

    // Output the decoded data.
    std::cout << "Decoded data: " << decodedMessage << std::endl;

    // Compare the decoded data against the original data.
    if (decodedMessage.compare(input) == 0)
    {
      std::cout << "The original data and decoded data match." << std::endl;
    }
    else
    {
      std::cout << "The original data and decoded DO NOT data match." << std::endl;
      return -1;
    }

  }

  std::cout << "Complete, press enter to end..." << std::endl;
  std::cin.get();

  // Success.
  return 0;
}