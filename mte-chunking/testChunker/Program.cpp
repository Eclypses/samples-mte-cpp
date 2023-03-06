#include "MteBase.h"
#include "MteMkeEnc.h"
#include "MteMkeDec.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <vector>

int main()
{
  size_t bufferSize = 1024;
  std::string identifier = "mySecretIdentifier";
  mte_status status;

  std::string fPath = "";

  // Prompt for file path.
  std::cout << "Please enter path to file" << std::endl;
  std::getline(std::cin, fPath);

  // Check to make sure file exists.
  std::ifstream inpuFile;
  inpuFile.open(fPath, std::ifstream::in | std::ifstream::binary);
  if (!inpuFile.good())
  {
    std::cerr << "Error opening file." << std::endl;
    return -1;
  }

  std::string encodedFileName = "encodedFile";
  std::string decodedFileName = "decodedFile";
  std::string fExt = "";

  // Get the file extension.
  size_t extIndex = fPath.rfind('.');
  if (extIndex != std::string::npos)
  {
    fExt = fPath.substr(extIndex);
  }

  encodedFileName += fExt;
  decodedFileName += fExt;

  // Check if the encoded file we will create is already there.
  // If present then delete it.
  std::remove(encodedFileName.c_str());
  
  // Create MKE Encoder and Decoder.
  MteMkeEnc encoder;
  MteMkeDec decoder;

  // Check version and output to screen.
  std::string version = MteBase::getVersion();
  std::cout << "Using MTE Version " << version << std::endl;

  // Check the license.If the license code is not required,
  // such as when using trial mode, this can be skipped.
  if (!MteBase::initLicense("YOUR_COMPANY", "YOUR_LICENSE"))
  {
    status = mte_status_license_error;
    std::cerr << "There was an error attempting to initialize the MTE License." << std::endl;
    return status;
  }

  // Check how long entropy we need, set default.
  // Providing Entropy in this fashion is insecure.This is for demonstration
  // purposes onlyand should never be done in practice.
  size_t entropyBytes = MteBase::getDrbgsEntropyMinBytes(encoder.getDrbg());
  uint8_t* entropy = new uint8_t[entropyBytes];
  memset(entropy, '0', entropyBytes);
  encoder.setEntropy(entropy, entropyBytes);
  encoder.setNonce(1);

  //  Initialize the Encoder.
  status = encoder.instantiate(identifier);
  if (status != mte_status_success)
  {
    std::cout << "Encoder instantiate error " << encoder.getStatusName(status) << ": " << encoder.getStatusDescription(status) << std::endl;
    return status;
  }

  // Since entropy is zero'd after using it for the encoder, fill in again.
  // Providing Entropy in this fashion is insecure.This is for demonstration
  // purposes onlyand should never be done in practice.
  entropy = new uint8_t[entropyBytes];
  memset(entropy, '0', entropyBytes);

  // Initialize the Decoder.
  decoder.setEntropy(entropy, entropyBytes);
  decoder.setNonce(1);
  status = decoder.instantiate(identifier);
  if (status != mte_status_success)
  {
    std::cout << "Decoder instantiate error " << decoder.getStatusName(status) << ": " << decoder.getStatusDescription(status) << std::endl;
    return status;
  }

  // Initialize chunking session.
  status = encoder.startEncrypt();
  if (status != mte_status_success)
  {
    std::cout << "MTE Encoder start encrypt error " << encoder.getStatusName(status) << ": " << encoder.getStatusDescription(status) << std::endl;
    return status;
  }

  // Create destination encoded file.
  std::ofstream destination;
  destination.open(encodedFileName, std::ofstream::out | std::ifstream::binary);

  inpuFile.seekg(0, inpuFile.end);
  size_t fileLength = inpuFile.tellg();
  inpuFile.seekg(0, inpuFile.beg);
  size_t amountWritten = 0;
  
  // Iterate through file and write to new location.
  while (amountWritten < fileLength)
  {
    // Create buffer for file parts.
    size_t amountRead = std::min(bufferSize, fileLength - amountWritten);

    std::vector<char> buf(amountRead, 0);
    inpuFile.read(buf.data(), amountRead);

    // Encrypt the chunk.
    status = encoder.encryptChunk(buf.data(), amountRead);
    if (status != mte_status_success)
    {
      std::cout << "Encode error " << encoder.getStatusName(status) << ": " << encoder.getStatusDescription(status) << std::endl;
      return status;
    }

    // Write the encoded bytes to destination.
    destination.write(buf.data(), amountRead);

    amountWritten += amountRead;
  }

  // End of the file reached.
  // Finish the chunking session.
  size_t encodedBytesLen = 0;
  const void* finishEncode = encoder.finishEncrypt(encodedBytesLen, status);
  if (status != mte_status_success)
  {
    std::cout << "Encode finish error " << encoder.getStatusName(status) << ": " << encoder.getStatusDescription(status) << std::endl;
    return status;
  }

  // If there are bytes to write, write them to file.
  if (encodedBytesLen > 0)
  {
    destination.write(static_cast<const char*>(finishEncode), encodedBytesLen);
  }

  destination.close();
  inpuFile.close();

  std::cout << "Finished creating " << encodedFileName << " file." << std::endl;

  // Now read and decode file into new destination.
  std::ifstream fRead;
  fRead.open(encodedFileName, std::ifstream::in | std::ifstream::binary);

  // Check if the decoded file we will create is already there.
  std::remove(decodedFileName.c_str());

  // Initialize decrypt chunking session.
  status = decoder.startDecrypt();
  if (status != mte_status_success)
  {
    std::cout << "MTE Decoder start decrypt error " << decoder.getStatusName(status) << ": " << decoder.getStatusDescription(status) << std::endl;
    return status;
  }

  // Create final destination file.
  std::ofstream finalDestination;
  finalDestination.open(decodedFileName, std::ofstream::out | std::ifstream::binary);

  // Iterate through encoded file and decode.
  amountWritten = 0;
  while (amountWritten < fileLength)
  {
    // Create buffer for file parts.
    size_t amountRead = std::min(bufferSize, fileLength - amountWritten - 1);

    std::vector<char> buf(amountRead, 0);
    fRead.read(buf.data(), amountRead);

    // Decrypt the chunk.
    size_t decodedBytes = 0;
    const void* decoded = decoder.decryptChunk(buf.data(), amountRead, decodedBytes);

    // Write the decoded bytes to destination.
    size_t amountToWrite = amountWritten + decodedBytes < fileLength ? decodedBytes : fileLength - amountWritten;
    amountWritten += amountToWrite;

    // If there is any amount to write, write the decoded bytes to destination.
    if (amountToWrite > 0)
    {
      finalDestination.write(static_cast<const char*>(decoded), amountToWrite);
    }
  }

  // End of file reached. Finish the decryption.
  // Write any remaining bytes to the file.
  size_t decodedBytes = 0;
  const void* finishDecode = decoder.finishDecrypt(decodedBytes, status);
  if (status != mte_status_success)
  {
    std::cout << "Decode finish error " << decoder.getStatusName(status) << ": " << decoder.getStatusDescription(status) << std::endl;
    return status;
  }
  size_t amountToWrite = fileLength - amountWritten;
  if (amountToWrite > 0)
  {
    finalDestination.write(static_cast<const char*>(finishDecode), amountToWrite);
  }

  // Print out success message.
  std::cout << "Finished creating " << decodedFileName << " file." << std::endl;


  // Close the files.
  finalDestination.close();
  fRead.close();

  return 0;

}