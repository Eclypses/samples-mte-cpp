#ifndef EncoderDevice_h
#define EncoderDevice_h
#include "MteEnc.h"
#include "MteJail.h"
#include "Cbs.h"
#include <iostream>

class EncoderDevice
{
private:
  mte_status status = mte_status_success;

public:
  mte_status callEncoderDevice(MteJail::Algo jailAlgorithm, std::string input, uint64_t nonce, std::string personal, std::string &encodedMessage);
};
#endif
