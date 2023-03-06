#ifndef DecoderDevice_h
#define DecoderDevice_h
#include "MteDec.h"
#include "MteJail.h"
#include "Cbs.h"
#include <iostream>

class DecoderDevice
{
private:
  mte_status status = mte_status_success;

public:
  mte_status callDecoderDevice(MteJail::Algo jailAlgorithm, std::string encodedInput, uint64_t nonce, std::string personal, std::string& decodedMessage);
};
#endif
