#ifndef Cbs_h
#define Cbs_h
#include "MteJail.h"
#include <cstdint>

class Cbs : public MteJail
{
protected:
  virtual void nonceCallback(mte_drbg_nonce_info& info);
};
#endif