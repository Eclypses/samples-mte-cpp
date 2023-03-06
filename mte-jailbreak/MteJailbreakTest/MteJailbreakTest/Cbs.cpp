#ifndef Cbs_h
#include "Cbs.h"
void Cbs::nonceCallback(mte_drbg_nonce_info& info)
{
  // Super.
  MteJail::nonceCallback(info);
}
#endif