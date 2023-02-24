/* Copyright (C) 2012-2020 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
#include <NTL/BasicThreadPool.h>

#include <helib/binio.h>
#include <helib/timing.h>
#include <helib/Context.h>
#include <helib/Ctxt.h>
#include <helib/keySwitching.h>
#include <helib/CtPtrs.h>
#include <helib/EncryptedArray.h>
#include <helib/Ptxt.h>

#include <helib/debugging.h>
#include <helib/norms.h>
#include <helib/fhe_stats.h>
#include <helib/powerful.h>
#include <helib/log.h>

namespace helib {

extern int fhe_watcher;
static const double safety = 1 * log(2.0); // 1 bits of safety

void SKHandle::read(std::istream& str)
{
  powerOfS = read_raw_int(str);
  powerOfX = read_raw_int(str);
  secretKeyID = read_raw_int(str);
}

void SKHandle::write(std::ostream& str) const
{
  write_raw_int(str, powerOfS);
  write_raw_int(str, powerOfX);
  write_raw_int(str, secretKeyID);
}

// A hack for recording required automorphisms (see NumbTh.h)
std::set<long>* FHEglobals::automorphVals = nullptr;
std::set<long>* FHEglobals::automorphVals2 = nullptr;

// Dummy encryption, just encodes the plaintext in a Ctxt object.
// NOTE: for now, it leaves the intFactor field of *this alone.
// This assumption is relied upon in the reCrypt() and thinReCrypt()
// routines in recryption.cpp.
void Ctxt::DummyEncrypt(const NTL::ZZX& ptxt, double size)
{
  const Context& context = getContext();
  const PAlgebra& zMStar = context.zMStar;

  if (isCKKS()) {
    ptxtSpace = 1;

    if (size < 0)
      size = 1.0;
    ptxtMag = size;
    ratFactor = context.ea->getCx().encodeScalingFactor() / size;
    noiseBound = context.noiseBoundForUniform(0.5, zMStar.getPhiM());
    // noiseBound is a bound on the error during encoding, we assume
    // heuristically that rounding errors are uniform in [-0.5,0.5].
  } else { // BGV
    if (size < 0) {
      // HEURISTIC: we assume that we can safely model the coefficients
      // of ptxt as uniformly and independently distributed over
      // [-magBound, magBound], where magBound = ptxtSpace/2
      noiseBound = context.noiseBoundForMod(ptxtSpace, zMStar.getPhiM());
    } else
      noiseBound = size;
  }

  primeSet = context.ctxtPrimes;

  // A single part, with the plaintext as data and handle pointing to 1

  long f = isCKKS()
               ? 1
               : rem(context.productOfPrimes(context.ctxtPrimes), ptxtSpace);
  if (f == 1) {
    DoubleCRT dcrt(ptxt, context, primeSet);
    parts.assign(1, CtxtPart(dcrt));
  } else {
    NTL::ZZX tmp;
    MulMod(tmp, ptxt, f, ptxtSpace, /*positive=*/false);
    DoubleCRT dcrt(tmp, context, primeSet);
    parts.assign(1, CtxtPart(dcrt));
  }
}

// Sanity-check: Check that prime-set is "valid", i.e. that it
// contains either all the special primes or none of them
bool Ctxt::verifyPrimeSet() const
{
  IndexSet s = primeSet & context.specialPrimes; // special primes in primeSet
  if (!empty(s) && s != context.specialPrimes)
    return false;

  s = primeSet & context.ctxtPrimes; // ctxt primes in primeSet
  return s.isInterval();
}

// Multiply vector of digits by key-switching matrix and add to *this.
// It is assumed that W has at least as many b[i]'s as there are digits.
// The vector of digits is modified in place.
void Ctxt::keySwitchDigits(const KeySwitch& W, std::vector<DoubleCRT>& digits)
{ // An object to hold the pseudorandom ai's, note that it must be defined
  // with the maximum number of levels, else the PRG will go out of sync.
  // FIXME: This is a bug waiting to happen.

 // DoubleCRT ai(context, context.ctxtPrimes | context.specialPrimes);

  // Subsequent ai's use the evolving RNG state
  //RandomState state; // backup the NTL PRG seed
  //NTL::SetSeed(W.prgSeed);

  // Add the columns in, one by one
  DoubleCRT tmpDCRT(context, IndexSet::emptySet());
  for (size_t i = 0; i < digits.size(); i++) {
    HELIB_NTIMER_START(KS_loop);
    //ai.randomize();
    tmpDCRT = digits[i];
    // The operations below all use the IndexSet of tmpDCRT

    // add digit*a[i] with a handle pointing to base of W.toKeyID
    {
      HELIB_NTIMER_START(KS_loop_1);
      tmpDCRT.Mul(W.a[i], /*matchIndexSet=*/false);
    }
    {
      HELIB_NTIMER_START(KS_loop_2);
      this->addPart(tmpDCRT, SKHandle(1, 1, W.toKeyID), /*matchPrimeSet=*/true);
    }
    // add digit*b[i] with a handle pointing to one
    {
      HELIB_NTIMER_START(KS_loop_3);
      digits[i].Mul(W.b[i], /*matchIndexSet=*/false);
    }
    {
      HELIB_NTIMER_START(KS_loop_4);
      this->addPart(digits[i], SKHandle(), /*matchPrimeSet=*/true);
    }
  }
} // restore random state upon destruction of the RandomState, see NumbTh.h

bool CtxtPart::operator==(const CtxtPart& other) const
{
  if (((DoubleCRT&)*this) != ((DoubleCRT&)other))
    return false;

  return (skHandle == other.skHandle);
}

// Checking equality between ciphertexts. This routine performs a
// "shallow" check, comparing only pointers to ciphertext parts.
bool Ctxt::equalsTo(const Ctxt& other, bool comparePkeys) const
{
  if (&context != &other.context)
    return false;
  if (comparePkeys && &pubKey != &other.pubKey)
    return false;

  if (parts.size() != other.parts.size())
    return false;
  for (size_t i = 0; i < parts.size(); i++)
    if (parts[i] != other.parts[i])
      return false;

  if (primeSet != other.primeSet)
    return false;
  if (ptxtSpace != other.ptxtSpace)
    return false;
  if (intFactor != other.intFactor)
    return false;

  // compare ratFactor, ignoring small deviations
  // VJS-FIXME: maybe skip this if not CKKS?
  if (ratFactor == 0.0 && other.ratFactor != 0.0)
    return false;
  NTL::xdouble ratio = other.ratFactor / ratFactor;
  if (ratio < 0.9 && ratio > 1.1)
    return false;

  // compare noiseBound, ignoring small deviations
  if (noiseBound == 0.0)
    return (other.noiseBound == 0.0);
  ratio = other.noiseBound / noiseBound;
  return (ratio > 0.9 && ratio < 1.1);
}

// Constructor
Ctxt::Ctxt(const PubKey& newPubKey, long newPtxtSpace) :
    context(newPubKey.getContext()),
    pubKey(newPubKey),
    ptxtSpace(newPtxtSpace),
    noiseBound(NTL::to_xdouble(0.0))
{
  if (ptxtSpace < 2) {
    ptxtSpace = pubKey.getPtxtSpace();
  } else {
    // sanity check
    assertTrue(NTL::GCD(ptxtSpace, pubKey.getPtxtSpace()) > 1,
               "Ptxt spaces from ciphertext and public key are coprime");
  }
  primeSet = context.ctxtPrimes;
  intFactor = 1;
  ratFactor = ptxtMag = 1.0;
}

// Constructor
Ctxt::Ctxt(ZeroCtxtLike_type, const Ctxt& ctxt) :
    context(ctxt.getPubKey().getContext()),
    pubKey(ctxt.getPubKey()),
    ptxtSpace(ctxt.getPtxtSpace()),
    noiseBound(NTL::to_xdouble(0.0))
{
  // same body as previous constructor
  if (ptxtSpace < 2) {
    ptxtSpace = pubKey.getPtxtSpace();
  } else {
    // sanity check
    assertTrue(NTL::GCD(ptxtSpace, pubKey.getPtxtSpace()) > 1,
               "Ptxt spaces from ciphertext and public key are coprime");
  }
  primeSet = context.ctxtPrimes;
  intFactor = 1;
  ratFactor = ptxtMag = 1.0;
}

// A private assignment method that does not check equality of context or
// public key, this needed for example when we copy the pubEncrKey member
// between different public keys.
Ctxt& Ctxt::privateAssign(const Ctxt& other)
{
  HELIB_TIMER_START;
  if (this == &other)
    return *this; // both point to the same object

  parts = other.parts;
  primeSet = other.primeSet;
  ptxtSpace = other.ptxtSpace;
  noiseBound = other.noiseBound;
  intFactor = other.intFactor;
  ratFactor = other.ratFactor;
  ptxtMag = other.ptxtMag;
  return *this;
}

// explicitly multiply intFactor by e, which should be
// in the interval [0, ptxtSpace)
void Ctxt::mulIntFactor(long e)
{
  if (e == 1)
    return; // nothing to do
  intFactor = NTL::MulMod(intFactor, e, ptxtSpace);
  long bal_e = balRem(e, ptxtSpace);
  for (auto& part : parts)
    part *= bal_e;
  noiseBound *= std::abs(bal_e); // because every part was scaled by bal_e
}

// Ciphertext maintenance

// mod-switch up to add the primes in s \setminus primeSet, after this call we
// have s<=primeSet. s must contain either all special primes or none of them.
void Ctxt::modUpToSet(const IndexSet& s)
{
  IndexSet setDiff =
      s / primeSet; // set minus (primes in s but not in primeSet)
  if (empty(setDiff))
    return; // nothing to do, no primes are added

  // scale up all the parts to use also the primes in setDiff
  double f = 0.0;
  for (long i = 0; i < lsize(parts); i++) {
    // addPrimesAndScale returns the log of the product of added primes,
    // all calls return the same value = log(prod. of primes in setDiff)
    f = parts[i].addPrimesAndScale(setDiff);
  }

  // The noise bound grows by a factor of exp(f)
  noiseBound *= NTL::xexp(f);

  // If CKKS, the rational factor grows by a factor of exp(f)
  ratFactor *= NTL::xexp(f);

  primeSet.insert(setDiff); // add setDiff to primeSet

  // sanity-check: ensure primeSet is still valid
  assertTrue(verifyPrimeSet(), "primeSet is no longer valid");
}

void Ctxt::bringToSet(const IndexSet& s)
{
  auto cap = capacity();
  if (cap < 1) {
    // VJS-FIXME: make this a warning? What are we testing here?
    std::cerr << "Ctxt::bringToSet called with capacity=" << cap
              << ", likely decryption error\n";
  }
  if (empty(s)) { // If empty, use a singleton with 1st ctxt prime
    IndexSet tmp(getContext().ctxtPrimes.first());
    modUpToSet(tmp);
    modDownToSet(tmp);
    if (cap >= 1)
      // VJS-FIXME: make this a warning? What are we testing here?
      std::cerr << "Ctxt::bringToSet called with empty set and capacity=" << cap
                << ", this is likely a bug\n";
  } else {
    modUpToSet(s);
    modDownToSet(s);
  }
}

// mod-switch down to primeSet \intersect s, after this call we have
// primeSet<=s. s must contain either all special primes or none of them.
void Ctxt::modDownToSet(const IndexSet& s)
{
  HELIB_TIMER_START;
  IndexSet intersection = primeSet & s;
  if (empty(intersection)) {
    std::stringstream ss;
    ss << "modDownToSet called from " << primeSet << " to " << s;
    throw RuntimeError(ss.str());
  }
  IndexSet setDiff = primeSet / intersection; // set-minus
  if (empty(setDiff))
    return; // nothing to do, removing no primes

  // Scale down all the parts: use either a simple "drop down" (just removing
  // primes, i.e., reducing the ctxt modulo the smaller modulus), or a "real
  // modulus switching" with rounding, basically whichever yields smaller
  // noise.

  // Get an estimate for the added noise term for modulus switching
  NTL::xdouble addedNoiseBound = modSwitchAddedNoiseBound();

  // For approximate nums, make sure that scaling factor is large enough

  // VJS-FIXME: I'm skeptical that this special processing is
  // a good idea.  It increases the total noise in the ctxt.
  // Generally speaking, all calls to to modDownToSet should
  // anyway be making their own choices.

  if (isCKKS()) {
    // Sanity check: ensuring that we don't lose too much on precision.
    // We check that log(addedNoise) <= log(noiseBound/scaleFactor)-safety,
    // (safety=log 2 defined at top of the file). This ensures that we are
    // losing less than one extra bit of accuracy.
    double logScaledNoise =
        log(noiseBound) - getContext().logOfProduct(setDiff);
    NTL::xdouble xf =
        ceil(NTL::xexp(log(addedNoiseBound) - logScaledNoise + safety));
    if (xf > 1.0) { // need to multiply by an extra factor
      NTL::ZZ factorZZ = NTL::conv<NTL::ZZ>(xf);
      for (auto& part : parts)
        part *= factorZZ;
      noiseBound *= xf; // Increase noiseBound
      ratFactor *= xf;  // Increase the factor
      std::cerr << "** sanity-check triggered in Ctxt::modDownToSet()\n";
      // VJS-FIXME: this should probably be a Warning.
    }
  }

  if (0 && noiseBound <= addedNoiseBound) { // a degenerate "drop down"
    // FIXME: I'm disabling this for now.  It is essentially never
    // invoked and I don't think we have any unit tests that test it.

    for (auto& part : parts)
      part.removePrimes(setDiff); // remove the primes not in s

    // For BGV we keep the invariant that a ciphertext mod Q is
    // decrypted to intFactor*Q*m (mod p), so if we just "drop down" by
    // a factor F we still need to multiply intFactor by (F mod p).
    long F = 1;
    if (ptxtSpace > 1)
      F = rem(context.productOfPrimes(setDiff), ptxtSpace);
    if (F > 1)
      intFactor = NTL::MulMod(intFactor, F, ptxtSpace);
    Warning("Ctxt::modDownToSet: DEGENERATE DROP");
  } else { // do real mod switching
#if 1
    NTL::ZZX delta;
    NTL::ZZ diff = context.productOfPrimes(setDiff);
    NTL::xdouble xdiff = NTL::conv<NTL::xdouble>(diff);

    long nparts = parts.size();

    std::vector<std::vector<double>> fdeltas(nparts);
    for (long i : range(nparts)) {
      CtxtPart& part = parts[i];
      std::vector<double>& fdelta = fdeltas[i];
      part.scaleDownToSet(intersection, ptxtSpace, delta);
      fdelta.resize(delta.rep.length());
      for (long j : range(delta.rep.length())) {
        fdelta[j] =
            NTL::conv<double>(NTL::conv<NTL::xdouble>(delta.rep[j]) / xdiff);

        // sanity check: |fdelta[j]| <= ptxtSpace/2
        if (std::fabs(fdelta[j]) > double(ptxtSpace) / 2.0 + 0.0001) {
          std::stringstream ss;
          ss << "\n***Bad modSwitch: diff =" << std::fabs(fdelta[j])
             << ", ptxtSpace=" << ptxtSpace;
          throw RuntimeError(ss.str());
        }
      }
    }

    std::vector<double> norms(nparts);
    HELIB_NTIMER_START(AAA_modDownEnbeddings);
#if 1
    for (long i : range(nparts / 2)) {
      // compute two for the price of one!
      embeddingLargestCoeff_x2(norms[2 * i],
                               norms[2 * i + 1],
                               fdeltas[2 * i],
                               fdeltas[2 * i + 1],
                               context.zMStar);
    }
    if (nparts % 2) {
      norms[nparts - 1] =
          embeddingLargestCoeff(fdeltas[nparts - 1], context.zMStar);
    }
#else
    for (long i : range(nparts))
      norms[i] = embeddingLargestCoeff(fdeltas[i], context.zMStar);
#endif
    HELIB_NTIMER_STOP(AAA_modDownEnbeddings);

    NTL::xdouble addedNoise(0.0);

    for (long i : range(nparts)) {
      const CtxtPart& part = parts[i];
      double norm = norms[i];

      if (part.skHandle.isOne())
        addedNoise += norm;
      else {
        long keyId = part.skHandle.getSecretKeyID();
        long d = part.skHandle.getPowerOfS();
        NTL::xdouble h = NTL::conv<NTL::xdouble>(pubKey.getSKeyBound(keyId));

        addedNoise += norm * NTL::power(h, d);
      }
    }

    // update the noise estimate
    NTL::xdouble f = NTL::xexp(context.logOfProduct(setDiff));
    ratFactor /= f; // The factor in CKKS encryption
    noiseBound /= f;
    noiseBound += addedNoise;

    double ratio = NTL::conv<double>(addedNoise / addedNoiseBound);

    HELIB_STATS_UPDATE("mod-switch-added-noise", ratio);

    if (addedNoise > addedNoiseBound) {
      Warning("addedNoiseBound too big");
    }

#else
    NTL::ZZX delta;

    for (auto& part : parts) {
      part.scaleDownToSet(intersection, ptxtSpace, delta);
    }

    // update the noise estimate
    NTL::xdouble f = NTL::xexp(context.logOfProduct(setDiff));
    ratFactor /= f; // The factor in CKKS encryption
    noiseBound /= f;
    noiseBound += addedNoiseBound;

#endif
  }
  primeSet.remove(setDiff); // remove the primes not in s

  // sanity-check: ensure primeSet is still valid
  assertTrue(verifyPrimeSet(), "primeSet is no longer valid");
}

void Ctxt::blindCtxt(const NTL::ZZX& poly)
{
  Ctxt tmp(pubKey);
  pubKey.Encrypt(tmp, poly, ptxtSpace, /*highNoise=*/true);
  *this += tmp;
  // FIXME: Need to blind the intFactor too
  // FIXME: highNoise does not work for CKKS
  // FIXME: This implementation is not optimized, the levels in the
  //        modulus chain should be handled much better.
}

// Reduce plaintext space to a divisor of the original plaintext space
void Ctxt::reducePtxtSpace(long newPtxtSpace)
{
  long g = NTL::GCD(ptxtSpace, newPtxtSpace);

  // NOTE: Will trigger an error if called for CKKS ciphertext
  assertTrue(g > 1, "New and old plaintext spaces are coprime");
  ptxtSpace = g;
  intFactor %= g;
}

// Drop sll smallPrimes and specialPrimes, adding ctxtPrimes
// as necessary to ensure that the scaled noise is above the
// modulus-switching added noise term.
void Ctxt::dropSmallAndSpecialPrimes()
{
  if (primeSet.disjointFrom(context.smallPrimes)) {
    // nothing to do except drop the special primes, if any
    modDownToSet(context.ctxtPrimes);
  } else {
    // we will be dropping some smallPrimes, and we need to figure
    // out how much we have to compensate with other ctxtPrimes

    // The target set contains only the ctxtPrimes, and its size
    IndexSet target = primeSet & context.ctxtPrimes;

    // Compute the set of dropped primes and its total size
    IndexSet dropping = primeSet / target;
    double log_dropping = context.logOfProduct(dropping);

    // Below we ensure that the scaled ctxt is not too small
    double log_modswitch_noise = log(modSwitchAddedNoiseBound());
    double log_noise =
        (getNoiseBound() <= 0.0) ? -DBL_MAX : log(getNoiseBound());
    double log_compensation = 0;

    // For CKKS, try to ensure that the scaling factor is at least as large
    // as the mod-switch added noise times a factor of getPPowR()/ptxtMag

    // VJS-FIXME: I'm skeptical that this special-case processing
    // is really a goof idea.  Indeed, the general processing ensures
    // adn < noise/8, and ptxMag is just an *upper bound* on the size
    // of ptx, so it's not clear what this is possibly achieving.
    // That said, the only *harm* in using more ctxtPrimes is performance.

    if (isCKKS()) {
      double log_bound =
          log_modswitch_noise + log(context.alMod.getPPowR()) - log(ptxtMag);
      double log_rf = log(getRatFactor()) // log(factor) after scaling
                      + context.logOfProduct(target) - logOfPrimeSet();
      if (log_rf < log_bound) {
        IndexSet candidates = context.ctxtPrimes / target;
        for (long i : candidates) {
          target.insert(i);
          log_compensation += context.logOfPrime(i);
          if (log_rf + log_compensation >= log_bound)
            break;
        }
      }
    }

    // In either BGV or CKKS, try to ensure that the scaled noise
    // remains not much smaller than the mod-switch added noise.
    // This is done so as not to waste too much capacity.

    // Actually, despite what the above comment says, the following code
    // ensures that the scaled noise remains a bit *larger* than the mod-switch
    // added noise.  However, it seems safer to keep the scaled noise a bit
    // larger than the mod-switch added noise, so this should be fine.

    log_modswitch_noise += 3 * log(2.0); // 3 bits of elbow room
    if (log_noise - log_dropping + log_compensation < log_modswitch_noise) {

      IndexSet candidates = context.ctxtPrimes / target;
      for (long i : candidates) {
        target.insert(i);
        log_compensation += context.logOfPrime(i);
        if (log_noise - log_dropping + log_compensation >= log_modswitch_noise)
          break;
      }
    }

    // Finally mod-switch to the right target set
    bringToSet(target);
  }
}

// key-switch to (1,s_i), s_i is the base key with index keyID. If
// keyID<0 then re-linearize to any key for which a switching matrix exists
void Ctxt::reLinearize(long keyID)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty or already re-linearized then do nothing
  if (this->isEmpty() || this->inCanonicalForm(keyID)) {
    return;
  }
    // this->reduce();

#if 0
  // HERE
  std::cerr << "*** reLinearlize: " << primeSet;
#endif
  //std::cout<<"part[2]:" << parts[2] <<std::endl;
  dropSmallAndSpecialPrimes();

#if 0
  // HERE
  std:: cout
       << " " << primeSet
       << " " <<  (context.logOfProduct(primeSet)/log(2.0))
       << " " <<  (log(noiseBound)/log(2.0))
       << " " <<  (log(modSwitchAddedNoiseBound())/log(2.0))
       << "\n";

#endif
  long g = ptxtSpace;
  double logProd = context.logOfProduct(context.specialPrimes);

  Ctxt tmp(pubKey, ptxtSpace); // an empty ciphertext, same plaintext space
  tmp.intFactor = intFactor;   // same intFactor, too
  tmp.ptxtMag = ptxtMag;       // same CKKS plaintext size
  tmp.noiseBound = noiseBound * NTL::xexp(logProd); // The noise after mod-up
  std::cout << "noiseBound before relinearize" << noiseBound << std::endl;
  tmp.ratFactor = ratFactor * NTL::xexp(logProd); // CKKS factor after mod-up
  // std::cerr << "=== " << ratFactor << tmp.ratFactor << "\n";


  for (CtxtPart& part : parts) {
    // For a part relative to 1 or base,  only scale and add
    
    if (part.skHandle.isOne() || part.skHandle.isBase(keyID)) {
      part.addPrimesAndScale(context.specialPrimes);
      tmp.addPart(part, /*matchPrimeSet=*/true);
      continue;
    }
	
    // Look for a key-switching matrix to re-linearize this part
  
    const KeySwitch& W = (keyID >= 0)
                             ? pubKey.getKeySWmatrix(part.skHandle, keyID)
                             : pubKey.getAnyKeySWmatrix(part.skHandle);

    // verify that a switching matrix exists
    assertTrue(W.toKeyID >= 0, "No key-switching matrix exists");

    if (g > 1) {                    // g==1 for CKKS, g>1 for BGV
      g = NTL::GCD(W.ptxtSpace, g); // verify that the plaintext spaces match
      assertTrue(g > 1, "Plaintext spaces do not match");
      tmp.ptxtSpace = g;
    }
    

    tmp.keySwitchPart(part, W); // switch this part & update noiseBound
  }
  *this = tmp;
  std::cout<< "Noise after Reli : "<< noiseBound <<std::endl;
  dropSmallAndSpecialPrimes();
   //std::cerr << "====== " << ratFactor << "\n";
}

Ctxt& Ctxt::cleanUp()
{
  reLinearize();
  // reduce();
  if (!primeSet.disjointFrom(context.specialPrimes) ||
      !primeSet.disjointFrom(context.smallPrimes)) {
    dropSmallAndSpecialPrimes();
  }
  return *this;
}

// Takes as arguments a key-switching matrix W = W[s'->s] and a
// ciphertext-part p relative to s', uses W to switch p relative to
// (1,s), and adds the and result to *this.
// It is assumed that the part p does not include any of the special
// primes, and that if *this is not an empty ciphertext then its
// primeSet is p.getIndexSet() \union context.specialPrimes
void Ctxt::keySwitchPart(const CtxtPart& p, const KeySwitch& W)
{
  HELIB_TIMER_START;

  // no special primes in the input part
  assertTrue(
      context.specialPrimes.disjointFrom(p.getIndexSet()),
      "Special primes and CtxtPart's index set have non-empty intersection");

  // For parts p that point to 1 or s, only scale and add
  if (p.skHandle.isOne() || p.skHandle.isBase(W.toKeyID)) {
    CtxtPart pp = p;
    pp.addPrimesAndScale(context.specialPrimes);
    addPart(pp, /*matchPrimeSet=*/true);
    return;
  }

  // some sanity checks
  // the handles must match
  assertEq(W.fromKey, p.skHandle, "Secret key handles do not match");

  std::vector<DoubleCRT> polyDigits;
  NTL::xdouble addedNoise = p.breakIntoDigits(polyDigits);
  std::cout<<"Noise of AddNoise:" << addedNoise<<std::endl;
  addedNoise *= W.noiseBound;
  std::cout<<"Noise of W.noiseBound:" << W.noiseBound<<std::endl;

  // Finally we multiply the vector of digits by the key-switching matrix
  keySwitchDigits(W, polyDigits);

  HELIB_STATS_UPDATE("KS-noise-ratio",
                     NTL::conv<double>(addedNoise / noiseBound));
  // HERE
  // fprintf(stderr, "   KS-log-noise-ratio: %f\n",
  // log(addedNoise/noiseBound)/log(2.0));

  noiseBound += addedNoise; // update the noise estimate
  
}

/********************************************************************/
// Ciphertext arithmetic

// Add/subtract a ciphertext part to a ciphertext.
// With negative=true we subtract, otherwise we add.
void Ctxt::addPart(const DoubleCRT& part,
                   const SKHandle& handle,
                   bool matchPrimeSet,
                   bool negative)
{
  HELIB_TIMER_START;

  // VJS-FIXME: the new requirement is that primeSet <= part.getIndexSet()

  assertEq(&part.getContext(), &context, "Context mismatch");

  if (parts.size() == 0) { // inserting 1st part
    primeSet = part.getIndexSet();
    // note that primeSet gets set to part.getIndexSet(),
    // meaning that the value of primeSet for an "empty" ciphertext
    // is irrelevant.

    parts.push_back(CtxtPart(part, handle));
    if (negative)
      parts.back().Negate();
  } else { // adding to a ciphertext with existing parts
    // VJS-FIXME: we are adding this as a new requiremennt
    if (!(primeSet <= part.getIndexSet())) {
#if 0
	 std::cerr << "******** primeSet=" << primeSet
		   << "part.getIndexSet()=" << part.getIndexSet()
		   << "\n";
#endif
      throw RuntimeError("Ctxt::addPart: ctxt has primes not in part");
    }
    if (!(part.getIndexSet() <= primeSet)) {
      // add to the the prime-set of *this, if needed (this is expensive)
      if (matchPrimeSet) {
// VJS-FIXME: matchPrimeSet disabled
#if 0
        IndexSet setDiff = part.getIndexSet() / primeSet; // set minus
        for (size_t i = 0; i < parts.size(); i++) {
          Warning("addPrimes called in addPart");
          parts[i].addPrimes(setDiff);
        }
        primeSet.insert(setDiff);
#else
        throw RuntimeError("Ctxt::addPart: matchPrimeSet not honored");
#endif
      }

// VJS-FIXME: we just ignore extra primes in part
#if 0
      else // this should never happen
        throw LogicError(
            "Ctxt::addPart: part has too many primes and matchPrimeSet==false");
#endif
    }

    DoubleCRT tmp(context, IndexSet::emptySet());
    const DoubleCRT* ptr = &part;

    // mod-UP the part if needed
    // VJS-FIXME: this will never happen
    IndexSet s = primeSet / part.getIndexSet();
    if (!empty(s)) { // if need to mod-UP, do it on a temporary copy
      tmp = part;
      tmp.addPrimesAndScale(s);
      ptr = &tmp;
    }
    long j = getPartIndexByHandle(handle);
    if (j >= 0) { // found a matching part, add them up
      if (negative)
        parts[j].Sub(*ptr, /*matchIndexSets=*/false);
      else
        parts[j].Add(*ptr, /*matchIndexSets=*/false);
    } else { // no matching part found, just append this part
      parts.push_back(CtxtPart(*ptr, handle));
      if (negative)
        parts.back().Negate();
    }
  }
}

// Add a constant polynomial
void Ctxt::addConstant(const DoubleCRT& dcrt, double size)
{
  if (isCKKS()) {
    addConstantCKKS(dcrt, NTL::to_xdouble(size));
    return;
  }

  // FIXME: the other addConstant variants should do the scaling
  // in the plaintext space, so as to not add noise

  // If the size is not given, we use a bound based on the assumption
  // that the coefficients are uniformly and independently distributed
  // over [-ptxtSpace/2, ptxtSpace/2]
  if (size < 0.0)
    size = context.noiseBoundForMod(ptxtSpace, context.zMStar.getPhiM());

  const IndexSet& s = isEmpty() ? dcrt.getIndexSet() : primeSet;
  // If ctxt is empty, addPart will make its prime set equal to that of dcrt

  // Scale the constant, then add it to the part that points to one \B6Գ\A3\CA\FD\BD\F8\D0б\EA\B6ȣ\ACȻ\BA\F3\BD\AB\C6\E4\BCӵ\BDָ\CF\F2һ\B8\F6\B5Ĳ\BF\B7\D6
  long f = 1;
  if (ptxtSpace > 2) {
    f = rem(context.productOfPrimes(s), ptxtSpace);
    f = NTL::MulMod(intFactor, f, ptxtSpace);
    f = balRem(f, ptxtSpace);
  }

  noiseBound += size * std::abs(f);

#if 0

  IndexSet delta = dcrt.getIndexSet() / s;        // set minus
  if (f == 1 && empty(delta)) {                   // just add it
    addPart(dcrt, SKHandle(0, 1, 0));
    return;
  }

  // work with a local copy
  DoubleCRT tmp = dcrt;
  if (!empty(delta))
    tmp.removePrimes(delta);
  if (f != 1)
    tmp *= f;
  addPart(tmp, SKHandle(0, 1, 0));

#else

  // This version insists that if ctxt is non-empty, then
  // the prime set of dcrt contains prime set of ctxt (if ctxt not empty).
  // If not, addPart will raise an exception.
  /*
  \D5\E2\B8\F6\B0汾\BC\E1\B3\D6\C8\E7\B9\FBctxt\CAǷǿյģ\AC\C4\C7ôdcrt\B5\C4\CBؼ\AF\B0\FC\BA\ACctxt\B5\C4\CBؼ\AF(\C8\E7\B9\FBctxt\B2\BB\CAǿյ\C4)\A1\A3\C8\E7\B9\FB\B2\BB\CAǣ\ACaddPart\BB\E1\CC\E1\B3\F6һ\B8\F6\C0\FD\CD⡣
  */

  if (f == 1) {
    addPart(dcrt, SKHandle(0, 1, 0));
  } else {
    // work with a local copy
    DoubleCRT tmp = dcrt;
    tmp *= f;
    addPart(tmp, SKHandle(0, 1, 0));
  }

#endif
}

void Ctxt::addConstant(const NTL::ZZX& poly, double size)
{
  if (size < 0 && !isCKKS()) {
    size = NTL::conv<double>(embeddingLargestCoeff(poly, getContext().zMStar));
  }

  addConstant(DoubleCRT(poly, context, primeSet), size);
}

// Add a constant polynomial
void Ctxt::addConstant(const NTL::ZZ& c)
{
  if (isCKKS()) {
    addConstantCKKS(c);
    return;
  }
  DoubleCRT dcrt(getContext(), getPrimeSet());
  long cc = rem(c, ptxtSpace); // reduce modulo plaintext space
  if (cc > ptxtSpace / 2)
    cc -= ptxtSpace;
  dcrt = cc;

  double size = NTL::to_double(cc);

  addConstant(dcrt, size);
}

// Add a constant polynomial for CKKS encryption. The 'size' argument is
// a bound on the size of the content of the slots. If the factor is not
// specified, we the default PAlgebraModCx::encodeScalingFactor()/size
void addSomePrimes(Ctxt& c);
void Ctxt::addConstantCKKS(const DoubleCRT& dcrt,
                           NTL::xdouble size,
                           NTL::xdouble factor)
{
  // VJS-FIXME: seems complicated...need to understand this better.
  if (size <= 0)
    size = 1.0;

  if (factor <= 0)
    conv(factor, getContext().ea->getCx().encodeScalingFactor() / size);

  // VJS-FIXME: I think we need to special case an empty ciphertext

  NTL::xdouble ratio =
      NTL::floor((ratFactor / factor) + 0.5); // round to integer
  double inaccuracy =
      std::abs(NTL::conv<double>(ratio * factor / ratFactor) - 1.0);

  // Check if you need to scale up to get target accuracy of 2^{-r}
  if ((inaccuracy * getContext().alMod.getPPowR()) > 1.0) {
    Warning("addSomePrimes called in Ctxt::addConstantCKKS(DoubleCRT)");
    addSomePrimes(*this);                      // This increases ratFactor
    ratio = floor((ratFactor / factor) + 0.5); // re-compute the ratio
  }

  // VJS-FIXME: this strategy of adding some primes to offset the
  // rounding error kind of makes it difficult for the caller
  // to ensure that the prime set of scrt contains the prime set
  // of ctxt.  This means we will expand the prime set of dcrt if
  // necessary.

  ptxtMag += size; // perhaps too conservative? size(x+y)<=size(x)+size(y)

  noiseBound += 0.5; // FIXME: what's the noise of a fresh encoding?
  // VJS-FIXME: This can't possibly be right.
  // Shoudn't this be set to encodeRoundingError?
  // Even better, shouldn't we have an optional parameter?
  // Also, in addition to the encode rounding error, we should take
  // into accoung the rounding error introduced by rounding ratio
  // to an integer.
  // Also, the addConstantCKKS routine that takes a complex vector
  // as input should take into account the ratFactor of the given
  // ctxt (if non-empty!) so as to only get a single rounding error.

  NTL::ZZ intRatio = NTL::conv<NTL::ZZ>(ratio);

  // VJS-FIXME: I'm getting rid of this prime dropping logic.
  // Extra primes in dcrt will be ignored in addPart.
#if 0
  IndexSet delta = dcrt.getIndexSet() / getPrimeSet(); // set minus

  if (NTL::IsOne(intRatio) && empty(delta)) { // just add it
    addPart(dcrt, SKHandle(0, 1, 0));
    return;
  }

  // work with a local copy
  DoubleCRT tmp = dcrt;
  if (!empty(delta))
    tmp.removePrimes(delta);

  delta = getPrimeSet() / tmp.getIndexSet(); // set minus
  if (!empty(delta))
    tmp.addPrimes(delta); // that's expensive

  if (!NTL::IsOne(intRatio))
    tmp *= intRatio;
  addPart(tmp, SKHandle(0, 1, 0));
#else

  IndexSet delta = primeSet / dcrt.getIndexSet();
  // VJS-FIXME: we don't want to do this if ctxt was empty,
  // but we have other problems to deal with as well in that case.

  if (NTL::IsOne(intRatio) && empty(delta)) { // just add it
    addPart(dcrt, SKHandle(0, 1, 0));
    return;
  }

  // work with a local copy
  DoubleCRT tmp = dcrt;

  if (!empty(delta))
    tmp.addPrimes(delta);
  // VJS-FIXME: we have to do this here because addPart requires
  // that the prime set of dcrt contains that of ctxt

  if (!NTL::IsOne(intRatio))
    tmp *= intRatio;

  addPart(tmp, SKHandle(0, 1, 0));

#endif
}

void Ctxt::addConstantCKKS(const NTL::ZZX& poly,
                           NTL::xdouble size,
                           NTL::xdouble factor)
{
  // just call the DoubleCRT version
  addConstantCKKS(DoubleCRT(poly, context, primeSet), size, factor);
}

Ctxt& Ctxt::operator+=(const Ptxt<BGV>& other)
{
  addConstant(other.getPolyRepr());
  return *this;
}

Ctxt& Ctxt::operator+=(const Ptxt<CKKS>& other)
{
  addConstantCKKS(other);
  return *this;
}

Ctxt& Ctxt::operator-=(const Ptxt<BGV>& other)
{
  Ptxt<BGV> subtrahend(other);
  subtrahend.negate();
  addConstant(subtrahend.getPolyRepr());
  return *this;
}

Ctxt& Ctxt::operator-=(const Ptxt<CKKS>& other)
{
  Ptxt<CKKS> subtrahend(other);
  subtrahend.negate();
  addConstantCKKS(subtrahend);
  return *this;
}

Ctxt& Ctxt::operator*=(const Ptxt<BGV>& other)
{
  multByConstant(other.getPolyRepr());
  return *this;
}

Ctxt& Ctxt::operator*=(const Ptxt<CKKS>& other)
{
  multByConstantCKKS(other);
  return *this;
}

Ctxt& Ctxt::operator*=(const NTL::ZZX& poly)
{
  if (isCKKS())
    multByConstantCKKS(poly);
  else
    multByConstant(poly);
  return *this;
}

Ctxt& Ctxt::operator*=(const long scalar) { return *this *= NTL::ZZX(scalar); }

void Ctxt::addConstantCKKS(const std::vector<std::complex<double>>& other)
{
  NTL::ZZX poly;
  double factor = getContext().ea->getCx().encode(poly, other);
  // VJS-FIXME: maybe this encdoing routine should also return
  // the rounding error...we kind of need this value

  double size = max_abs(other);

  if (size == 0.0)
    return;

  addConstantCKKS(poly, NTL::xdouble{size}, NTL::xdouble{factor});
}

void Ctxt::addConstantCKKS(const NTL::ZZ& c)
{
  // VJS-FIXME: need to review
  NTL::xdouble xc = NTL::to_xdouble(c);
  NTL::xdouble scaled = floor(ratFactor * xc + 0.5); // scaled up and rounded
  // VJS-FIXME: why round to integer?

  DoubleCRT dcrt(getContext(), getPrimeSet());
  dcrt = to_ZZ(scaled);

  addConstantCKKS(dcrt, /*size=*/xc, /*factor=*/scaled / xc);
}

// Add the rational constant num.first / num.second
void Ctxt::addConstantCKKS(std::pair<long, long> num)
{
  // VJS-FIXME: seems complicated...need to understand this better.
#if 1
  // Check if you need to scale up to get target accuracy of 2^{-r}
  NTL::xdouble xb = NTL::to_xdouble(num.second); // denominator

  NTL::xdouble ratio = floor((ratFactor / xb) + 0.5); // round to integer
  double inaccuracy = std::abs(NTL::conv<double>(ratio * xb / ratFactor) - 1.0);
  if ((inaccuracy * getContext().alMod.getPPowR()) > 1.0) {
    Warning("addSomePrimes called in Ctxt::addConstantCKKS(pair<long,long>");
    addSomePrimes(*this); // This increases ratFactor
  }
  // scaled up and round the numerator
  NTL::xdouble scaled = floor(num.first * ratFactor / xb + 0.5);
  NTL::xdouble& factor = ratFactor;
#else
  // simpler alternative?
  NTL::xdouble scaled = num.first;
  NTL::xdouble factor = num.second;
#endif
  DoubleCRT dcrt(getContext(), getPrimeSet());
  dcrt = to_ZZ(scaled);
  addConstantCKKS(dcrt, /*size=*/scaled / factor, factor);
}

void Ctxt::addConstantCKKS(const Ptxt<CKKS>& ptxt)
{
  addConstantCKKS(ptxt.getSlotRepr());
}

// Add at least one prime to the primeSet of c
void addSomePrimes(Ctxt& c)
{
  const Context& context = c.getContext();
  IndexSet s = c.getPrimeSet();

  // Sanity check: there should be something left to add
  assertNeq(s, context.allPrimes(), "Nothing left to add");

  // Add a ctxt prime if possible
  if (!s.contains(context.ctxtPrimes)) {
    IndexSet delta = context.ctxtPrimes / s; // set minus
    long idx = delta.first();                // We know that |delta| >= 1

    s.insert(idx);
  }
  // else, add a small prime if possible
  else if (!s.contains(context.smallPrimes)) {
    IndexSet delta = context.smallPrimes / s; // set minus
    long idx = delta.first();                 // We know that |delta| >= 1

    s.insert(idx);
  } else // otherwise, insert all the special primes
    s.insert(context.specialPrimes);

  c.modUpToSet(s);
}

void Ctxt::negate()
{
  for (size_t i = 0; i < parts.size(); i++)
    parts[i].Negate();
}

// scale up c1, c2 so they have the same factor
#if 1

static NTL::xdouble calc_err(NTL::xdouble f,
                             NTL::xdouble m1,
                             NTL::xdouble f1,
                             NTL::xdouble e1,
                             NTL::xdouble m2,
                             NTL::xdouble f2,
                             NTL::xdouble e2)
{
  return m1 * NTL::fabs(f1 / f - 1.0) + m2 * NTL::fabs(f2 / f - 1.0) +
         (e1 + e2) / f;
}

// NEW VERSION
void Ctxt::equalizeRationalFactors(Ctxt& c1, Ctxt& c2)
{
  Ctxt& big = (c1.ratFactor > c2.ratFactor) ? c1 : c2;
  Ctxt& small = (c1.ratFactor > c2.ratFactor) ? c2 : c1;

  NTL::xdouble x = big.ratFactor / small.ratFactor;
  long denomBound{c1.getContext().alMod.getPPowR() * 2};

  double epsilon = 0.125 / denomBound;         // "smudge factor"
  NTL::ZZ a = NTL::conv<NTL::ZZ>(x + epsilon); // floor function
  // NOTE: epsilon is meant to counter rounding errors

  NTL::xdouble xi = x - NTL::conv<NTL::xdouble>(a);

  NTL::ZZ prevDenom{0};
  NTL::ZZ denom{1};

  NTL::ZZ numer = NTL::conv<NTL::ZZ>(NTL::conv<NTL::xdouble>(denom) * x + 0.5);

  // in the following big is index 1 and small is index 2
  NTL::xdouble m1 = big.ptxtMag;
  NTL::xdouble of1 = big.ratFactor;
  NTL::xdouble oe1 = big.noiseBound;

  NTL::xdouble m2 = small.ptxtMag;
  NTL::xdouble of2 = small.ratFactor;
  NTL::xdouble oe2 = small.noiseBound;

  NTL::xdouble target_error = oe1 / of1 + oe2 / of2;
  // this is the error (scaled noise) without discretization errors

  NTL::xdouble f, fe1, fe2;
  // f represents the common rat factor we will eventually use for both
  // fe1 represents the eventual noiseBound for big
  // fe2 represents the eventual noiseBound for small

  // Continued fractions: a_{i+1}=floor(1/xi), x_{i+1} = 1/xi - a_{i+1}
  for (;;) {
    // see if we can stop now

    NTL::xdouble xnumer = NTL::conv<NTL::xdouble>(numer);
    NTL::xdouble xdenom = NTL::conv<NTL::xdouble>(denom);

    NTL::xdouble f1 = of1 * xdenom;
    NTL::xdouble e1 = oe1 * xdenom;

    NTL::xdouble f2 = of2 * xnumer;
    NTL::xdouble e2 = oe2 * xnumer;

    // We want to minimize the error (scaled noise) by choosing the optimal
    // value for f, which represents the common rat factor we will
    // eventually use.  Some calculus shows that the optimal value
    // is either f=f1 or f=f2 (the relevant derivative never vanishes),
    // so we just try both.

    NTL::xdouble err1 = calc_err(f1, m1, f1, e1, m2, f2, e2);
    // this is the error (scaled noise) if we use rat factor f = f1
    // for both ciphertexts

    NTL::xdouble err2 = calc_err(f2, m1, f1, e1, m2, f2, e2);
    // this is the error (scaled noise) if we use rat factor f = f2
    // for both ciphertexts

    NTL::xdouble err;

    if (err1 < err2) {
      // use rat factor f = f1
      f = f1;
      fe1 = e1;
      fe2 = e2 + m2 * NTL::fabs(f2 - f1);
      err = err1;
    } else {
      // use rat factor f = f1
      f = f2;
      fe1 = e1 + m1 * NTL::fabs(f2 - f1);
      fe2 = e2;
      err = err2;
    }

    const double thresh = std::sqrt(2.0);
    // this means we could lose half a bit of precision
    // by stopping early

    if (err < thresh * target_error) {
      // std::cerr << "=== err/target_error=" << (err/target_error) << "\n";
      break;
    }
    // close enough...let's stop now to reduce capacity loss at the
    // expense of a little precision

    if (xi <= 0)
      break;

    xi = 1.0 / xi;
    NTL::ZZ ai = NTL::conv<NTL::ZZ>(xi + epsilon); // floor function
    // NOTE: epsilon is meant to counter rounding errors
    xi = xi - NTL::conv<NTL::xdouble>(ai);

    NTL::ZZ tmpDenom = denom * ai + prevDenom;
    if (tmpDenom > denomBound) // bound exceeded: return previous denominator
      break;
    // update denominator
    prevDenom = denom;
    denom = tmpDenom;
    numer = NTL::conv<NTL::ZZ>(NTL::conv<NTL::xdouble>(denom) * x + 0.5);
  }

#if 0

  std::cerr << "***** equalize: " << x << " "
            << numer << " "
            << denom << " "
            << ((x - NTL::conv<NTL::xdouble>(numer)/
                        NTL::conv<NTL::xdouble>(denom))/x) << "\n";
  std::cerr << "   noise before: " << (oe1+oe2) << "=" << oe1 << "+" << oe2 << "\n";
  std::cerr << "   noise after:  " << (fe1+fe2) << "\n";

#endif

  if (denom != 1) {
    for (auto& part : big.parts)
      part *= denom;
  }
  big.ratFactor = f;
  big.noiseBound = fe1;

  if (numer != 1) {
    for (auto& part : small.parts)
      part *= numer;
  }
  small.ratFactor = f;
  small.noiseBound = fe2;
}
#else
void Ctxt::equalizeRationalFactors(Ctxt& c1, Ctxt& c2)
{
  // VJS-FIXME: need to rethink this
  long targetPrecision = c1.getContext().alMod.getPPowR() * 2;
  Ctxt& big = (c1.ratFactor > c2.ratFactor) ? c1 : c2;
  Ctxt& small = (c1.ratFactor > c2.ratFactor) ? c2 : c1;
  NTL::xdouble ratio = big.ratFactor / small.ratFactor;
  std::pair<NTL::ZZ, NTL::ZZ> factors =
      rationalApprox(ratio, NTL::xdouble(targetPrecision));

#if 0

  std::cerr << "***** equalize: " << ratio << " "
            << factors.first << " "
            << factors.second << " "
            << ((ratio - NTL::conv<NTL::xdouble>(factors.first)/
                        NTL::conv<NTL::xdouble>(factors.second))/ratio) << "\n";
  std::cerr << "   noise before: " << (small.noiseBound + big.noiseBound) << "=" << small.noiseBound << "+" << big.noiseBound << "\n";
  std::cerr << "   noise after:  " << (small.noiseBound*NTL::to_xdouble(factors.first) + big.noiseBound*NTL::to_xdouble(factors.second)) << "\n";

#endif

  if (factors.first != 1) {
    for (auto& part : small.parts)
      part *= factors.first;
    small.ratFactor *= NTL::to_xdouble(factors.first);
    small.noiseBound *= NTL::to_xdouble(factors.first);
  }
  if (factors.second != 1) {
    for (auto& part : big.parts)
      part *= factors.second;
    big.ratFactor *= NTL::to_xdouble(factors.second);
    big.noiseBound *= NTL::to_xdouble(factors.second);
  }
}

#endif

static NTL::xdouble NoiseNorm(NTL::xdouble noise1,
                              NTL::xdouble noise2,
                              long e1,
                              long e2,
                              long p)
{
  return noise1 * std::abs(balRem(e1, p)) + noise2 * std::abs(balRem(e2, p));
}

// Add/subtract another ciphertext (depending on the negative flag)
void Ctxt::addCtxt(const Ctxt& other, bool negative)
{
  HELIB_TIMER_START;

  // Sanity check: same context and public key
  assertEq(&context, &other.context, "Context mismatch");
  assertEq(&pubKey, &other.pubKey, "Public key mismatch");

  // std::cerr << "*** " << ratFactor << " " << other.ratFactor << "\n";
  // std::cerr << "*** " << primeSet << " " << other.primeSet << "\n";

  // Special case: if *this is empty then just copy other
  if (this->isEmpty()) {
    *this = other;
    if (negative)
      negate();
    return;
  }

  // Verify that the plaintext spaces are compatible
  if (isCKKS()) {
    assertEq(getPtxtSpace(), 1l, "Plaintext spaces incompatible");
    assertEq(other.getPtxtSpace(), 1l, "Plaintext spaces incompatible");
  } else // BGV
    this->reducePtxtSpace(other.getPtxtSpace());

  const Ctxt* other_pt = &other;

  // make other ptxtSpace match
  Ctxt tmp(pubKey, other.ptxtSpace); // a temporary empty ciphertext
  if (ptxtSpace != other_pt->ptxtSpace) {
    tmp = other;
    tmp.reducePtxtSpace(ptxtSpace);
    other_pt = &tmp;
  }

  // Match the prime-sets, mod-UP the arguments if needed
  IndexSet s = other_pt->primeSet / primeSet; // set-minus
  if (!empty(s))
    modUpToSet(s);

  s = primeSet / other_pt->primeSet; // set-minus
  if (!empty(s)) { // need to mod-UP the other, use a temporary copy
    if (other_pt != &tmp) {
      tmp = other;
      other_pt = &tmp;
    }
    tmp.modUpToSet(s);
  }

  // std::cerr << "*** " << ratFactor << " " << other_pt->ratFactor << "\n";

  // If approximate numbers, make sure the scaling factors are the same
  // VJS-FIXME: I've re-implemented equalizeRationalFactors,
  // and I also call it unconditionally, so as to ensure the
  // noiseBound is actually computed accurately.
  // if (isCKKS() && !closeToOne(ratFactor / other_pt->ratFactor,
  // getContext().alMod.getPPowR() * 2)) {
  if (isCKKS()) {
    if (other_pt != &tmp) {
      tmp = other;
      other_pt = &tmp;
    }
    equalizeRationalFactors(*this, tmp);
  }
  long e1 = 1, e2 = 1;
  if (!isCKKS() && intFactor != other_pt->intFactor) { // harmonize factors
    long f1 = intFactor;
    long f2 = other_pt->intFactor;
    // set e1, e2 so that e1*f1 == e2*f2 (mod ptxtSpace),
    // minimizing the increase in noise.

    // f2/f1 so equivalently, we want e1 = e2*ratio (mod ptxtSpace)
    long ratio = NTL::MulMod(f2, NTL::InvMod(f1, ptxtSpace), ptxtSpace);

    NTL::xdouble noise1 = noiseBound;
    NTL::xdouble noise2 = other_pt->noiseBound;

    // now we run the extended Euclidean on (ptxtSpace, ratio)
    // to generate pairs (r_i, t_i) such that r_i = t_i*ratio (mod ptxtSpace).

    long r0 = ptxtSpace, t0 = 0;
    long r1 = ratio, t1 = 1;

    long e1_best = r1, e2_best = t1;
    NTL::xdouble noise_best =
        NoiseNorm(noise1, noise2, e1_best, e2_best, ptxtSpace);
    long p = context.zMStar.getP();

    while (r1 != 0) {
      long q = r0 / r1;
      long r2 = r0 % r1;
      long t2 = t0 - t1 * q;
      r0 = r1;
      r1 = r2;
      t0 = t1;
      t1 = t2;

      long e1_try = mcMod(r1, ptxtSpace), e2_try = mcMod(t1, ptxtSpace);
      if (e1_try % p != 0) {
        NTL::xdouble noise_try =
            NoiseNorm(noise1, noise2, e1_try, e2_try, ptxtSpace);
        if (noise_try < noise_best) {
          e1_best = e1_try;
          e2_best = e2_try;
          noise_best = noise_try;
        }
      }
    }
    e1 = e1_best;
    e2 = e2_best;

    assertEq(NTL::MulMod(e1, f1, ptxtSpace),
             NTL::MulMod(e2, f2, ptxtSpace),
             "e1f1 not equivalent to e2f2 mod p");
    assertEq(NTL::GCD(e1, ptxtSpace), 1l, "e1 and ptxtSpace not co-prime");
    assertEq(NTL::GCD(e2, ptxtSpace), 1l, "e2 and ptxtSpace not co-prime");
  }

  if (e2 != 1) {
    if (other_pt != &tmp) {
      tmp = other;
      other_pt = &tmp;
    }
    tmp.mulIntFactor(e2);
  }
  if (e1 != 1)
    mulIntFactor(e1);

  // Go over the parts of other, for each one check if
  // there is a matching part in *this
  for (size_t i = 0; i < other_pt->parts.size(); i++) {
    const CtxtPart& part = other_pt->parts[i];
    long j = getPartIndexByHandle(part.skHandle);
    if (j >= 0) { // found a matching part, add them up
      if (negative)
        parts[j] -= part;
      else
        parts[j] += part;
    } else { // no matching part found, just append this part
      parts.push_back(part);
      if (negative)
        parts.back().Negate(); // not thread safe??
    }
  }
  ptxtMag += other_pt->ptxtMag;
  noiseBound += other_pt->noiseBound;
}

// long fhe_disable_intFactor = 0;

// Create a tensor product of c1,c2. It is assumed that *this,c1,c2
// are defined relative to the same set of primes and plaintext space.
// It is also assumed that *this DOES NOT alias neither c1 nor c2.
void Ctxt::tensorProduct(const Ctxt& c1, const Ctxt& c2)
{
  clear();                // clear *this, before we start adding things to it
  primeSet = c1.primeSet; // set the correct prime-set before we begin

  long ptxtSp = c1.getPtxtSpace();

  if (ptxtSp > 2) { // BGV, handle the integer factor
    long q = rem(context.productOfPrimes(c1.getPrimeSet()), ptxtSp);
    intFactor = NTL::MulMod(c1.intFactor, c2.intFactor, ptxtSp);
    intFactor = NTL::MulMod(intFactor, q, ptxtSp);
  }

  // The actual tensoring
  CtxtPart tmpPart(context, IndexSet::emptySet()); // a scratch CtxtPart
  for (long i : range(c1.parts.size())) {
    CtxtPart thisPart = c1.parts[i];

    for (long j : range(c2.parts.size())) {
      tmpPart = c2.parts[j];
      // What secret key will the product point to?
      if (!tmpPart.skHandle.mul(thisPart.skHandle, tmpPart.skHandle))
        throw LogicError(
            "Ctxt::tensorProduct: cannot multiply secret-key handles");

      tmpPart *= thisPart; // The element of the tensor product

      // Check if we already have a part relative to this secret-key handle
      long k = getPartIndexByHandle(tmpPart.skHandle);
      if (k >= 0) // found a matching part
        parts[k] += tmpPart;
      else
        parts.push_back(tmpPart);
    }
  }

  // Compute the noise estimate of the product
  if (isCKKS()) { // we have totalNoiseBound = factor*ptxt + noiseBound
    // VJS-FIXME: this should be computed directly, WITHOUT subtraction
    // In fact, it just seems plain wrong
#if 0
    NTL::xdouble totalNoise1 = c1.ptxtMag * c1.ratFactor + c1.noiseBound;
    NTL::xdouble totalNoise2 = c2.ptxtMag * c2.ratFactor + c2.noiseBound;
    noiseBound = c1.noiseBound * totalNoise2 + c2.noiseBound * totalNoise1 -
                 c1.noiseBound * c2.noiseBound;
#else
    noiseBound = c1.noiseBound * c2.ptxtMag * c2.ratFactor +
                 c2.noiseBound * c1.ptxtMag * c1.ratFactor +
                 c1.noiseBound * c2.noiseBound;
#endif
    ratFactor = c1.ratFactor * c2.ratFactor;
    ptxtMag = c1.ptxtMag * c2.ptxtMag;
  } else // BGV
    noiseBound = c1.noiseBound * c2.noiseBound;
}

void computeIntervalForMul(double& lo,
                           double& hi,
                           const Ctxt& ctxt1,
                           const Ctxt& ctxt2)
{
  const double slack = 4 * log(2.0);
  // FIXME: 4 bits of slack...could be something more dynamic

  double cap1 = ctxt1.capacity();
  double cap2 = ctxt2.capacity();

  double adn1 = log(ctxt1.modSwitchAddedNoiseBound());
  double adn2 = log(ctxt2.modSwitchAddedNoiseBound());
  // The added noise (adn) should be the same for both ciphertexts

  // Compute the interval into which we want to mod-switch.
  // For a given ctxt with modulus q and noise bound n, we want to
  // switch to a new modulus q' s.t. n*q'/q \approx AddedNoiseBound.
  // Taking logs, this is the same as saying that
  // log(q') \approx adn + (log(q) - log(n)) = adn + ctxt.capacity()

  // When we have two ciphertexts, we can e.g., set hi to the minimum
  // for both ciphertexts, and set lo a few bits lower, so that we
  // have some flexibility in finding an efficient dropping strategy.
  // It may be worthwhile to experiment with other strategies for BGV.
  //
  // For CKKS we do the opposite, set lo to the maximum of the two
  // and set hi to a few bits higher. This is done to get good accuracy,
  // setting n*q'/q >> AddedNoiseBound means losing about one bit of
  // accuracy, and going down to n*q'/q = AddedNoiseBound would lose two
  // bits.

  if (ctxt1.isCKKS()) {
    lo = std::max(cap1 + adn1, cap2 + adn2) + safety;
    hi = lo + slack;
  } else { // BGV
    hi = std::min(cap1 + adn1, cap2 + adn2) - safety;
    lo = hi - slack;
  }
}

void computeIntervalForSqr(double& lo, double& hi, const Ctxt& ctxt)
{
  computeIntervalForMul(lo, hi, ctxt, ctxt);
}

double Ctxt::naturalSize() const
// VJS-FIXME: what is this function, really?
// I'm not sure it makes sense...and it does not seem like
// it is really used anywhere
{
  double lo, hi;
  computeIntervalForSqr(lo, hi, *this);
  return isCKKS() ? lo : hi;
}

IndexSet Ctxt::naturalPrimeSet() const
{
  double lo, hi;
  computeIntervalForSqr(lo, hi, *this);

  IndexSet retval = context.modSizes.getSet4Size(lo, hi, primeSet, isCKKS());
  return retval;
}

// This is essentially operator*=, but with an extra parameter
void Ctxt::multLowLvl(const Ctxt& other_orig, bool destructive)
{
  HELIB_TIMER_START;

  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  if (other_orig.isEmpty()) {
    *this = other_orig;
    return;
  }

  assertEq(isCKKS(), other_orig.isCKKS(), "Scheme mismatch");
  assertEq(&context, &other_orig.context, "Context mismatch");
  assertEq(&pubKey, &other_orig.pubKey, "Public key mismatch");
  if (isCKKS()) {
    assertEq(getPtxtSpace(), 1l, "Plaintext spaces incompatible");
    assertEq(other_orig.getPtxtSpace(), 1l, "Plaintext spaces incompatible");
  }

  Ctxt* other_pt = nullptr;
  std::unique_ptr<Ctxt> ct;        // scratch space if needed
  if (this == &other_orig) {       // squaring
    bringToSet(naturalPrimeSet()); // drop to the "natural" primeSet
    other_pt = this;
  } else { // real multiplication
    // If this is a non-destructive call, make a copy of other
    if (destructive)
      other_pt = (Ctxt*)&other_orig;  // cast away const-ness
    else {                            // work with a copy
      ct.reset(new Ctxt(other_orig)); // make a copy
      other_pt = ct.get();            // point to it
    }

    // equalize plaintext spaces
    if (!isCKKS()) {
      long g = NTL::GCD(ptxtSpace, other_pt->ptxtSpace);
      assertTrue(g > 1, "Plaintext spaces are co-prime");
      ptxtSpace = other_pt->ptxtSpace = g;
    }

    // Compute commonPrimeSet, which defines the modulus q of the product

    // To do this, we first compute an interval [lo, hi] in which
    // log(q) should lie in order to properly manage noise growth
    double lo, hi;
    computeIntervalForMul(lo, hi, *this, *other_pt);

    // We then compute commonPrimeSet in a way that minimizes
    // the computational cost of dropping to it
    IndexSet commonPrimeSet = context.modSizes.getSet4Size(lo,
                                                           hi,
                                                           primeSet,
                                                           other_pt->primeSet,
                                                           isCKKS());

    // drop the prime sets of *this and other
    bringToSet(commonPrimeSet);
    other_pt->bringToSet(commonPrimeSet);
  }

  // Perform the actual tensor product
  Ctxt tmpCtxt(pubKey, ptxtSpace);
  tmpCtxt.tensorProduct(*this, *other_pt);
  *this = tmpCtxt;
}

// Higher-level multiply routines that include also modulus-switching
// and re-linearization

void Ctxt::multiplyBy(const Ctxt& other)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  if (other.isEmpty()) {
    *this = other;
    return;
  }

  *this *= other; // perform the multiplication
  //std::cout << "parts[0] before re:" << parts[0] << std::endl;
  //std::cout << "parts[1] before re:" << parts[1] << std::endl;
  //std::cout << "parts[2] before re:" << parts[2] << std::endl;
  //std::cout << "Noise of MultiplyBy :" << this->getNoiseBound();
  reLinearize();  // re-linearize

#ifdef HELIB_DEBUG
  checkNoise(*this, *dbgKey, "reLinearize " + std::to_string(size_t(this)));
#endif
}

void Ctxt::multiplyBy2(const Ctxt& other1, const Ctxt& other2)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  if (other1.isEmpty()) {
    *this = other1;
    return;
  }

  if (other2.isEmpty()) {
    *this = other2;
    return;
  }

  // VJS-FIXME: should these be capacity or "net capacity" in CKKS?
  long cap = capacity();
  long cap1 = other1.capacity();
  long cap2 = other2.capacity();

  if (cap < cap1 && cap < cap2) { // if both others at higher levels than this,
    Ctxt tmp = other1;            // multiply others by each other, then by this
    if (&other1 == &other2)
      tmp *= tmp; // squaring rather than multiplication
    else
      tmp *= other2;

    *this *= tmp;
    reLinearize(); // re-linearize after all the multiplications
    return;
  }

  const Ctxt *first, *second;
  if (cap < cap2 || cap1 < cap2) { // cap1<=cap<cap2 or cap1<=cap,cap2
                                   // multiply by other2, then by other1
    first = &other2;
    second = &other1;
  } else { // multiply first by other1, then by other2
    first = &other1;
    second = &other2;
  }

  if (this == second) { // handle pointer collision
    Ctxt tmp = *second;
    *this *= *first;
    *this *= tmp;
  } else {
    *this *= *first;
    *this *= *second;
  }
  reLinearize(); // re-linearize after all the multiplications
}

#if 1
// Multiply-by-constant
void Ctxt::multByConstant(const NTL::ZZ& c)
{
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;
  HELIB_TIMER_START;

  if (isCKKS()) { // multiply by dividing the scaling factor
    NTL::xdouble size = NTL::fabs(NTL::to_xdouble(c));
    ptxtMag *= size;
    ratFactor /= size;
    if (c < 0)
      this->negate();
    return;
  }

  // BGV

  long c0 = rem(c, ptxtSpace);

  if (c0 == 1)
    return;
  if (c0 == 0) {
    clear();
    return;
  }

  long d = NTL::GCD(c0, ptxtSpace);
  long c1 = c0 / d;
  long c1_inv = NTL::InvMod(c1, ptxtSpace);
  // write c0 = c1 * d, mul ctxt by d, and intFactor by c1_inv

  intFactor = NTL::MulMod(intFactor, c1_inv, ptxtSpace);

  if (d == 1)
    return;

  long cc = balRem(d, ptxtSpace);
  noiseBound *= std::abs(cc);

  // multiply all the parts by this constant
  NTL::ZZ c_copy(cc);
  for (auto& part : parts)
    part *= c_copy;
}
#else
void Ctxt::multByConstant(const NTL::ZZ& c)
{
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;
  HELIB_TIMER_START;

  if (isCKKS()) { // multiply by dividing the scaling factor
    NTL::xdouble size = NTL::fabs(NTL::to_xdouble(c));
    ptxtMag *= size;
    ratFactor /= size;
    if (c < 0)
      this->negate();
    return;
  }
  // for BGV, need to do real multiplication
  long cc = balRem(rem(c, ptxtSpace), ptxtSpace); // reduce modulo ptxt space
  noiseBound *= std::abs(cc);

  // multiply all the parts by this constant
  NTL::ZZ c_copy(cc);
  for (auto& part : parts)
    part *= c_copy;
}

#endif

// Multiply-by-constant, it is assumed that the size of this
// constant fits in a double float
void Ctxt::multByConstant(const DoubleCRT& dcrt, double size)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  if (isCKKS()) {
    multByConstantCKKS(dcrt, NTL::to_xdouble(size));
    // Use default size, factor, encoding-rounding-error
    return;
  }

  // If the size is not given, we use the default value corresponding
  // to uniform distribution on [-ptxtSpace/2, ptxtSpace/2].
  if (size < 0.0) {
    size = context.noiseBoundForMod(ptxtSpace, getContext().zMStar.getPhiM());
  }

  // multiply all the parts by this constant
  for (long i : range(parts.size()))
    parts[i].Mul(dcrt, /*matchIndexSets=*/false);

  noiseBound *= size;
}

void Ctxt::multByConstant(const NTL::ZZX& poly, double size)
{
  HELIB_TIMER_START;
  if (this->isEmpty())
    return;
  if (size < 0 && !isCKKS()) {
    // VJS-FIXME: should this be done also for CKKS?
    size = NTL::conv<double>(embeddingLargestCoeff(poly, getContext().zMStar));
  }
  DoubleCRT dcrt(poly, context, primeSet);
  multByConstant(dcrt, size);
}

void Ctxt::multByConstant(const zzX& poly, double size)
{
  HELIB_TIMER_START;
  if (this->isEmpty())
    return;
  if (size < 0 && !isCKKS()) {
    size = embeddingLargestCoeff(poly, getContext().zMStar);
  }
  DoubleCRT dcrt(poly, context, primeSet);
  multByConstant(dcrt, size);
}

void Ctxt::multByConstantCKKS(const std::vector<std::complex<double>>& other)
{
  // NOTE: some replicated logic here and in addConstantCKKS...
  NTL::ZZX poly;
  double factor = getContext().ea->getCx().encode(poly, other);
  // VJS-FIXME: why does encode with ZZX not require a size arg?

  // VJS-FIXME: This code is reprated...make a function
  double size = max_abs(other);

  // VJS-FIXME: if size==0 we should just do thus->clear()
  if (size == 0.0)
    size = 1.0;

  multByConstantCKKS(poly, NTL::xdouble{size}, NTL::xdouble{factor});
}

void Ctxt::multByConstantCKKS(const DoubleCRT& dcrt,
                              NTL::xdouble size,
                              NTL::xdouble factor,
                              double roundingErr)
{
  // VJS-FIXME: looks reasonable, but still needs review

  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  if (size <= 0) // size is a bound on the magnitude of the slot content
    size = 1.0;

  if (factor <= 0) // if not specified, assume default value
    factor = getContext().ea->getCx().encodeScalingFactor() / size;

  if (roundingErr < 0)
    roundingErr = getContext().ea->getCx().encodeRoundingError();

  // This statement must come first!
  noiseBound = noiseBound * factor * size + roundingErr * ratFactor * ptxtMag +
               noiseBound * roundingErr;

  ptxtMag *= size;
  ratFactor *= factor;

  // multiply all the parts by this constant
  for (auto& part : parts)
    part.Mul(dcrt, /*matchIndexSets=*/false);
}

void Ctxt::multByConstantCKKS(const Ptxt<CKKS>& ptxt)
{
  multByConstantCKKS(ptxt.getSlotRepr());
}

// Divide a ciphertext by 2. It is assumed that the ciphertext
// encrypts an even polynomial and has plaintext space 2^r for r>1.
// As a side-effect, the plaintext space is halved from 2^r to 2^{r-1}
// If these assumptions are not met then the result will not be a
// valid ciphertext anymore.

// FIXME: is this still needed/used?
void Ctxt::divideBy2()
{
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;
  assertEq(ptxtSpace % 2, 0l, "Plaintext space is not even");
  assertTrue(ptxtSpace > 2, "Plaintext space must be greater than 2");

  // multiply all the parts by (productOfPrimes+1)/2
  NTL::ZZ twoInverse; // set to (Q+1)/2
  getContext().productOfPrimes(twoInverse, getPrimeSet());
  twoInverse += 1;
  twoInverse /= 2;
  for (long i : range(parts.size()))
    parts[i] *= twoInverse;

  noiseBound /= 2;        // noise is halved by this operation
  ptxtSpace /= 2;         // and so is the plaintext space
  intFactor %= ptxtSpace; // adjust intFactor
}

// Divide a ciphertext by p, for plaintext space p^r, r>1. It is assumed
// that the ciphertext encrypts a polynomial which is zero mod p. If this
// is not the case then the result will not be a valid ciphertext anymore.
// As a side-effect, the plaintext space is reduced from p^r to p^{r-1}.
void Ctxt::divideByP()
{
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  long p = getContext().zMStar.getP();
  assertEq(ptxtSpace % p, 0l, "p must divide ptxtSpace");
  assertTrue(ptxtSpace > p, "ptxtSpace must be strictly greater than p");

  // multiply all the parts by p^{-1} mod Q (Q=productOfPrimes)
  NTL::ZZ pInverse, Q;
  getContext().productOfPrimes(Q, getPrimeSet());
  NTL::InvMod(pInverse, NTL::conv<NTL::ZZ>(p), Q);
  for (long i : range(parts.size()))
    parts[i] *= pInverse;

  noiseBound /= p;        // noise is reduced by a p factor
  ptxtSpace /= p;         // and so is the plaintext space
  intFactor %= ptxtSpace; // adjust intFactor
}

void Ctxt::automorph(long k) // Apply automorphism F(X)->F(X^k) (gcd(k,m)=1)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  // Sanity check: verify that k \in Zm*
  assertTrue(context.zMStar.inZmStar(k), "k must be in Zm*");
  long m = context.zMStar.getM();

  // Apply this automorphism to all the parts
  for (auto& part : parts) {
    part.automorph(k);
    if (!part.skHandle.isOne()) {
      part.skHandle.powerOfX = NTL::MulMod(part.skHandle.powerOfX, k, m);
    }
  }
  // no change in noise bound
  HELIB_TIMER_STOP;
}
void Ctxt::complexConj() //  Complex conjugate, same as automorph(m-1)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty())
    return;

  // Apply this automorphism to all the parts
  for (auto& part : parts) {
    part.complexConj();
    if (!part.skHandle.isOne()) {
      part.skHandle.powerOfX = context.zMStar.getM() - part.skHandle.powerOfX;
    }
  } // no change in noise bound
}

// Apply F(X)->F(X^k) followed by re-linearization. The automorphism is possibly
// evaluated via a sequence of steps, to ensure that we can re-linearize the
// result of every step.
void Ctxt::smartAutomorph(long k)
{
  HELIB_TIMER_START;

  // A hack: record this automorphism rather than actually performing it
  if (isSetAutomorphVals()) { // defined in NumbTh.h
    recordAutomorphVal(k);
    return;
  }

  // Sanity check: verify that k \in Zm*
  long m = context.zMStar.getM();
  k = mcMod(k, m);

  // Special cases
  if (this->isEmpty() || k == 1)
    return;

  assertTrue(context.zMStar.inZmStar(k), "k must be in Zm*");

  long keyID = getKeyID();
  // must have key-switching matrices for it
  if (!pubKey.isReachable(k, keyID)) {
    throw LogicError("no key-switching matrices for k=" + std::to_string(k) +
                     ", keyID=" + std::to_string(keyID));
  }

  if (!inCanonicalForm(keyID)) { // Re-linearize the input, if needed
    reLinearize(keyID);
    // ensure that re-linearization succeeded
    assertTrue(inCanonicalForm(keyID),
               "Re-linearization failed: not in canonical form");
  }

  while (k != 1) {
    const KeySwitch& matrix = pubKey.getNextKSWmatrix(k, keyID);
    long amt = matrix.fromKey.getPowerOfX();

    // A hack: record this automorphism rather than actually performing it
    if (isSetAutomorphVals2()) { // defined in NumbTh.h
      recordAutomorphVal2(amt);
      return;
    }
    automorph(amt);
    reLinearize(keyID);
    k = NTL::MulMod(k, NTL::InvMod(amt, m), m);
  }
  HELIB_TIMER_STOP;
}

// applies the Frobenius automorphism p^j
void Ctxt::frobeniusAutomorph(long j)
{
  HELIB_TIMER_START;
  // Special case: if *this is empty then do nothing
  if (this->isEmpty() || j == 0)
    return;

  if (isCKKS()) { // For CKKS compute complex conjugate
    if (j & 1)
      complexConj(); // If j is even do nothing
  } else {           // For BGV compute frobenius
    long m = context.zMStar.getM();
    long p = context.zMStar.getP();
    long d = context.zMStar.getOrdP();

    j = mcMod(j, d);
    long val = NTL::PowerMod(p % m, j, m);
    smartAutomorph(val);
  }
}

/********************************************************************/
// Utility methods

long Ctxt::getKeyID() const
{
  for (auto& part : parts)
    if (!part.skHandle.isOne())
      return part.skHandle.getSecretKeyID();

  return 0; // no part pointing to anything, return the default key
}

// Estimates the added noise bound from mod-switching down
NTL::xdouble Ctxt::modSwitchAddedNoiseBound() const
{
  NTL::xdouble addedNoise = NTL::to_xdouble(0.0);

  // incorporate the secret keys' Hamming-weight
  for (auto& part : parts) {
    if (part.skHandle.isOne()) {
      addedNoise += 1.0;
    } else {
      long keyId = part.skHandle.getSecretKeyID();
      long d = part.skHandle.getPowerOfS();
      NTL::xdouble h = NTL::conv<NTL::xdouble>(pubKey.getSKeyBound(keyId));

      addedNoise += NTL::power(h, d);
    }
  }

  double roundingNoise = context.noiseBoundForUniform(double(ptxtSpace) / 2.0,
                                                      context.zMStar.getPhiM());

  return addedNoise * roundingNoise;
}

void Ctxt::write(std::ostream& str) const
{
  writeEyeCatcher(str, BINIO_EYE_CTXT_BEGIN);

  /*  Writing out in binary:
    1.  long ptxtSpace
    2.  NTL::xdouble noiseBound
    3.  IndexSet primeSet;
    4.  std::vector<CtxtPart> parts;
  */

  write_raw_int(str, ptxtSpace);
  write_raw_int(str, intFactor);
  write_raw_xdouble(str, ptxtMag);
  write_raw_xdouble(str, ratFactor);
  write_raw_xdouble(str, noiseBound);
  primeSet.write(str);
  write_raw_vector(str, parts);

  writeEyeCatcher(str, BINIO_EYE_CTXT_END);
}

void Ctxt::read(std::istream& str)
{
  int eyeCatcherFound = readEyeCatcher(str, BINIO_EYE_CTXT_BEGIN);
  assertEq(eyeCatcherFound, 0, "Could not find pre-ciphertext eye catcher");

  ptxtSpace = read_raw_int(str);
  intFactor = read_raw_int(str);
  ptxtMag = read_raw_xdouble(str);
  ratFactor = read_raw_xdouble(str);
  noiseBound = read_raw_xdouble(str);
  primeSet.read(str);
  CtxtPart blankCtxtPart(context, IndexSet::emptySet());
  read_raw_vector(str, parts, blankCtxtPart);

  eyeCatcherFound = readEyeCatcher(str, BINIO_EYE_CTXT_END);
  assertEq(eyeCatcherFound, 0, "Could not find post-ciphertext eye catcher");
}

void CtxtPart::write(std::ostream& str) const
{
  this->DoubleCRT::write(str); // CtxtPart is a child.
  skHandle.write(str);
}

void CtxtPart::read(std::istream& str)
{
  this->DoubleCRT::read(str); // CtxtPart is a child.
  skHandle.read(str);
}

std::istream& operator>>(std::istream& str, SKHandle& handle)
{
  seekPastChar(str, '['); // defined in NumbTh.cpp
  str >> handle.powerOfS;
  str >> handle.powerOfX;
  str >> handle.secretKeyID;
  seekPastChar(str, ']');
  return str;
}

std::ostream& operator<<(std::ostream& str, const CtxtPart& p)
{
  return str << "[" << ((const DoubleCRT&)p) << std::endl << p.skHandle << "]";
}

std::istream& operator>>(std::istream& str, CtxtPart& p)
{
  seekPastChar(str, '['); // defined in NumbTh.cpp
  str >> (DoubleCRT&)p;
  str >> p.skHandle;
  seekPastChar(str, ']');
  return str;
}

std::ostream& operator<<(std::ostream& str, const Ctxt& ctxt)
{
  str << "[" << ctxt.ptxtSpace << " " << ctxt.noiseBound << " " << ctxt.primeSet
      << ctxt.intFactor << " " << ctxt.ptxtMag << " " << ctxt.ratFactor << " "
      << ctxt.parts.size() << std::endl;
  for (auto& part : ctxt.parts)
    str << part << std::endl;
  return str << "]";
}

std::istream& operator>>(std::istream& str, Ctxt& ctxt)
{
  seekPastChar(str, '['); // defined in NumbTh.cpp
  str >> ctxt.ptxtSpace >> ctxt.noiseBound >> ctxt.primeSet >> ctxt.intFactor >>
      ctxt.ptxtMag >> ctxt.ratFactor;
  long nParts;
  str >> nParts;
  ctxt.parts.resize(nParts, CtxtPart(ctxt.context, IndexSet::emptySet()));
  for (auto& part : ctxt.parts) {
    str >> part;
    // sanity-check
    assertEq(
        part.getIndexSet(),
        ctxt.primeSet,
        "Ciphertext part's index set does not match prime set"); // sanity-check
  }
  seekPastChar(str, ']');
  return str;
}

// The recursive incremental-product function that does the actual work
static void recursiveIncrementalProduct(Ctxt array[], long n)
{
  if (n <= 1)
    return; // nothing to do

  // split the array in two, first part is the highest power of two smaller
  // than n and second part is the rest

  long ell = NTL::NumBits(n - 1); // 2^{l-1} <= n-1
  long n1 = 1UL << (ell - 1);     // n/2 <= n1 = 2^l < n

  // Call the recursive procedure separately on the first and second parts
  recursiveIncrementalProduct(array, n1);
  recursiveIncrementalProduct(&array[n1], n - n1);

  // Multiply the last product in the 1st part into every product in the 2nd
  if (n - n1 > 1) {
    NTL_EXEC_RANGE(n - n1, first, last)
    for (long i = n1 + first; i < n1 + last; i++)
      array[i].multiplyBy(array[n1 - 1]);
    NTL_EXEC_RANGE_END
  } else
    for (long i = n1; i < n; i++)
      array[i].multiplyBy(array[n1 - 1]);
}

// For i=n-1...0, set v[i]=prod_{j<=i} v[j]
// This implementation uses depth log n and (nlog n)/2 products
void incrementalProduct(std::vector<Ctxt>& v)
{
  long n = v.size(); // how many ciphertexts do we have
  if (n > 0)
    recursiveIncrementalProduct(&v[0], n); // do the actual work
}

static void recursiveTotalProduct(Ctxt& out, const Ctxt array[], long n)
{
  if (n <= 3) {
    out = array[0];
    if (n == 2)
      out.multiplyBy(array[1]);
    else if (n == 3)
      out.multiplyBy2(array[1], array[2]);
    return;
  }

  // split the array in two

  long ell = NTL::NumBits(n - 1); // 2^{l-1} <= n-1
  long n1 = 1UL << (ell - 1);     // n/2 <= n1 = 2^l < n

  // Call the recursive procedure separately on the first and second parts
  Ctxt out2(ZeroCtxtLike, out);
  recursiveTotalProduct(out, array, n1);
  recursiveTotalProduct(out2, &array[n1], n - n1);

  // Multiply the beginning of the two halves
  out.multiplyBy(out2);
}

// set out=prod_{i=0}^{n-1} v[j], takes depth log n and n-1 products
// out could point to v[0], but having it pointing to any other v[i]
// will make the result unpredictable.
void totalProduct(Ctxt& out, const std::vector<Ctxt>& v)
{
  long n = v.size(); // how many ciphertexts do we have
  if (n > 0)
    recursiveTotalProduct(out, &v[0], n); // do the actual work
}

// Compute the inner product of two vectors of ciphertexts, this routine uses
// the lower-level *= operator and does only one re-linearization at the end.
void innerProduct(Ctxt& result, const CtPtrs& v1, const CtPtrs& v2)
{
  long n = std::min(v1.size(), v2.size());
  if (n <= 0) {
    result.clear();
    return;
  }
  result = *v1[0];
  result *= *v2[0];
  for (long i = 1; i < n; i++) {
    Ctxt tmp = *v1[i];
    tmp *= *v2[i];
    result += tmp;
  }
  result.reLinearize();
}

void innerProduct(Ctxt& result,
                  const std::vector<Ctxt>& v1,
                  const std::vector<Ctxt>& v2)
{
  innerProduct(result,
               CtPtrs_vectorCt((std::vector<Ctxt>&)v1),
               CtPtrs_vectorCt((std::vector<Ctxt>&)v2));
}

// Compute the inner product of a ciphertext vector and a constant vector
void innerProduct(Ctxt& result,
                  const std::vector<Ctxt>& v1,
                  const std::vector<DoubleCRT>& v2)
{
  long n = std::min(v1.size(), v2.size());
  if (n <= 0) {
    result.clear();
    return;
  }
  result = v1[0];
  result.multByConstant(v2[0]);
  for (long i = 1; i < n; i++) {
    Ctxt tmp = v1[i];
    tmp.multByConstant(v2[i]);
    result += tmp;
  }
}

void innerProduct(Ctxt& result,
                  const std::vector<Ctxt>& v1,
                  const std::vector<NTL::ZZX>& v2)
{
  long n = std::min(v1.size(), v2.size());
  if (n <= 0) {
    result.clear();
    return;
  }
  result = v1[0];
  result.multByConstant(v2[0]);
  for (long i = 1; i < n; i++) {
    Ctxt tmp = v1[i];
    tmp.multByConstant(v2[i]);
    result += tmp;
  }
}

// Special-purpose modulus-switching for bootstrapping.
// Mod-switch to an externally-supplied modulus. The modulus need not be in
// the moduli-chain in the context, and does not even need to be a prime.
// The ciphertext *this is not affected, instead the result is returned in
// the zzParts std::vector, as a vector of ZZX'es.
// Returns an estimate for the scaled noise (not including the
// additive mod switching noise)

double Ctxt::rawModSwitch(std::vector<NTL::ZZX>& zzParts, long q) const
{
  // Ensure that new modulus is co-prime with plaintext space
  const long p2r = getPtxtSpace();
  assertTrue<InvalidArgument>(q > 1, "q must be greater than 1");
  assertTrue(p2r > 1,
             "Plaintext space must be greater than 1 for mod switching");
  assertEq(NTL::GCD(q, p2r),
           1l,
           "New modulus and current plaintext space must be co-prime");

  // Compute the ratio between the current modulus and the new one.
  // NOTE: q is a long int, so a double for the logarithms and
  //       NTL::xdouble for the ratio itself is sufficient
  NTL::xdouble ratio =
      NTL::xexp(log((double)q) - context.logOfProduct(getPrimeSet()));

  // Compute also the ratio modulo ptxtSpace
  NTL::ZZ Q = context.productOfPrimes(getPrimeSet());
  NTL::ZZ Q_half = Q / 2;
  long Q_inv_mod_p = NTL::InvMod(rem(Q, p2r), p2r);

  assertTrue(NTL::GCD(rem(Q, q), q) == 1,
             "GCD(Q, q) != 1 in Ctxt::rawModSwitch");
  // This should not trigger, but if it does, we should perhaps
  // modify the code in primeChain.cpp to avoid adding primes in the
  // prime that divide q.  With this assumption, the probabilistic
  // analysis is a bit cleaner

  // Scale and round all the integers in all the parts
  zzParts.resize(parts.size());
  const PowerfulDCRT& p2d_conv = *context.rcData.p2dConv;
  for (long i : range(parts.size())) {

    NTL::Vec<NTL::ZZ> pwrfl;
    p2d_conv.dcrtToPowerful(pwrfl, parts[i]); // convert to powerful rep

    // vecRed(pwrfl, pwrfl, Q, false);
    // reduce to interval [-Q/2,+Q/2]
    // FIXME: it looks like the coefficients should already be reduced

    NTL::ZZ c, X, Y, cq;

    for (long j : range(pwrfl.length())) {
      c = pwrfl[j];
      mul(cq, c, q);
      DivRem(X, Y, cq, Q);
      if (Y > Q_half) {
        sub(Y, Y, Q);
        add(X, X, 1);
      }

      // c*q = Q*X + Y, where X = round(c*q/Q)
      // in other words: c*q/Q = X + Y/Q

      long x = NTL::conv<long>(X);

      long delta = NTL::MulMod(rem(Y, p2r), Q_inv_mod_p, p2r);
      // delta = Y*Q^{-1} mod p^r
      // so we have c*q*Q^{-1} = X + Y*Q^{-1} = x + delta (mod p^r)

      // c' = c*q/Q - Y/Q + delta
      // this logic makes sure that -Y/Q + delta is essentially
      // uniformly distributed over [-p2r/2,p2r/2].

      if (delta > p2r / 2 ||
          (p2r % 2 == 0 && delta == p2r / 2 &&
           ((sign(Y) < 0) || (sign(Y) == 0 && NTL::RandomBnd(2)))))
        delta -= p2r;

      x += delta;

      // sanity check: |c*q/Q - x| <= p^r/2
      NTL::xdouble diff =
          NTL::fabs(NTL::conv<NTL::xdouble>(c) * NTL::conv<NTL::xdouble>(q) /
                        NTL::conv<NTL::xdouble>(Q) -
                    NTL::conv<NTL::xdouble>(x));
      if (diff > NTL::conv<NTL::xdouble>(p2r) / 2.0 + 0.0001) {
        std::stringstream ss;
        ss << "\n***BAD rawModSwitch: diff=" << diff << ", p2r=" << p2r;
        throw RuntimeError(ss.str());
      }

      // reduce symmetrically mod q, randomizing if necessary for even q
      if (x > q / 2 || (q % 2 == 0 && x == q / 2 && NTL::RandomBnd(2)))
        x -= q;
      else if (x < -q / 2 || (q % 2 == 0 && x == -q / 2 && NTL::RandomBnd(2)))
        x += q;

      pwrfl[j] = x; // store back in the powerful vector
    }

    p2d_conv.powerfulToZZX(zzParts[i], pwrfl); // convert to ZZX
  }

  // Return an estimate for the noise
  double scaledNoise = NTL::conv<double>(noiseBound * ratio);

  return scaledNoise;
  // this is returned so that caller in recryption.cpp can check bounds
}

} // namespace helib
