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
/* DoubleCRT.cpp - This class holds an integer polynomial in double-CRT form
 *
 * Double-CRT form is a matrix of L rows and phi(m) columns. The i'th row
 * contains the FFT of the element wrt the ith prime, i.e. the evaluations of
 * the polynomial at the primitive mth roots of unity mod the ith prime. The
 * polynomial thus represented is defined modulo the product of all the primes
 * in use. The list of primes is defined by the data member modChain, which is
 * a vector of Cmodulus objects.
 */
#include <NTL/ZZVec.h>
#include <NTL/BasicThreadPool.h>

#include <helib/timing.h>
#include <helib/binio.h>
#include <helib/sample.h>
#include <helib/DoubleCRT.h>
#include <helib/Context.h>
#include <helib/norms.h>
#include <helib/fhe_stats.h>
#include <helib/log.h>

namespace helib {

// A threaded implementation of DoubleCRT operations

static long MakeIndexVector(const IndexSet& s, NTL::Vec<long>& v)
{
  long sz = s.card();
  v.SetLength(sz);
  for (long i = s.first(), j = 0; i <= s.last(); i = s.next(i), j++)
    v[j] = i;
  return sz;
}

// representing an integer polynomial as DoubleCRT. If the number of moduli
// to use is not specified, the resulting object uses all the moduli in
// the context. If the coefficients of poly are larger than the product of
// the used moduli, they are effectively reduced modulo that product

void DoubleCRT::FFT(const NTL::ZZX& poly, const IndexSet& s)
{
  HELIB_TIMER_START;

  if (empty(s))
    return;

  static thread_local NTL::Vec<long> tls_ivec;
  NTL::Vec<long>& ivec = tls_ivec;

  long icard = MakeIndexVector(s, ivec);
  NTL_EXEC_RANGE(icard, first, last)
  for (long j = first; j < last; j++) {
    long i = ivec[j];
    context.ithModulus(i).FFT(map[i], poly);
  }
  NTL_EXEC_RANGE_END
}

// FIXME: "code bloat": this just replicates the above with NTL::ZZX -> zzX
void DoubleCRT::FFT(const zzX& poly, const IndexSet& s)
{
  HELIB_TIMER_START;

  if (empty(s))
    return;

  static thread_local NTL::Vec<long> tls_ivec;
  NTL::Vec<long>& ivec = tls_ivec;

  long icard = MakeIndexVector(s, ivec);
  NTL_EXEC_RANGE(icard, first, last)
  for (long j = first; j < last; j++) {
    long i = ivec[j];
    context.ithModulus(i).FFT(map[i], poly);
  }
  NTL_EXEC_RANGE_END
}

// a "sanity check" function, verifies consistency of matrix with current
// moduli chain an error is raised if they are not consistent
void DoubleCRT::verify()
{
  assertTrue(map.getIndexSet() <= (context.smallPrimes | context.specialPrimes |
                                   context.ctxtPrimes),
             "Index set must be a subset of the union of small primes, special "
             "primes, and ctxt primes");

  const IndexSet& s = map.getIndexSet();

  long phim = context.zMStar.getPhiM();

  // check that the content of i'th row is in [0,pi) for all i
  for (long i : s) {
    NTL::vec_long& row = map[i];

    if (row.length() != phim)
      throw RuntimeError("DoubleCRT object has bad row length");

    long pi = context.ithPrime(i); // the i'th modulus
    for (long j : range(phim))
      if (row[j] < 0 || row[j] >= pi)
        throw RuntimeError("DoubleCRT object has inconsistent data");
  }
}

// Arithmetic operations. Only the "destructive" versions are used,
// i.e., a += b is implemented but not a + b.

// Generic operation, Fnc is AddMod, SubMod, or MulMod (from NTL's ZZ module)
template <typename Fun>
DoubleCRT& DoubleCRT::Op(const DoubleCRT& other, Fun fun, bool matchIndexSets)
{
  if (isDryRun())
    return *this;

  if (&context != &other.context)
    throw RuntimeError("DoubleCRT::Op: incompatible objects");

  // VJS-FIXME: experiment to ignore matchIndexSets
  // Match the index sets, if needed
  if (matchIndexSets && !(map.getIndexSet() >= other.map.getIndexSet())) {
#if 0
    HELIB_NTIMER_START(addPrimes_1);
    Warning("addPrimes called (1) in DoubleCRT::op");
    addPrimes(other.map.getIndexSet() / map.getIndexSet()); // This is expensive
#else
    throw RuntimeError("DoubleCRT::Op: matchIndexSets not honored");
#endif
  }

  // If you need to mod-up the other, do it on a temporary scratch copy
  DoubleCRT tmp(context, IndexSet());
  const IndexMap<NTL::vec_long>* other_map = &other.map;

  // VJS-FIXME: experiment to insist that
  // map.getIndexSet() <= other.map.getIndexSet()
  if (!(map.getIndexSet() <= other.map.getIndexSet())) { // Even more expensive
#if 0
    HELIB_NTIMER_START(addPrimes_2);
    tmp = other;
    Warning("addPrimes called (2) in DoubleCRT::op");
    tmp.addPrimes(map.getIndexSet() / other.map.getIndexSet());
    other_map = &tmp.map;
#else
    throw RuntimeError(
        "DoubleCRT::Op: !(map.getIndexSet() <= other.map.getIndexSet())");
#endif
  }

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  // add/sub/mul the data, element by element, modulo the respective primes
  for (long i : s) {
    long pi = context.ithPrime(i);
    NTL::vec_long& row = map[i];
    const NTL::vec_long& other_row = (*other_map)[i];

    for (long j : range(phim))
      row[j] = fun.apply(row[j], other_row[j], pi);
  }
  return *this;
}

// Victor says: I added this routine so I could look
// examine its performance more carefully

DoubleCRT& DoubleCRT::do_mul(const DoubleCRT& other, bool matchIndexSets)
{
  HELIB_TIMER_START;

  if (isDryRun())
    return *this;

  if (&context != &other.context)
    throw RuntimeError("DoubleCRT::Op: incompatible objects");

  // VJS-FIXME: experiment to ignore matchIndexSets
  // Match the index sets, if needed
  if (matchIndexSets && !(map.getIndexSet() >= other.map.getIndexSet())) {
#if 0
    HELIB_NTIMER_START(addPrimes_3);
    Warning("addPrimes called (1) in DoubleCRT::mul");
    addPrimes(other.map.getIndexSet() / map.getIndexSet()); // This is expensive
#else
    throw RuntimeError("DoubleCRT::mul: matchIndexSets not honored");
#endif
  }

  // If you need to mod-up the other, do it on a temporary scratch copy
  DoubleCRT tmp(context, IndexSet());
  const IndexMap<NTL::vec_long>* other_map = &other.map;

  // VJS-FIXME: experiment to insist that
  // map.getIndexSet() <= other.map.getIndexSet()
  if (!(map.getIndexSet() <= other.map.getIndexSet())) { // Even more expensive
#if 0
    HELIB_NTIMER_START(addPrimes_4);
    tmp = other;
    Warning("addPrimes called (2) in DoubleCRT::mul");
    tmp.addPrimes(map.getIndexSet() / other.map.getIndexSet());
    other_map = &tmp.map;
#else
    throw RuntimeError(
        "DoubleCRT::mul: !(map.getIndexSet() <= other.map.getIndexSet())");
#endif
  }

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  // add/sub/mul the data, element by element, modulo the respective primes
  for (long i : s) {
    long pi = context.ithPrime(i);
    NTL::mulmod_t pi_inv = context.ithModulus(i).getQInv();
    NTL::vec_long& row = map[i];
    const NTL::vec_long& other_row = (*other_map)[i];

    for (long j : range(phim))
      row[j] = MulMod(row[j], other_row[j], pi, pi_inv);
  }
  return *this;
}

#if 0
template
DoubleCRT& DoubleCRT::Op<DoubleCRT::MulFun>(const DoubleCRT &other, MulFun fun,
			 bool matchIndexSets);
#endif

template DoubleCRT& DoubleCRT::Op<DoubleCRT::AddFun>(const DoubleCRT& other,
                                                     AddFun fun,
                                                     bool matchIndexSets);

template DoubleCRT& DoubleCRT::Op<DoubleCRT::SubFun>(const DoubleCRT& other,
                                                     SubFun fun,
                                                     bool matchIndexSets);

template <typename Fun>
DoubleCRT& DoubleCRT::Op(const NTL::ZZ& num, Fun fun)
{
  if (isDryRun())
    return *this;

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  for (long i : s) {
    long pi = context.ithPrime(i);
    long n = rem(num, pi); // n = num % pi
    NTL::vec_long& row = map[i];
    for (long j : range(phim))
      row[j] = fun.apply(row[j], n, pi);
  }
  return *this;
}

template DoubleCRT& DoubleCRT::Op<DoubleCRT::MulFun>(const NTL::ZZ& num,
                                                     MulFun fun);

template DoubleCRT& DoubleCRT::Op<DoubleCRT::AddFun>(const NTL::ZZ& num,
                                                     AddFun fun);

template DoubleCRT& DoubleCRT::Op<DoubleCRT::SubFun>(const NTL::ZZ& num,
                                                     SubFun fun);

DoubleCRT& DoubleCRT::Negate(const DoubleCRT& other)
{
  if (isDryRun())
    return *this;

  if (&context != &other.context)
    throw RuntimeError("DoubleCRT Negate: incompatible contexts");

  if (map.getIndexSet() != other.map.getIndexSet()) {
    map = other.map; // copy the data
  }
  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();
  for (long i : s) {
    long pi = context.ithPrime(i);
    NTL::vec_long& row = map[i];
    const NTL::vec_long& other_row = other.map[i];
    for (long j : range(phim))
      row[j] = NTL::NegateMod(other_row[j], pi);
  }
  return *this;
}

template <typename Fun>
DoubleCRT& DoubleCRT::Op(const NTL::ZZX& poly, Fun fun)
{
  if (isDryRun())
    return *this;

  const IndexSet& s = map.getIndexSet();
  DoubleCRT other(poly, context, s); // other defined wrt same primes as *this

  return Op(other, fun);
}

template DoubleCRT& DoubleCRT::Op<DoubleCRT::MulFun>(const NTL::ZZX& poly,
                                                     MulFun fun);

template DoubleCRT& DoubleCRT::Op<DoubleCRT::AddFun>(const NTL::ZZX& poly,
                                                     AddFun fun);

template DoubleCRT& DoubleCRT::Op<DoubleCRT::SubFun>(const NTL::ZZX& poly,
                                                     SubFun fun);

// break *this into n digits,according to the primeSets in context.digits
// returns the sum of the canonical embedding norms of the digits
NTL::xdouble DoubleCRT::breakIntoDigits(std::vector<DoubleCRT>& digits) const
{
  HELIB_TIMER_START;

  const PAlgebra& palg = context.zMStar;
  long phim = palg.getPhiM();

  IndexSet remainingPrimes = getIndexSet();
  long n = 0;

  for (; !empty(remainingPrimes); n++) {
    IndexSet digitPrimes = context.digits.at(n);
    digitPrimes.retain(remainingPrimes);

    remainingPrimes.remove(context.digits.at(n));
  }
  std::cout << "n: " << n << std::endl;
  IndexSet allPrimes = getIndexSet() | context.specialPrimes;

  assertTrue(getIndexSet() <= context.ctxtPrimes,
             "Index set must be a subset of ctxt primes");
  // the calling routine should ensure that the index set
  // contains only ctxt primes

  assertTrue(n <= (long)context.digits.size(),
             "n cannot be larger than the size of context.digits");

  digits.resize(n, DoubleCRT(context, IndexSet::emptySet()));
  if (isDryRun())
    return NTL::conv<NTL::xdouble>(0.0);

  for (long i : range(n)) {
    digits[i] = *this;
    IndexSet notInDigit = digits[i].getIndexSet() / context.digits[i];
    digits[i].removePrimes(notInDigit); // reduce modulo the digit primes
  }

  NTL::xdouble noise(0.0);

  for (long i : range(digits.size())) {
    HELIB_NTIMER_START(addPrimes_5);
    IndexSet notInDigit = allPrimes / digits[i].getIndexSet();

#if 0
// This version coumputes a high-probability bound

    double digitSize = context.logOfProduct(digits[i].getIndexSet());
    NTL::xdouble norm_bnd =
      context.noiseBoundForUniform( NTL::xexp(digitSize)/2.0, phim );
    noise += norm_bnd;

    digits[i].addPrimes(notInDigit); // add back all the primes

#else
    // This version computes an "exact" value

    double digitSize = context.logOfProduct(digits[i].getIndexSet());
    NTL::xdouble norm_bnd =
        context.noiseBoundForUniform(NTL::xexp(digitSize) / 2.0, phim);

    NTL::ZZX poly;
    digits[i].addPrimes(notInDigit, &poly); // add back all the primes

    HELIB_NTIMER_START(NORM_VAL);
    NTL::xdouble norm_val = embeddingLargestCoeff(poly, palg);
    HELIB_NTIMER_STOP(NORM_VAL);

    noise += norm_val;

    double ratio = NTL::conv<double>(norm_val / norm_bnd);
    HELIB_STATS_UPDATE("break-into-digits-ratio", ratio);

#endif

    NTL::ZZ pi = context.productOfPrimes(context.digits[i]);
    for (long j : range(i + 1, digits.size())) {
      digits[j].Sub(digits[i], /*matchIndexSets=*/false);
      digits[j] /= pi;
    }
  }
  HELIB_TIMER_STOP;

  return noise;
}

// expand index set by s1.
// it is assumed that s1 is disjoint from the current index set.
void DoubleCRT::addPrimes(const IndexSet& s1, NTL::ZZX* poly_p)
{
  HELIB_TIMER_START;

  if (empty(s1)) {
    assertTrue(poly_p == 0, "poly_p must be null here");
    return; // nothing to do
  }
  // s1 is disjoint from *this
  assertTrue(disjoint(s1, map.getIndexSet()),
             "addPrimes can only be called on a disjoint set");

  if (empty(getIndexSet())) { // special case for empty DCRT
    map.insert(s1);           // just add new rows to the map and return
    SetZero();
    if (poly_p)
      clear(*poly_p);
    return;
  }
  NTL::ZZX poly;
  toPoly(poly); // recover in coefficient representation

  if (poly_p)
    *poly_p = poly;

  map.insert(s1); // add new rows to the map
  if (isDryRun())
    return;

  // fill in new rows
  if (deg(poly) <= 0)       // special case for a constant polynomial
    *this = coeff(poly, 0); // no FFT is needed
  else
    FFT(poly, s1);
}

// Expand index set by s1, and multiply by \prod{q \in s1}. s1 is assumed to
// be disjoint from the current index set. Returns the logarithm of product.
double DoubleCRT::addPrimesAndScale(const IndexSet& s1)
{
  if (empty(s1))
    return 0.0; // nothing to do
  // s1 is disjoint from *this
  assertTrue(empty(s1 & map.getIndexSet()),
             "addPrimes can only be called on a disjoint set");

  if (empty(getIndexSet())) { // special case for empty DCRT
    map.insert(s1);           // just add new rows to the map and return
    SetZero();
    return 0.0;
  }
  // compute factor to scale existing rows
  NTL::ZZ factor = NTL::to_ZZ(1);
  double logFactor = 0.0;
  for (long i : s1) {
    long qi = context.ithPrime(i);
    factor *= qi;
    logFactor += log((double)qi);
  }

  // scale existing rows
  long phim = context.zMStar.getPhiM();
  const IndexSet& iSet = map.getIndexSet();
  for (long i : iSet) {
    long qi = context.ithPrime(i);
    long f = rem(factor, qi); // f = factor % qi
    NTL::vec_long& row = map[i];
    // scale row by a factor of f modulo qi
    NTL::mulmod_precon_t bninv = NTL::PrepMulModPrecon(f, qi);
    for (long j : range(phim))
      row[j] = NTL::MulModPrecon(row[j], f, qi, bninv);
  }

  // insert new rows and fill them with zeros
  map.insert(s1); // add new rows to the map
  for (long i : s1) {
    NTL::vec_long& row = map[i];
    for (long j : range(phim))
      row[j] = 0;
  }

  return logFactor;
}

// *****************************************************
DoubleCRTHelper::DoubleCRTHelper(const Context& context)
{
  val = context.zMStar.getPhiM();
}

DoubleCRT::DoubleCRT(const NTL::ZZX& poly,
                     const Context& _context,
                     const IndexSet& s) :
    context(_context), map(new DoubleCRTHelper(_context))
{
  HELIB_TIMER_START;
  assertTrue(s.last() < context.numPrimes(),
             "s must end with a smaller element than context.numPrimes()");

  map.insert(s);
  if (isDryRun())
    return;

  // convert the integer polynomial to FFT representation modulo the primes
  if (deg(poly) <= 0)       // special case for a constant polynomial
    *this = coeff(poly, 0); // no FFT is needed
  else
    FFT(poly, s);
}

// FIXME-IndexSet
#if 0
DoubleCRT::DoubleCRT(const NTL::ZZX& poly, const Context &_context)
: context(_context), map(new DoubleCRTHelper(_context))
{
  HELIB_TIMER_START;
  IndexSet s = IndexSet(0, context.numPrimes()-1);
  // FIXME: maybe the default index set should be determined by context?

  map.insert(s);
  if (isDryRun()) return;

  // convert the integer polynomial to FFT representation modulo the primes
  if (deg(poly)<=0) // special case for a constant polynomial
    *this = coeff(poly,0); // no FFT is needed
  else
    FFT(poly, s);
}

DoubleCRT::DoubleCRT(const NTL::ZZX& poly)
: context(*activeContext), map(new DoubleCRTHelper(*activeContext))
{
  HELIB_TIMER_START;
  IndexSet s = IndexSet(0, context.numPrimes()-1);
  // FIXME: maybe the default index set should be determined by context?

  map.insert(s);
  if (isDryRun()) return;

  // convert the integer polynomial to FFT representation modulo the primes
  if (deg(poly)<=0) // special case for a constant polynomial
    *this = coeff(poly,0); // no FFT is needed
  else
    FFT(poly, s);
}
#endif

// *****************************************************
// FIXME: "code bloat": this just replicates the above with NTL::ZZX -> zzX

DoubleCRT::DoubleCRT(const zzX& poly,
                     const Context& _context,
                     const IndexSet& s) :
    context(_context), map(new DoubleCRTHelper(_context))
{
  HELIB_TIMER_START;
  assertTrue(s.last() < context.numPrimes(),
             "s must end with a smaller element than context.numPrimes()");

  map.insert(s);
  if (isDryRun())
    return;

  // convert the integer polynomial to FFT representation modulo the primes
  if (lsize(poly) <= 1) // special case for a constant polynomial
    *this = (lsize(poly) == 1) ? poly[0] : 0; // no FFT is needed
  else
    FFT(poly, s);
}

// FIXME-IndexSet
#if 0
DoubleCRT::DoubleCRT(const zzX& poly, const Context &_context)
: context(_context), map(new DoubleCRTHelper(_context))
{
  HELIB_TIMER_START;
  IndexSet s = IndexSet(0, context.numPrimes()-1);
  // FIXME: maybe the default index set should be determined by context?

  map.insert(s);
  if (isDryRun()) return;

  // convert the integer polynomial to FFT representation modulo the primes
  // convert the integer polynomial to FFT representation modulo the primes
  if (lsize(poly)<=1) // special case for a constant polynomial
    *this = (lsize(poly)==1)? poly[0] : 0;  // no FFT is needed
  else
    FFT(poly, s);
}

DoubleCRT::DoubleCRT(const zzX& poly)
: context(*activeContext), map(new DoubleCRTHelper(*activeContext))
{
  HELIB_TIMER_START;
  IndexSet s = IndexSet(0, context.numPrimes()-1);
  // FIXME: maybe the default index set should be determined by context?

  map.insert(s);
  if (isDryRun()) return;

  // convert the integer polynomial to FFT representation modulo the primes
  // convert the integer polynomial to FFT representation modulo the primes
  if (lsize(poly)<=1) // special case for a constant polynomial
    *this = (lsize(poly)==1)? poly[0] : 0;  // no FFT is needed
  else
    FFT(poly, s);
}
#endif

DoubleCRT::DoubleCRT(const Context& _context, const IndexSet& s) :
    context(_context), map(new DoubleCRTHelper(_context))
{
  assertTrue(s.last() < context.numPrimes(),
             "s must end with a smaller element than context.numPrimes()");

  map.insert(s);
  if (isDryRun())
    return;

  long phim = context.zMStar.getPhiM();

  for (long i : s) {
    NTL::vec_long& row = map[i];
    for (long j : range(phim))
      row[j] = 0;
  }
}

// *****************************************************

// FIXME-IndexSet
#if 0
DoubleCRT::DoubleCRT(const Context &_context)
: context(_context), map(new DoubleCRTHelper(_context))
{
  IndexSet s = IndexSet(0, context.numPrimes()-1);
  // FIXME: maybe the default index set should be determined by context?

  map.insert(s);
  if (isDryRun()) return;

  long phim = context.zMStar.getPhiM();

  for (long i = s.first(); i <= s.last(); i = s.next(i)) {
    NTL::vec_long& row = map[i];
    for (long j = 0; j < phim; j++) row[j] = 0;
  }
}
#endif

DoubleCRT& DoubleCRT::operator=(const DoubleCRT& other)
// optimized for the case of matching index sets
{
  if (this == &other)
    return *this;

  if (&context != &other.context)
    throw RuntimeError("DoubleCRT assignment: incompatible contexts");

  if (map.getIndexSet() != other.map.getIndexSet()) {
    map = other.map; // copy the data
  } else {
    const IndexSet& s = map.getIndexSet();
    long phim = context.zMStar.getPhiM();
    for (long i : s) {
      NTL::vec_long& row = map[i];
      const NTL::vec_long& other_row = other.map[i];
      for (long j : range(phim))
        row[j] = other_row[j];
    }
  }
  return *this;
}

DoubleCRT& DoubleCRT::operator=(const NTL::ZZX& poly)
{
  if (isDryRun())
    return *this;

  const IndexSet& s = map.getIndexSet();
  if (deg(poly) <= 0)       // special case for a constant polynomial
    *this = coeff(poly, 0); // no FFT is needed
  else
    FFT(poly, s);
  return *this;
}

DoubleCRT& DoubleCRT::operator=(const zzX& poly)
{
  if (isDryRun())
    return *this;

  const IndexSet& s = map.getIndexSet();
  // convert the integer polynomial to FFT representation modulo the primes
  if (lsize(poly) <= 1) // special case for a constant polynomial
    *this = (lsize(poly) == 1) ? poly[0] : 0; // no FFT is needed
  else
    FFT(poly, s);
  return *this;
}

DoubleCRT& DoubleCRT::operator=(const NTL::ZZ& num)
{
  const IndexSet& s = map.getIndexSet();
  if (isDryRun())
    return *this;

  long phim = context.zMStar.getPhiM();

  for (long i : s) {
    NTL::vec_long& row = map[i];
    long pi = context.ithPrime(i);
    long n = rem(num, pi);

    for (long j : range(phim))
      row[j] = n;
  }

  return *this;
}

// DIRT: this method affect the NTL zz_p::modulus
long DoubleCRT::getOneRow(NTL::zz_pX& row, long idx) const
{
  if (!map.getIndexSet().contains(idx)) // idx not in the primeset
    return 0;

  // convert from evaluation to standard coefficient representation
  context.ithModulus(idx).restoreModulus(); // recover NTL modulus for prime
  context.ithModulus(idx).iFFT(row, map[idx]);
  return context.ithPrime(idx);
}

// Get the row corresponding to the i'th moduli, in NTL::Vec<long> format.
// For convenience, returns the modulus that was used for this row.
// If idx is not in the current primesSet then do nothing and return 0;
long DoubleCRT::getOneRow(NTL::Vec<long>& row, long idx, bool positive) const
{
  NTL::zz_pBak bak;
  bak.save(); // backup NTL's current modulus

  NTL::zz_pX& tmp = Cmodulus::getScratch_zz_pX();
  long q = getOneRow(tmp, idx);
  if (q == 0)
    return 0; // no such index

  conv(row, tmp.rep); // copy the row to NTL::Vec<long> format

  // By default, integers are in [0,q).
  // If we need the symmetric interval then make it so.
  if (!positive) {
    long phim = context.zMStar.getPhiM();
    for (long j : range(phim))
      if (row[j] > q / 2)
        row[j] -= q;
  }
  return q;
}

// A parallelizable implementation of toPoly
void DoubleCRT::toPoly(NTL::ZZX& poly, const IndexSet& s, bool positive) const
{
  HELIB_TIMER_START;
  if (isDryRun())
    return;

  IndexSet s1 = map.getIndexSet() & s;
  if (empty(s1)) { // nothing to do
    clear(poly);
    return;
  }

  // To avoid allocating these with every call, they are defined static
  // but thread_local, so concurrent calls to toPoly by multiple threads
  // will have different copies. (tls_ = "Thread-Local Storage")
  static thread_local NTL::Vec<long> tls_ivec;
  static thread_local NTL::Vec<long> tls_pvec;
  static thread_local NTL::Vec<NTL::Vec<long>> tls_remtab;
  static thread_local NTL::Vec<NTL::zz_pX> tls_tmpvec;

  // For readability, call them by names without the tls_
  NTL::Vec<long>& ivec = tls_ivec; // the indexes of the active primes
  // remtab[*][i] = coeffs of tmpvec[i]
  NTL::Vec<NTL::Vec<long>>& remtab = tls_remtab;
  // tmpvec[i] = current poly in i'th thread
  NTL::Vec<NTL::zz_pX>& tmpvec = tls_tmpvec;

  // initialize the ivec vector, ivec[j] = index of j'th active prime
  long phim = context.zMStar.getPhiM();
  long icard = MakeIndexVector(s1, ivec); // icard = how many active primes

  // Which primes are handled by what thread
  NTL::PartitionInfo pinfo(icard); // allocate threads to handle icard primes
  long cnt = pinfo.NumIntervals(); // how many threads are allocated

  // allocate space for all the coefficients modulo all the primes
  remtab.SetLength(phim);
  for (long h : range(phim))
    remtab[h].SetLength(icard);

  // allocate space for the polynomials modulo all the primes
  tmpvec.SetLength(cnt);
  for (long i : range(cnt))
    tmpvec[i].SetMaxLength(phim);

  // Run the inverse FFT modulo the different primes in parallel
  {
    HELIB_NTIMER_START(toPoly_FFT);
    NTL_EXEC_INDEX(cnt, index)
    long first, last;
    pinfo.interval(first, last, index);

    NTL::zz_pX& tmp = tmpvec[index];

    for (long j : range(first, last)) {
      long i = ivec[j];
      context.ithModulus(i).iFFT(tmp, map[i]); // inverse FFT

      long d = deg(tmp); // copy the coefficients, pad by zeros if needed
      for (long h = 0; h <= d; h++)
        remtab[h][j] = rep(tmp.rep[h]);
      for (long h = d + 1; h < phim; h++)
        remtab[h][j] = 0;
    }
    NTL_EXEC_INDEX_END
  } // release space of local variables

  // Run the integer CRT in parallel for the different coefficients
  {
    HELIB_NTIMER_START(toPoly_CRT);
    NTL::PartitionInfo pinfo1(phim);
    long cnt1 = pinfo1.NumIntervals();

    // static thread-local variables to avoid re-allocation
    static thread_local NTL::ZZ tls_prod;
    static thread_local NTL::ZZ tls_prod_half;
    static thread_local NTL::Vec<long> tls_qvec;
    static thread_local NTL::Vec<double> tls_qrecipvec;
    static thread_local NTL::Vec<long> tls_tvec;
    static thread_local NTL::Vec<NTL::mulmod_precon_t> tls_tqinvvec;

    static thread_local NTL::ZZVec tls_prod1vec;
    static thread_local NTL::ZZVec tls_resvec;

    NTL::ZZ& prod = tls_prod;            // product of all the primes
    NTL::ZZ& prod_half = tls_prod_half;  // = (prod+1)/2
    NTL::ZZVec& prod1vec = tls_prod1vec; // prod1vec[i] = prod / qi
    NTL::Vec<long>& qvec = tls_qvec;     // vector of the primes themselves
    NTL::Vec<double>& qrecipvec = tls_qrecipvec; // keeps 1/qi for each prime qi
    NTL::Vec<long>& tvec = tls_tvec; // tvec[i] = (prod / qi)^{-1} mod qi
    // tvec with extra tables
    NTL::Vec<NTL::mulmod_precon_t>& tqinvvec = tls_tqinvvec;
    NTL::ZZVec& resvec = tls_resvec;

    qvec.SetLength(icard);
    qrecipvec.SetLength(icard);
    tvec.SetLength(icard);
    tqinvvec.SetLength(icard);

    // store the primes and reciprocals, and compute their product
    prod = 1;
    for (long j : range(icard)) {
      long i = ivec[j];
      long q = context.ithModulus(i).getQ(); // the prime
      qvec[j] = q;
      qrecipvec[j] = 1 / double(q);
      mul(prod, prod, q);
    }
    long sz = prod.size(); // size of the product

    // reallocate space only if needed
    if (prod1vec.length() != icard || prod1vec.BaseSize() != sz + 1) {
      prod1vec.kill();
      prod1vec.SetSize(icard, sz + 1); // icard integers of size<=sz+1 each
    }

    // compute (prod / qi)^{-1} mod qi
    for (long j : range(icard)) {
      long q = qvec[j];
      div(prod1vec[j], prod, q);
      long t = rem(prod1vec[j], q);
      t = NTL::InvMod(t, q);
      tvec[j] = t;
      tqinvvec[j] = NTL::PrepMulModPrecon(t, q);
    }

    if (resvec.length() != phim || resvec.BaseSize() != sz + 1) {
      resvec.kill();
      resvec.SetSize(phim, sz + 1);
    }

    if (!positive) { // prod_half = (prod+1)/2
      add(prod_half, prod, 1);
      div(prod_half, prod_half, 2);
    }

    // Compute the actual CRT reconstruction
    NTL_EXEC_INDEX(cnt1, index)
    NTL_IMPORT(icard)
    long first, last;
    pinfo1.interval(first, last, index);

    long* qvecp = qvec.elts();
    double* qrecipvecp = qrecipvec.elts();
    long* tvecp = tvec.elts();
    NTL::mulmod_precon_t* tqinvvecp = tqinvvec.elts();
    NTL::ZZ* prod1vecp = prod1vec.elts();

    NTL::ZZ tmp;
    tmp.SetSize(sz + 4);

    for (long h : range(first, last)) { // CRT the h'th coefficient
      clear(tmp);
      double quotient = 0;
      long* remvec = remtab[h].elts();

      for (long j : range(icard)) { // Add one prime at a time
        long q = qvecp[j];
        long t = tvecp[j];
        NTL::mulmod_precon_t tqinv = tqinvvecp[j];
        long r = remvec[j];
        double qrecip = qrecipvecp[j];
        r = NTL::MulModPrecon(r, t, q, tqinv);
        MulAddTo(tmp, prod1vecp[j], r);
        quotient += r * qrecip;
      }
      // reduce modulo prod
      MulSubFrom(tmp, prod, long(quotient));
      while (tmp < 0)
        add(tmp, tmp, prod);
      while (tmp >= prod)
        sub(tmp, tmp, prod);
      // if !positive, reduce to the interval [-prod/2, prod/2]
      if (!positive && tmp >= prod_half)
        tmp -= prod;
      resvec[h] = tmp;
    }
    NTL_EXEC_INDEX_END

    poly.SetLength(phim);
    for (long j : range(phim))
      poly[j] = resvec[j];
    poly.normalize();

    // NOTE: assigning to poly[j] within the parallel loop
    // leads to horrible performance, as there apparently is
    // a lot of contention within malloc.
  }
}

void DoubleCRT::toPoly(NTL::ZZX& p, bool positive) const
{
  const IndexSet& s = map.getIndexSet();
  toPoly(p, s, positive);
}

// Division by constant
DoubleCRT& DoubleCRT::operator/=(const NTL::ZZ& num)
{
  if (isDryRun())
    return *this;

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  for (long i : s) {
    long pi = context.ithPrime(i);
    long n = NTL::InvMod(rem(num, pi), pi); // n = num^{-1} mod pi
    NTL::vec_long& row = map[i];
    NTL::mulmod_precon_t precon = NTL::PrepMulModPrecon(n, pi);
    for (long j : range(phim))
      row[j] = NTL::MulModPrecon(row[j], n, pi, precon);
  }
  return *this;
}

// Small-exponent polynomial exponentiation
void DoubleCRT::Exp(long e)
{
  if (isDryRun())
    return;

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  for (long i : s) {
    long pi = context.ithPrime(i);
    NTL::vec_long& row = map[i];
    for (long j : range(phim))
      row[j] = NTL::PowerMod(row[j], e, pi);
  }
}

// Apply the automorphism F(X) --> F(X^k)  (with gcd(k,m)=1)
#if 1
void DoubleCRT::automorph(long k)
{
  if (isDryRun())
    return;

  const PAlgebra& zMStar = context.zMStar;
  if (!zMStar.inZmStar(k))
    throw RuntimeError("DoubleCRT::automorph: k not in Zm*");

  long m = zMStar.getM();
  long phim = zMStar.getPhiM();
  std::vector<long> tmp(m); // temporary array of size m
  NTL::mulmod_precon_t precon = NTL::PrepMulModPrecon(k, m);

  const IndexSet& s = map.getIndexSet();

  // go over the rows, permute them one at a time
  for (long i : s) {
    NTL::vec_long& row = map[i];

    // Compute new[j] = old[j*k mod m]

    // for (long j=1; j<m; j++) { // 1st pass: copy to temporary array
    //   long idx = zMStar.indexInZmstar_unchecked(j);
    //   if (idx>=0) tmp[j] = row[idx];
    // }
    // for (long j=1; j<m; j++) { // 2nd pass: copy back from temporary array
    //   long idx = zMStar.indexInZmstar_unchecked(j);
    //   if (idx>=0) row[idx] = tmp[NTL::MulModPrecon(j,k,m,precon)];
    //                                        // new[j] = old[j*k mod m]
    // }

    // slightly faster...

    for (long j : range(phim)) { // 1st pass: copy to temporary array
      tmp[zMStar.repInZmstar_unchecked(j)] = row[j];
    }
    for (long j : range(phim)) { // 2nd pass: copy back from temp array
      row[j] =
          tmp[NTL::MulModPrecon(zMStar.repInZmstar_unchecked(j), k, m, precon)];
    }
  }
}

#else
// VJS: I tried this as an alternative...it is slower :-(
void DoubleCRT::automorph(long k)
{
  if (isDryRun())
    return;
  const PAlgebra& zMStar = context.zMStar;
  if (!zMStar.inZmStar(k))
    throw RuntimeError("DoubleCRT::automorph: k not in Zm*");
  long m = zMStar.getM();
  long phim = zMStar.getPhiM();
  std::vector<long> tmp(phim); // temporary array of size m

  k = NTL::InvMod(k, m);
  NTL::mulmod_precon_t precon = NTL::PrepMulModPrecon(k, m);
  const IndexSet& s = map.getIndexSet();

  // go over the rows, permute them one at a time
  // new[j*k mod m] = old[j]
  for (long i = s.first(); i <= s.last(); i = s.next(i)) {
    NTL::vec_long& row = map[i];

    for (long j = 0; j < phim; j++)
      tmp[j] = row[j];

    for (long j = 0; j < phim; j++) {
      long rep = zMStar.repInZmstar_unchecked(j);
      rep = NTL::MulModPrecon(rep, k, m, precon);
      long idx = zMStar.indexInZmstar_unchecked(rep);
      row[idx] = tmp[j];
    }
  }
}
#endif

// Compute the complex conjugate, this is the same as automorph(m-1)
void DoubleCRT::complexConj()
{
  if (isDryRun())
    return;

  const PAlgebra& zMStar = context.zMStar;
  long phim = zMStar.getPhiM();

  const IndexSet& s = map.getIndexSet();

  // go over the rows, permute them one at a time
  for (long i : s) {
    NTL::vec_long& row = map[i];
    for (long j : range(phim / 2)) { // swap i <-> phi(m)-i-1
      std::swap(row[j], row[phim - j - 1]);
    }
  }
}

// fills each row i with random integers mod pi
void DoubleCRT::randomize(const NTL::ZZ* seed)
{
  HELIB_TIMER_START;

  if (isDryRun())
    return;

  if (seed != nullptr)
    SetSeed(*seed);

  const IndexSet& s = map.getIndexSet();
  long phim = context.zMStar.getPhiM();

  NTL::RandomStream& stream = NTL::GetCurrentRandomStream();
  const long bufsz = 2048;

  NTL::Vec<unsigned char> buf_storage;
  buf_storage.SetLength(bufsz);

  unsigned char* buf = buf_storage.elts();

  for (long i : s) {
    long pi = context.ithPrime(i);
    long k = NTL::NumBits(pi - 1);
    long nb = (k + 7) / 8;
    unsigned long mask = (1UL << k) - 1UL;

    NTL::vec_long& row = map[i];
    long j = 0;

    for (;;) {
      {
        HELIB_NTIMER_START(randomize_stream);
        stream.get(buf, bufsz);
      }

      for (long pos = 0; pos <= bufsz - nb; pos += nb) {

        // "Duff's device" used to avoid loops
        // Commented out. Reference of the operation done as loop.
        //  unsigned long utmp = 0;
        //  for (long cnt = nb-1;  cnt >= 0; cnt--)
        //    utmp = (utmp << 8) | buf[pos+cnt];

#if (defined(__GNUC__) || defined(__clang__))
        unsigned long utmp = buf[pos + nb - 1];

        {

          // This is gcc non-standard. Works also on clang and icc.
          // It's only about 2-3% faster than Duff.

          // The pragma below disables the gcc warning temporarily.

#pragma GCC diagnostic push
#ifdef __GNUC__
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-label-as-value"
#else
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#endif
          static void* dispatch_table[] =
              {&&L0, &&L1, &&L2, &&L3, &&L4, &&L5, &&L6, &&L7, &&L8};

          goto* dispatch_table[nb];
#pragma GCC diagnostic pop

        L8:
          utmp = (utmp << 8) | buf[pos + 6];
        L7:
          utmp = (utmp << 8) | buf[pos + 5];
        L6:
          utmp = (utmp << 8) | buf[pos + 4];
        L5:
          utmp = (utmp << 8) | buf[pos + 3];
        L4:
          utmp = (utmp << 8) | buf[pos + 2];
        L3:
          utmp = (utmp << 8) | buf[pos + 1];
        L2:
          utmp = (utmp << 8) | buf[pos + 0];
        L1:;
        L0:;
        }

#else
        // Duff's device about 25% faster
        unsigned long utmp = buf[pos + nb - 1];
        switch (nb) {
        case 8:
          utmp = (utmp << 8) | buf[pos + 6];
        case 7:
          utmp = (utmp << 8) | buf[pos + 5];
        case 6:
          utmp = (utmp << 8) | buf[pos + 4];
        case 5:
          utmp = (utmp << 8) | buf[pos + 3];
        case 4:
          utmp = (utmp << 8) | buf[pos + 2];
        case 3:
          utmp = (utmp << 8) | buf[pos + 1];
        case 2:
          utmp = (utmp << 8) | buf[pos + 0];
        }
#endif

        utmp = (utmp & mask);

        long tmp = utmp;

        row[j] = tmp;
        j += (tmp < pi);
        if (j >= phim)
          break;
      }
      if (j >= phim)
        break;
    }
  }
}

// Coefficients are -1/0/1, Prob[0]=1/2
double DoubleCRT::sampleSmall()
{
  zzX poly;
  // degree-(phi(m)-1) polynomial
  double retval = ::helib::sampleSmall(poly, context);
  *this = poly; // convert to DoubleCRT
  return retval;
}

double DoubleCRT::sampleSmallBounded()
{
  zzX poly;
  // degree-(phi(m)-1) polynomial
  double retval = ::helib::sampleSmallBounded(poly, context);
  *this = poly; // convert to DoubleCRT
  return retval;
}

// Coefficients are -1/0/1 with pre-specified number of nonzeros
double DoubleCRT::sampleHWt(long Hwt)
{
  zzX poly;
  double retval = ::helib::sampleHWt(poly, context, Hwt);
  *this = poly; // convert to DoubleCRT
  return retval;
}

// Coefficients are -1/0/1 with pre-specified number of nonzeros
double DoubleCRT::sampleHWtBounded(long Hwt)
{
  zzX poly;
  double retval = ::helib::sampleHWtBounded(poly, context, Hwt);
  *this = poly; // convert to DoubleCRT
  return retval;
}

// Coefficients are Gaussians
double DoubleCRT::sampleGaussian(double stdev)
{
  if (stdev == 0.0)
    stdev = to_double(context.stdev);
  zzX poly;
  double retval = ::helib::sampleGaussian(poly, context, stdev);
  *this = poly; // convert to DoubleCRT
  return retval;
}

double DoubleCRT::sampleGaussianBounded(double stdev)
{
  if (stdev == 0.0)
    stdev = to_double(context.stdev);
  zzX poly;
  double retval = ::helib::sampleGaussianBounded(poly, context, stdev);
  *this = poly; // convert to DoubleCRT
  return retval;
}

// Coefficients are uniform in [-B..B]

double DoubleCRT::sampleUniform(long B)
{
  zzX poly;
  double retval = ::helib::sampleUniform(poly, context, B);
  *this = poly;
  return retval;
}

NTL::xdouble DoubleCRT::sampleUniform(const NTL::ZZ& B)
{
  NTL::ZZX poly;
  NTL::xdouble retval = ::helib::sampleUniform(poly, context, B);
  *this = poly;
  return retval;
}

void DoubleCRT::scaleDownToSet(const IndexSet& s,
                               long ptxtSpace,
                               NTL::ZZX& delta)
{
  IndexSet diff = getIndexSet() / s;
  if (empty(diff))
    return; // nothing to do

  assertTrue(ptxtSpace >= 1, "ptxtSpace must be at least 1");
  // cannot mod-down to the empty set
  assertNeq(diff,
            getIndexSet(),
            "s and the index set must have some intersection");
  if (isDryRun()) {
    removePrimes(diff); // remove the primes from consideration
    return;
  }

  NTL::ZZ diffProd = context.productOfPrimes(diff); // mod-down by this factor
  toPoly(delta, diff); // convert to coeff-representation modulo diffProd

  if (ptxtSpace > 1) { // make delta divisible by ptxtSpace

    // Need to subtract from each coefficient delta[i] the integer
    //          diffProd * (delta[i] * diffProd^{-1} mod ptxtSpace).
    // This does not change delta modulo diffProd, but makes it
    // divisible by ptxtSpace.
    long p_over_2 = ptxtSpace / 2;
    long p_mod_2 = ptxtSpace % 2;
    long prodInv = NTL::InvMod(rem(diffProd, ptxtSpace), ptxtSpace);

    for (long i : range(delta.rep.length())) {
      long delta_i_modP = rem(delta.rep[i], ptxtSpace);
      if (delta_i_modP != 0) { // if not already 0 mod ptxtSpace
        delta_i_modP = NTL::MulMod(delta_i_modP, prodInv, ptxtSpace);

        // NOTE: this makes sure we get a more truly balanced remainder
        if (delta_i_modP > p_over_2 ||
            (p_mod_2 == 0 && delta_i_modP == p_over_2 &&
             (sign(delta.rep[i]) < 0 ||
              (sign(delta.rep[i]) == 0 && NTL::RandomBnd(2)))))
          delta_i_modP -= ptxtSpace;
        delta.rep[i] -= diffProd * delta_i_modP;
      }
    }

    delta.normalize(); // normalize after working directly on the coeffs
  }
  removePrimes(diff); // remove the primes from consideration
  *this -= delta;     // convert delta to DoubleCRT, then subtract
  *this /= diffProd;  // *this is divisible by diffProd, so this operation
                      // actually scales it down
}

std::ostream& operator<<(std::ostream& str, const DoubleCRT& d)
{
  const IndexSet& set = d.map.getIndexSet();

  // check that the content of i'th row is in [0,pi) for all i
  str << "[" << set << std::endl;
  for (long i : set)
    str << " " << d.map[i] << "\n";
  str << "]";
  return str;
}

std::istream& operator>>(std::istream& str, DoubleCRT& d)
{
  //  std::cerr << "DoubleCRT[";
  // Advance str beyond first '['
  seekPastChar(str, '['); // this function is defined in NumbTh.cpp

  IndexSet set;
  const Context& context = d.context;
  long phim = context.zMStar.getPhiM();

  str >> set; // read in the indexSet
  assertTrue(
      set <= (context.smallPrimes | context.specialPrimes | context.ctxtPrimes),
      "Stream does not contain subset of the context's primes");
  d.map.clear();
  d.map.insert(set); // fix the index set for the data

  for (long i : set) {
    str >> d.map[i]; // read the actual data

    // verify that the data is valid
    assertEq(d.map[i].length(),
             phim,
             "Data not valid: d.map[i].length() != phim");
    for (long j : range(phim))
      assertInRange(
          d.map[i][j],
          0l,
          context.ithPrime(i),
          "d.map[i][j] invalid: must be between 0 and context.ithPrime(i)");
  }

  // Advance str beyond closing ']'
  seekPastChar(str, ']');
  //  std::cerr << "]";
  return str;
}

void DoubleCRT::write(std::ostream& str) const
{
  const IndexSet& set = map.getIndexSet();
  //  std::cerr << "[DCRT::write] set: " << set << std::endl;
  set.write(str);

  for (long i : set) {
    write_ntl_vec_long(str, map[i]);
    //   std::cerr << "[DCRT::write] map[i]: " << map[i] << std::endl;
  }
}

void DoubleCRT::read(std::istream& str)
{
  IndexSet set;
  set.read(str); // read in the indexSet
  map.clear();
  map.insert(set); // fix the index set for the data
                   //  std::cerr << "[DCRT::read] set: " << set << std::endl;

  for (long i : set) {
    read_ntl_vec_long(str, map[i]);
    //   std::cerr << "[DCRT::read] map[i]: " << map[i] << std::endl;
  }
}

} // namespace helib
