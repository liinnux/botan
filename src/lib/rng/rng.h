/*
* Random Number Generator base classes
* (C) 1999-2009,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RANDOM_NUMBER_GENERATOR_H__
#define BOTAN_RANDOM_NUMBER_GENERATOR_H__

#include <botan/entropy_src.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <botan/mutex.h>
#include <chrono>
#include <string>

namespace Botan {

class Entropy_Sources;

/**
* An interface to a cryptographic random number generator
*/
class BOTAN_DLL RandomNumberGenerator
   {
   public:
      virtual ~RandomNumberGenerator() = default;

      RandomNumberGenerator() = default;

      /*
      * Never copy a RNG, create a new one
      */
      RandomNumberGenerator(const RandomNumberGenerator& rng) = delete;
      RandomNumberGenerator& operator=(const RandomNumberGenerator& rng) = delete;

      /**
      * Randomize a byte array.
      * @param output the byte array to hold the random output.
      * @param length the length of the byte array output in bytes.
      */
      virtual void randomize(byte output[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state. For
      * example adding nonces or timestamps from a peer's protocol
      * message can help hedge against VM state rollback attacks.
      * A few RNG types do not accept any externally provided input,
      * in which case this function is a no-op.
      *
      * @param input a byte array containg the entropy to be added
      * @param length the length of the byte array in
      */
      virtual void add_entropy(const byte input[], size_t length) = 0;

      /**
      * Incorporate some additional data into the RNG state.
      */
      template<typename T> void add_entropy_T(const T& t)
         {
         this->add_entropy(reinterpret_cast<const uint8_t*>(&t), sizeof(T));
         }

      /**
      * Incorporate entropy into the RNG state then produce output.
      * Some RNG types implement this using a single operation, default
      * calls add_entropy + randomize in sequence.
      *
      * Use this to further bind the outputs to your current
      * process/protocol state. For instance if generating a new key
      * for use in a session, include a session ID or other such
      * value. See NIST SP 800-90 A, B, C series for more ideas.
      *
      * @param output buffer to hold the random output
      * @param output_len size of the output buffer in bytes
      * @param input entropy buffer to incorporate
      * @param input_len size of the input buffer in bytes
      */
      virtual void randomize_with_input(byte output[], size_t output_len,
                                        const byte input[], size_t input_len);

      /**
      * This calls `randomize_with_input` using some timestamps as extra input.
      *
      * For a stateful RNG using non-random but potentially unique data the
      * extra input can help protect against problems with fork, VM state
      * rollback, or other cases where somehow an RNG state is duplicated. If
      * both of the duplicated RNG states later incorporate a timestamp (and the
      * timestamps don't themselves repeat), their outputs will diverge.
      */
      virtual void randomize_with_ts_input(byte output[], size_t output_len);

      /**
      * @return the name of this RNG type
      */
      virtual std::string name() const = 0;

      /**
      * Clear all internally held values of this RNG
      * @post is_seeded() == false
      */
      virtual void clear() = 0;

      /**
      * Check whether this RNG is seeded.
      * @return true if this RNG was already seeded, false otherwise.
      */
      virtual bool is_seeded() const = 0;

      /**
      * Poll provided sources for up to poll_bits bits of entropy
      * or until the timeout expires. Returns estimate of the number
      * of bits collected.
      */
      virtual size_t reseed(Entropy_Sources& srcs,
                            size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                            std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);

      /**
      * Reseed by reading specified bits from the RNG
      */
      virtual void reseed_from_rng(RandomNumberGenerator& rng,
                                   size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS);

      // Some utility functions built on the interface above:

      /**
      * Return a random vector
      * @param bytes number of bytes in the result
      * @return randomized vector of length bytes
      */
      secure_vector<byte> random_vec(size_t bytes)
         {
         secure_vector<byte> output(bytes);
         this->randomize(output.data(), output.size());
         return output;
         }

      /**
      * Return a random byte
      * @return random byte
      */
      byte next_byte()
         {
         byte b;
         this->randomize(&b, 1);
         return b;
         }

      /**
      * @return a random byte that is not the zero byte
      */
      byte next_nonzero_byte()
         {
         byte b = this->next_byte();
         while(b == 0)
            b = this->next_byte();
         return b;
         }

      /**
      * Create a seeded and active RNG object for general application use
      * Added in 1.8.0
      * Use AutoSeeded_RNG instead
      */
      BOTAN_DEPRECATED("Use AutoSeeded_RNG")
      static RandomNumberGenerator* make_rng();
   };

/**
* Convenience typedef
*/
typedef RandomNumberGenerator RNG;

/**
* Hardware RNG has no members but exists to tag hardware RNG types
*/
class BOTAN_DLL Hardware_RNG : public RandomNumberGenerator
   {
   };

/**
* Null/stub RNG - fails if you try to use it for anything
* This is not generally useful except for in certain tests
*/
class BOTAN_DLL Null_RNG final : public RandomNumberGenerator
   {
   public:
      bool is_seeded() const override { return false; }

      void clear() override {}

      void randomize(byte[], size_t) override
         {
         throw Exception("Null_RNG called");
         }

      void add_entropy(const byte[], size_t) override {}

      std::string name() const override { return "Null_RNG"; }
   };

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
/**
* Wraps access to a RNG in a mutex
*/
class BOTAN_DLL Serialized_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->randomize(out, len);
         }

      bool is_seeded() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->is_seeded();
         }

      void clear() override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->clear();
         }

      std::string name() const override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->name();
         }

      size_t reseed(Entropy_Sources& src,
                    size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS,
                    std::chrono::milliseconds poll_timeout = BOTAN_RNG_RESEED_DEFAULT_TIMEOUT) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         return m_rng->reseed(src, poll_bits, poll_timeout);
         }

      void add_entropy(const byte in[], size_t len) override
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         m_rng->add_entropy(in, len);
         }

      BOTAN_DEPRECATED("Use Serialized_RNG(new AutoSeeded_RNG)") Serialized_RNG();

      explicit Serialized_RNG(RandomNumberGenerator* rng) : m_rng(rng) {}
   private:
      mutable mutex_type m_mutex;
      std::unique_ptr<RandomNumberGenerator> m_rng;
   };
#endif

}

#endif
