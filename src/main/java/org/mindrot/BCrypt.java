package org.mindrot;

// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import java.security.SecureRandom;

import static org.mindrot.BcryptImpl.checkPassword;
import static org.mindrot.BcryptImpl.generateHash;
import static org.mindrot.BcryptImpl.generateSalt;

/**
 * BCrypt implements OpenBSD-style Blowfish password hashing using
 * the scheme described in "A Future-Adaptable Password Scheme" by
 * Niels Provos and David Mazieres.
 * <p>
 * This password hashing system tries to thwart off-line password
 * cracking using a computationally-intensive hashing algorithm,
 * based on Bruce Schneier's Blowfish cipher. The work factor of
 * the algorithm is parameterised, so it can be increased as
 * computers get faster.
 * <p>
 * Usage is really simple. To hash a password for the first time,
 * call the hashpw method with a random salt, like this:
 * <p>
 * <code>
 * String pw_hash = BCrypt.hashpw(plain_password, BCrypt.gensalt()); <br />
 * </code>
 * <p>
 * To check whether a plaintext password matches one that has been
 * hashed previously, use the checkpw method:
 * <p>
 * <code>
 * if (BCrypt.checkpw(candidate_password, stored_hash))<br />
 * &nbsp;&nbsp;&nbsp;&nbsp;System.out.println("It matches");<br />
 * else<br />
 * &nbsp;&nbsp;&nbsp;&nbsp;System.out.println("It does not match");<br />
 * </code>
 * <p>
 * The gensalt() method takes an optional parameter (log_rounds)
 * that determines the computational complexity of the hashing:
 * <p>
 * <code>
 * String strong_salt = BCrypt.gensalt(10)<br />
 * String stronger_salt = BCrypt.gensalt(12)<br />
 * </code>
 * <p>
 * The amount of work increases exponentially (2**log_rounds), so 
 * each increment is twice as much work. The default log_rounds is
 * 10, and the valid range is 4 to 30.
 *
 * @author Damien Miller
 * @version 0.4
 */
public final class BCrypt {
	// BCrypt parameters
    public static final int GENSALT_DEFAULT_LOG2_ROUNDS = 10;
    public static final int BCRYPT_SALT_LEN = 16;

    public static final char A_MINOR = 'a';
	public static final char Y_MINOR = 'y';

    /**
     * Check that a plaintext password matches a previously hashed
     * one
     * @param plaintext	the plaintext password to verify
     * @param hashed	the previously-hashed password
     * @return	true if the passwords match, false otherwise
     */
    public static boolean checkpw(String plaintext, String hashed) {
        return checkPassword(plaintext, hashed);
    }

    /**
	 * Hash a password using the OpenBSD bcrypt scheme
	 * @param password	the password to hash
	 * @param salt	the salt to hash with (perhaps generated
	 * using BCrypt.gensalt)
	 * @return	the hashed password
	 */
	public static String hashpw(String password, String salt) {
        return generateHash(password, salt);
	}

    /**
     * Generate a salt for use with the BCrypt.hashpw() method,
     * selecting a reasonable default for the number of hashing
     * rounds to apply
     * @return	an encoded salt value
     */
    public static String gensalt() {
        return gensalt(GENSALT_DEFAULT_LOG2_ROUNDS);
    }

    /**
     * Generate a salt for use with the BCrypt.hashpw() method
     * @param log_rounds	the log2 of the number of rounds of
     * hashing to apply - the work factor therefore increases as
     * 2**log_rounds.
     * @return	an encoded salt value
     */
    public static String gensalt(int log_rounds) {
        return gensalt(log_rounds, new SecureRandom());
    }

	/**
	 * Generate a salt for use with the BCrypt.hashpw() method
	 * @param log_rounds	the log2 of the number of rounds of
	 * hashing to apply - the work factor therefore increases as
	 * 2**log_rounds.
	 * @param random		an instance of SecureRandom to use
	 * @return	an encoded salt value
	 */
	public static String gensalt(int log_rounds, SecureRandom random) {
        return generateSalt(log_rounds, random);
	}

}
