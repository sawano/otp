/*
 * Copyright 2017 Daniel Sawano
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.sawano.java.security.otp;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static se.sawano.java.security.otp.ShaAlgorithm.*;

@RunWith(Parameterized.class)
public class SharedSecretByteVerificationTests {

    @Parameterized.Parameters(name = "[{index}] noOfBytes: {0}, algorithm: {1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {noOfBytes(1), andAlgorithm(SHA1), isNotOk()},
                {noOfBytes(19), andAlgorithm(SHA1), isNotOk()},
                {noOfBytes(20), andAlgorithm(SHA1), isOk()},
                {noOfBytes(21), andAlgorithm(SHA1), isOk()},
                {noOfBytes(5432), andAlgorithm(SHA1), isOk()},

                {noOfBytes(0), andAlgorithm(SHA256), isNotOk()},
                {noOfBytes(19), andAlgorithm(SHA256), isNotOk()},
                {noOfBytes(20), andAlgorithm(SHA256), isOk()},
                {noOfBytes(21), andAlgorithm(SHA256), isOk()},
                {noOfBytes(31), andAlgorithm(SHA256), isOk()},
                {noOfBytes(32), andAlgorithm(SHA256), isOk()},
                {noOfBytes(33), andAlgorithm(SHA256), isOk()},
                {noOfBytes(235), andAlgorithm(SHA256), isOk()},

                {noOfBytes(3), andAlgorithm(SHA512), isNotOk()},
                {noOfBytes(19), andAlgorithm(SHA512), isNotOk()},
                {noOfBytes(20), andAlgorithm(SHA512), isOk()},
                {noOfBytes(21), andAlgorithm(SHA512), isOk()},
                {noOfBytes(31), andAlgorithm(SHA512), isOk()},
                {noOfBytes(32), andAlgorithm(SHA512), isOk()},
                {noOfBytes(33), andAlgorithm(SHA512), isOk()},
                {noOfBytes(63), andAlgorithm(SHA512), isOk()},
                {noOfBytes(64), andAlgorithm(SHA512), isOk()},
                {noOfBytes(65), andAlgorithm(SHA512), isOk()},
                {noOfBytes(234), andAlgorithm(SHA512), isOk()},
                });

    }

    private static int noOfBytes(final int noOfBytes) {
        return noOfBytes;
    }

    private static ShaAlgorithm andAlgorithm(final ShaAlgorithm algorithm) {
        return algorithm;
    }

    private static boolean isNotOk() {
        return false;
    }

    private static boolean isOk() {
        return true;
    }

    private static Random RANDOM = new Random();

    @Parameterized.Parameter(0)
    public int noOfBytes;
    @Parameterized.Parameter(1)
    public ShaAlgorithm algorithm;
    @Parameterized.Parameter(2)
    public boolean shouldCreate;

    @Test
    public void should_not_allow_creation_f_number_of_bytes_doesnt_match_SHA_algorithm() throws Exception {
        assertEquals(shouldCreate, tryCreateSharedSecret());

    }

    private boolean tryCreateSharedSecret() {
        try {
            SharedSecret.fromHex(createHexString(), algorithm);
            return true;
        } catch (final IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("Minimum length of secret is"));
            return false;
        }
    }

    private String createHexString() {
        final byte[] bytes = new byte[noOfBytes];
        RANDOM.nextBytes(bytes);

        return String.valueOf(Hex.encodeHex(bytes));
    }

}