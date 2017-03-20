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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static se.sawano.java.security.otp.ShaAlgorithm.*;

@RunWith(Parameterized.class)
public class SharedSecretTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {whenSeedIs("3132333435363738393031323334353637383930"),
                 andAlgorithmIs(SHA1),
                 thenProducedBytesAre(hexStr2Bytes("3132333435363738393031323334353637383930"))},
                {whenSeedIs("3132333435363738393031323334353637383930313233343536373839303132"),
                 andAlgorithmIs(SHA256),
                 thenProducedBytesAre(hexStr2Bytes("3132333435363738393031323334353637383930313233343536373839303132"))},
                {whenSeedIs("3132333435363738393031323334353637383930" +
                                    "3132333435363738393031323334353637383930" +
                                    "3132333435363738393031323334353637383930" +
                                    "31323334"),
                 andAlgorithmIs(SHA512),
                 thenProducedBytesAre(hexStr2Bytes("3132333435363738393031323334353637383930" +
                                                           "3132333435363738393031323334353637383930" +
                                                           "3132333435363738393031323334353637383930" +
                                                           "31323334"))}

        });

    }

    private static String whenSeedIs(final String s) {
        return s;
    }

    private static ShaAlgorithm andAlgorithmIs(final ShaAlgorithm algorithm) {
        return algorithm;
    }

    private static byte[] thenProducedBytesAre(final byte[] bytes) {
        return bytes;
    }

    @Parameterized.Parameter(0)
    public String seed;
    @Parameterized.Parameter(1)
    public ShaAlgorithm algorithm;
    @Parameterized.Parameter(2)
    public byte[] expectedBytes;

    @Test
    public void should_produce_correct_bytes() throws Exception {
        assertArrayEquals(expectedBytes, SharedSecret.fromHex(seed, algorithm).value());
    }

    private static byte[] hexStr2Bytes(final String hex) {
        try {
            return Hex.decodeHex(hex.toCharArray());
        } catch (final DecoderException e) {
            throw new RuntimeException(e);
        }

    }
}