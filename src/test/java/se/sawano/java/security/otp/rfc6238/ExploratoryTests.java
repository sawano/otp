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

package se.sawano.java.security.otp.rfc6238;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Used to explore the algorithms.
 */
public class ExploratoryTests {

    private static final int[] DIGITS_POWER
            // 0 1  2   3    4     5      6       7        8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    // Seed for HMAC-SHA1 - 20 bytes
    private static final String seed = "3132333435363738393031323334353637383930";
    // Seed for HMAC-SHA256 - 32 bytes
    private static final String seed32 = "3132333435363738393031323334353637383930" +
            "313233343536373839303132";
    // Seed for HMAC-SHA512 - 64 bytes
    private static final String seed64 = "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "31323334";

    @Test
    public void should_perform_TOTP() throws Exception {
        System.out.println("--> " + hexStr2Bytes(seed).length);

        final ReferenceDataRepository testData = new ReferenceDataRepository().init();

        final ReferenceDataRepository.ReferenceData data = testData.getForMode(ReferenceDataRepository.ReferenceData.Mode.SHA512);

        final SharedSecret sharedSecret = SharedSecret.fromHex(seed64, ShaAlgorithm.SHA512);
        assertArrayEquals(hexStr2Bytes(seed64), sharedSecret.value());

        final int numberOfDigitsInCode = 8;
        final long T0 = ReferenceDataRepository.T0.toEpochMilli();
        final long stepSize = ReferenceDataRepository.TIME_STEP.toMillis();
        final long T = (data.time.toEpochMilli() - T0) / stepSize; // Number of steps

        final String hexT = StringUtils.leftPad(Long.toHexString(T), 16, '0');

        System.out.println("Thex=" + hexT);
        assertEquals(data.hexTime, hexT);

        final byte[] hexTBytes = Hex.decodeHex(hexT.toCharArray());
        final byte[] hextBytes2 = hexStr2Bytes(hexT);
        assertArrayEquals(hextBytes2, hexTBytes);

        final byte[] hashBytes = HmacUtils.hmacSha512(sharedSecret.value(), hexTBytes);
        System.out.println(hashBytes.length);

        final int binary = truncate(hashBytes);

        int otp = binary % DIGITS_POWER[numberOfDigitsInCode];

        final String totpString = StringUtils.leftPad(Integer.toString(otp), numberOfDigitsInCode, '0');
        System.out.println(totpString);
        assertEquals(data.totp, totpString);
    }

    /**
     * Truncates the hash as described in rfc4226, with respect to rfc6238.
     * See https://tools.ietf.org/html/rfc4226#section-5.3.
     *
     * @param hash
     *         the HMAC bytes
     *
     * @return
     */
    private int truncate(byte[] hash) {
        int offset = hash[hash.length - 1] & 0xf;

        int binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        return binary;
    }

    // Taken directly from https://tools.ietf.org/html/rfc6238#appendix-A
    @Deprecated
    private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = bArray[i + 1];
        }
        return ret;
    }
}
