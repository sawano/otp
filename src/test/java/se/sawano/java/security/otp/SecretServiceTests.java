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

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static se.sawano.java.security.otp.CodecUtils.encodeToHex;
import static se.sawano.java.security.otp.ShaAlgorithm.*;

public class SecretServiceTests {

    public static final String ASCII_SECRET_FROM_RFC6238 = "12345678901234567890";
    public static final String EXPECTED_SHA1_HEX_SECRET_FROM_RFC_6238_EXAMPLE = "3132333435363738393031323334353637383930";
    public static final String EXPECTED_SHA256_HEX_SECRET_FROM_RFC_6238_EXAMPLE = "3132333435363738393031323334353637383930313233343536373839303132";
    public static final String EXPECTED_SHA512_HEX_SECRET_FROM_RFC_6238_EXAMPLE = "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "3132333435363738393031323334353637383930" +
            "31323334";
    private ShaAlgorithm algorithm;
    private SharedSecret secret;

    @Test
    public void should_generate_sha1_secret() throws Exception {
        givenAlgorithm(SHA1);

        whenGeneratingSecret();

        thenSecretShouldHaveCorrectAlgorithm();
        thenNumberOfBytesInSecretIs(20);
        thenHexSecretIs(EXPECTED_SHA1_HEX_SECRET_FROM_RFC_6238_EXAMPLE);
    }

    @Test
    public void should_generate_sha256_secret() throws Exception {
        givenAlgorithm(SHA256);

        whenGeneratingSecret();

        thenSecretShouldHaveCorrectAlgorithm();
        thenNumberOfBytesInSecretIs(32);
        thenHexSecretIs(EXPECTED_SHA256_HEX_SECRET_FROM_RFC_6238_EXAMPLE);
    }

    @Test
    public void should_generate_sha512_secret() throws Exception {
        givenAlgorithm(SHA512);

        whenGeneratingSecret();

        thenSecretShouldHaveCorrectAlgorithm();
        thenNumberOfBytesInSecretIs(64);
        thenHexSecretIs(EXPECTED_SHA512_HEX_SECRET_FROM_RFC_6238_EXAMPLE);
    }

    private void givenAlgorithm(final ShaAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    private void whenGeneratingSecret() {
        final SecretService secretService = new SecretService(fakeRandomSupplier());
        secret = secretService.generateSharedSecret(algorithm);
    }

    private RandomSupplier fakeRandomSupplier() {
        final String s = (ASCII_SECRET_FROM_RFC6238 + ASCII_SECRET_FROM_RFC6238 + ASCII_SECRET_FROM_RFC6238 + ASCII_SECRET_FROM_RFC6238);
        return bytes -> System.arraycopy(s.getBytes(), 0, bytes, 0, bytes.length);
    }

    private void thenSecretShouldHaveCorrectAlgorithm() {
        assertEquals(algorithm, secret.algorithm());
    }

    private void thenNumberOfBytesInSecretIs(final int expectedNumberOfBytes) {
        assertEquals(expectedNumberOfBytes, secret.keyLength());
    }

    private void thenHexSecretIs(final String expectedHexSecret) {
        assertEquals(expectedHexSecret, new String(encodeToHex(secret.value())));
    }
}