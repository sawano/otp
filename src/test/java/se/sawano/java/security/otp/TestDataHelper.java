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

import org.apache.commons.codec.binary.Base32;
import org.junit.Test;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.TOTPService;
import se.sawano.java.security.otp.impl.DefaultSecretService;

import static se.sawano.java.security.otp.ShaAlgorithm.SHA1;
import static se.sawano.java.security.otp.ShaAlgorithm.SHA256;
import static se.sawano.java.security.otp.TOTP.Length.SIX;

/**
 * Used to generate data for manual testing.
 */
public class TestDataHelper {

    @Test
    public void should_generate_new_secret() throws Exception {
        final SharedSecret secret = new DefaultSecretService().generateSharedSecret(SHA1);

        System.out.println(new Base32(false).encodeAsString(secret.value()));

    }

    @Test
    public void should_print_totp() throws Exception {
        final String secretB32SHA1 = "ZEJHUB2WISYTMOUMDNM7GO5URLKS7TXC";
        final String secretB32SHA256 = "YNLNGPKN47VVR7NXRGOM3KAQYQAFHDIY7WAIE2X3VVGVPUOTXJVQ";

        final SharedSecret secretSHA1 = SharedSecret.fromBase32(secretB32SHA1, SHA1);
        final SharedSecret secretSHA256 = SharedSecret.fromBase32(secretB32SHA256, SHA256);

        final TOTP totpSHA1 = new TOTPService().create(secretSHA1, SIX);
        final TOTP totpSHA256 = new TOTPService().create(secretSHA256, SIX);

        System.out.println("SHA1: " + totpSHA1.value());
        System.out.println("SHA256: " + totpSHA256.value());
    }

}
