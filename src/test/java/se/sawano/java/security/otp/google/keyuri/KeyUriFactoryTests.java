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

package se.sawano.java.security.otp.google.keyuri;

import org.junit.Test;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.google.keyuri.parameters.Algorithm;
import se.sawano.java.security.otp.google.keyuri.parameters.Counter;
import se.sawano.java.security.otp.google.keyuri.parameters.Digits;
import se.sawano.java.security.otp.google.keyuri.parameters.Period;

import java.time.Duration;

import static org.junit.Assert.assertEquals;

public class KeyUriFactoryTests {

    private static final String ISSUER = "Example Company";
    private static final String ACCOUNT_NAME = "jane.doe@example.com";
    private static final Duration PERIOD = Duration.ofSeconds(30);
    private static final int COUNTER = 123;

    @Test
    public void should_create_key_uri_for_totp() throws Exception {

        final KeyUri keyUri = KeyUriFactory.totpKeyUriFrom(secret(), Digits.SIX, period(), accountName(), issuer());

        assertEquals(Type.TOTP, keyUri.type());
        assertEquals(ISSUER, keyUri.label().issuer().get().value());
        assertEquals(ACCOUNT_NAME, keyUri.label().accountName().value());
        assertEquals(ISSUER, keyUri.parameters().issuer().get().value());
        assertEquals(Algorithm.SHA1, keyUri.parameters().algorithm().get());
        assertEquals(Digits.SIX, keyUri.parameters().digits().get());
        assertEquals(PERIOD.getSeconds(), keyUri.parameters().period().get().value());
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", keyUri.parameters().secret().value());
    }

    @Test
    public void should_create_key_uri_for_hotp() throws Exception {

        final KeyUri keyUri = KeyUriFactory.hotpKeyUriFrom(secret(), Digits.SIX, counter(), accountName(), issuer());

        assertEquals(Type.HOTP, keyUri.type());
        assertEquals(ISSUER, keyUri.label().issuer().get().value());
        assertEquals(ACCOUNT_NAME, keyUri.label().accountName().value());
        assertEquals(ISSUER, keyUri.parameters().issuer().get().value());
        assertEquals(Algorithm.SHA1, keyUri.parameters().algorithm().get());
        assertEquals(Digits.SIX, keyUri.parameters().digits().get());
        assertEquals(COUNTER, keyUri.parameters().counter().get().value());
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", keyUri.parameters().secret().value());
    }

    private Counter counter() {
        return new Counter(COUNTER);
    }

    private SharedSecret secret() {
        return SharedSecret.fromHex("3132333435363738393031323334353637383930", ShaAlgorithm.SHA1);
    }

    private Period period() {
        return new Period(PERIOD);
    }

    private Label.AccountName accountName() {
        return Label.AccountName.accountName(ACCOUNT_NAME);
    }

    private Label.Issuer issuer() {
        return Label.Issuer.issuer(ISSUER);
    }
}