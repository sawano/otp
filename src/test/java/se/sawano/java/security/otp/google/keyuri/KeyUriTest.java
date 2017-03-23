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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import se.sawano.java.security.otp.google.keyuri.parameters.*;

import java.time.Duration;

import static org.hamcrest.core.Is.is;

public class KeyUriTest {

    @Rule
    public ExpectedException expectation = ExpectedException.none();

    @Test
    public void should_not_create_if_issuer_is_different_from_issuer_in_parameters() throws Exception {

        final String issuer1 = "My Service";
        final String issuer2 = "My Other Service";

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Issuer must be same in Label and parameters"));

        new KeyUri(Type.TOTP, new Label(accountName(), issuer(issuer1)), totpParametersWithIssuer(issuer2));

    }

    @Test
    public void should_create_if_issuer_is_equal_to_issuer_in_parameters() throws Exception {

        final String issuer = "My Service";

        new KeyUri(Type.TOTP, new Label(accountName(), issuer(issuer)), totpParametersWithIssuer(issuer));

    }

    private Parameters totpParametersWithIssuer(final String issuer) {
        return Parameters.builder()
                         .withSecret(new Secret(new byte[]{}))
                         .withAlgorithm(Algorithm.SHA1)
                         .withIssuer(new Issuer(issuer))
                         .withPeriod(new Period(Duration.ofSeconds(30)))
                         .createFor(Type.TOTP);
    }

    private Label.Issuer issuer(final String issuer1) {
        return new Label.Issuer(issuer1);
    }

    private Label.AccountName accountName() {
        return new Label.AccountName("jane.doe");
    }
}