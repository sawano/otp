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

package se.sawano.java.security.otp.google.keyuri.parameters;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;

import java.time.Duration;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TOTPParametersTests {

    @Rule
    public ExpectedException expectation = ExpectedException.none();

    @Test
    public void should_fail_creation_if_period_is_missing() throws Exception {
        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("'Period' is required for type TOTP"));

        parametersWithoutPeriod().create();
    }

    @Test
    public void should_create_for_TOTP() throws Exception {

        assertNotNull(parametersForTotp().create());
    }

    @Test
    public void should_create_URI_encoded_string() throws Exception {
        final TOTPParameters parameters = parametersForTotp().create();

        assertEquals("?secret=ENJDVNXVNESP7N2VIOHSQG5RVID77N7P&issuer=Example%20Co&algorithm=SHA1&digits=6&period=30", parameters.asUriString());
    }

    private ParametersBuilder.TotpParametersBuilder parametersWithoutPeriod() {
        return completeBuilder()
                .withPeriod(null);
    }

    private ParametersBuilder.TotpParametersBuilder parametersForTotp() {
        return completeBuilder();
    }

    private ParametersBuilder.TotpParametersBuilder completeBuilder() {
        return ParametersBuilder.totpBuilder()
                                .withSecret(secret())
                                .withAlgorithm(algorithm())
                                .withIssuer(issuer())
                                .withDigits(Digits.SIX)
                                .withPeriod(period());
    }

    private Secret secret() {
        return new Secret(SharedSecret.fromBase32("ENJDVNXVNESP7N2VIOHSQG5RVID77N7P", ShaAlgorithm.SHA1).value());
    }

    private Algorithm algorithm() {
        return Algorithm.SHA1;
    }

    private Issuer issuer() {
        return new Issuer("Example Co");
    }

    private Period period() {
        return new Period(Duration.ofSeconds(30));
    }
}