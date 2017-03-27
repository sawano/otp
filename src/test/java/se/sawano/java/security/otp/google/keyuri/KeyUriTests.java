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

import java.net.URI;
import java.time.Duration;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static se.sawano.java.security.otp.google.keyuri.Label.AccountName.accountName;
import static se.sawano.java.security.otp.google.keyuri.Label.Issuer.issuer;
import static se.sawano.java.security.otp.google.keyuri.parameters.Counter.counter;
import static se.sawano.java.security.otp.google.keyuri.parameters.Period.period;
import static se.sawano.java.security.otp.google.keyuri.parameters.Secret.secret;

// TODO more tests
public class KeyUriTests {

    @Rule
    public ExpectedException expectation = ExpectedException.none();

    @Test
    public void should_not_create_if_issuer_is_different_from_issuer_in_parameters() throws Exception {

        final String issuer1 = "My Service";
        final String issuer2 = "My Other Service";

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Issuer must be same in Label and parameters"));

        new KeyUri(new Label(accountName("jane.doe"), issuer(issuer1)), totpParametersWithIssuer(issuer2));
    }

    @Test
    public void should_create_if_issuer_is_equal_to_issuer_in_parameters() throws Exception {

        final String issuer = "My Service";

        new KeyUri(new Label(accountName("jane.doe"), issuer(issuer)), totpParametersWithIssuer(issuer));
    }

    @Test
    public void should_create_a_proper_totp_uri() throws Exception {
        final TOTPParameters parameters = totpParametersWithIssuer("My Co");

        final URI uri = new KeyUri(new Label(accountName("john.doe@example.com"), issuer("My Co")),
                                   parameters).toURI();

        assertEquals("otpauth://totp/john.doe%40example.com%3AMy%20Co?algorithm=SHA1&digits=6&issuer=My%20Co&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri.toString());
    }

    @Test
    public void should_create_a_proper_hotp_uri() throws Exception {
        final HOTPParameters parameters = hotpParametersWithIssuer("My Co");

        final URI uri = new KeyUri(new Label(accountName("john.doe@example.com"), issuer("My Co")),
                                   parameters).toURI();

        assertEquals("otpauth://hotp/john.doe%40example.com%3AMy%20Co?algorithm=SHA1&counter=42&digits=6&issuer=My%20Co&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri.toString());
    }

    private TOTPParameters totpParametersWithIssuer(final String issuer) {
        return ParametersBuilder.totpBuilder()
                                .withSecret(secret("12345678901234567890".getBytes()))
                                .withAlgorithm(Algorithm.SHA1)
                                .withIssuer(Issuer.issuer(issuer))
                                .withDigits(Digits.SIX)
                                .withPeriod(period(Duration.ofSeconds(30)))
                                .create();
    }

    private HOTPParameters hotpParametersWithIssuer(final String issuer) {
        return ParametersBuilder.hotpBuilder()
                                .withSecret(secret("12345678901234567890".getBytes()))
                                .withAlgorithm(Algorithm.SHA1)
                                .withIssuer(Issuer.issuer(issuer))
                                .withDigits(Digits.SIX)
                                .withCounter(counter(42))
                                .create();
    }

}