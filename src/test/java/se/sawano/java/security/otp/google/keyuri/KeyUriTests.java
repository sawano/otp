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

        new KeyUri(Type.TOTP, new Label(accountName("jane.doe"), issuer(issuer1)), totpParametersWithIssuer(issuer2));
    }

    @Test
    public void should_create_if_issuer_is_equal_to_issuer_in_parameters() throws Exception {

        final String issuer = "My Service";

        new KeyUri(Type.TOTP, new Label(accountName("jane.doe"), issuer(issuer)), totpParametersWithIssuer(issuer));
    }

    @Test
    public void should_create_a_proper_totp_uri() throws Exception {
        final Parameters parameters = totpParametersWithIssuer("My Co");

        final URI uri = new KeyUri(Type.TOTP,
                                   new Label(accountName("john.doe@example.com"), issuer("My Co")),
                                   parameters).toURI();

        assertEquals("otpauth://totp/john.doe%40example.com%3AMy%20Co?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20Co&algorithm=SHA1&digits=6&period=30", uri.toString());
    }

    @Test
    public void should_create_a_proper_hotp_uri() throws Exception {
        final Parameters parameters = hotpParametersWithIssuer("My Co");

        final URI uri = new KeyUri(Type.HOTP,
                                   new Label(accountName("john.doe@example.com"), issuer("My Co")),
                                   parameters).toURI();

        assertEquals("otpauth://hotp/john.doe%40example.com%3AMy%20Co?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20Co&algorithm=SHA1&digits=6&counter=42", uri.toString());
    }

    @Test
    public void should_not_create_totp_if_parameters_have_hotp() throws Exception {
        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Parameters is not valid for type: TOTP"));

        final Parameters parameters = hotpParametersWithIssuer("My Co");
        new KeyUri(Type.TOTP,
                   new Label(accountName("john.doe@example.com"), issuer("My Co")),
                   parameters).toURI();
    }

    @Test
    public void should_not_create_hotp_if_parameters_have_hotp() throws Exception {
        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Parameters is not valid for type: HOTP"));

        final Parameters parameters = totpParametersWithIssuer("My Co");
        new KeyUri(Type.HOTP,
                   new Label(accountName("john.doe@example.com"), issuer("My Co")),
                   parameters).toURI();
    }

    private Parameters totpParametersWithIssuer(final String issuer) {
        return Parameters.builder()
                         .withSecret(new Secret("12345678901234567890".getBytes()))
                         .withAlgorithm(Algorithm.SHA1)
                         .withIssuer(new Issuer(issuer))
                         .withDigits(Digits.SIX)
                         .withPeriod(new Period(Duration.ofSeconds(30)))
                         .createFor(Type.TOTP);
    }

    private Parameters hotpParametersWithIssuer(final String issuer) {
        return Parameters.builder()
                         .withSecret(new Secret("12345678901234567890".getBytes()))
                         .withAlgorithm(Algorithm.SHA1)
                         .withIssuer(new Issuer(issuer))
                         .withDigits(Digits.SIX)
                         .withCounter(new Counter(42))
                         .createFor(Type.HOTP);
    }

}