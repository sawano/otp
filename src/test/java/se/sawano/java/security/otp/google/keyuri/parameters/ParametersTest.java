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
import se.sawano.java.security.otp.google.keyuri.Type;

import java.time.Duration;

import static org.hamcrest.core.Is.is;

public class ParametersTest {

    @Rule
    public ExpectedException expectation = ExpectedException.none();

    @Test
    public void should_not_be_valid_if_type_is_HOTP_and_counter_is_missing() throws Exception {
        final Parameters parameters = parametersWithoutCounter();

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("'Counter' is required for type HOTP"));

        parameters.validateFor(Type.HOTP);
    }

    @Test
    public void should_not_be_valid_if_type_is_HOTP_and_period_is_present() throws Exception {
        final Parameters parameters = parametersWithPeriod();

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("'Period' is not allowed for type HOTP"));

        parameters.validateFor(Type.HOTP);
    }

    @Test
    public void should_not_be_valid_if_type_is_TOTP_and_period_is_missing() throws Exception {
        final Parameters parameters = parametersWithoutPeriod();

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("'Period' is required for type TOTP"));

        parameters.validateFor(Type.TOTP);
    }

    @Test
    public void should_not_be_valid_if_type_is_TOTP_and_counter_is_present() throws Exception {
        final Parameters parameters = parametersWithCounter();

        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("'Counter' is not allowed for type TOTP"));

        parameters.validateFor(Type.TOTP);
    }

    private Parameters parametersWithPeriod() {
        return completeBuilder()
                .create();
    }

    private Parameters parametersWithoutCounter() {
        return completeBuilder()
                .withCounter(null)
                .create();
    }

    private Parameters parametersWithCounter() {
        return completeBuilder()
                .create();
    }

    private Parameters parametersWithoutPeriod() {
        return completeBuilder()
                .withPeriod(null)
                .create();
    }

    private Parameters.Builder completeBuilder() {
        return Parameters.builder()
                         .withSecret(new Secret(new byte[]{}))
                         .withAlgorithm(Algorithm.SHA1)
                         .withIssuer(new Issuer("Example Co"))
                         .withCounter(new Counter(0))
                         .withPeriod(new Period(Duration.ofSeconds(30)));
    }
}