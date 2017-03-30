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

package se.sawano.java.security.otp.impl;

import org.junit.Test;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.TOTP;

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static se.sawano.java.security.otp.TOTP.totp;

public class DefaultTOTPServiceTests {

    // Example data from RFC6238
    static final int TOTP_1 = 14050471;
    static final Instant TIME_1 = Instant.ofEpochSecond(1111111111);
    static final int TOTP_2 = 69279037;
    static final Instant TIME_2 = Instant.ofEpochSecond(2000000000);
    static final String SECRET_STR = "12345678901234567890";
    static final SharedSecret SECRET = SharedSecret.from(SECRET_STR.getBytes(), ShaAlgorithm.SHA1);

    private Instant time;
    private TOTP totp;
    private SharedSecret secret;
    private TOTP createdTotp;
    private boolean verifyResult;

    @Test
    public void should_verify_totp_code_1() throws Exception {
        givenTime(TIME_1);
        givenTotp(TOTP_1);

        whenVerifyingTotp();

        thenTheTotpShouldBeValid();
    }

    @Test
    public void should_verify_totp_code_2() throws Exception {
        givenTime(TIME_2);
        givenTotp(TOTP_2);

        whenVerifyingTotp();

        thenTheTotpShouldBeValid();
    }

    @Test
    public void should_create_totp() throws Exception {
        givenTime(TIME_1);
        givenSecret(SECRET);

        whenCreatingTotp();

        thenTotpIs(TOTP_1);
    }

    private void thenTotpIs(final int expectedTotp) {
        assertEquals(expectedTotp, Integer.parseInt(createdTotp.value()));
    }

    private void givenSecret(final SharedSecret secret) {
        this.secret = secret;
    }

    private void whenCreatingTotp() {
        createdTotp = totpService().create(secret, TOTP.Length.EIGHT);
    }

    private void givenTime(final Instant time) {
        this.time = time;
    }

    private void givenTotp(final int totp) {
        this.totp = totp(totp, TOTP.Length.EIGHT);
    }

    private void whenVerifyingTotp() {
        verifyResult = totpService().verify(totp, SECRET);
    }

    private void thenTheTotpShouldBeValid() {
        assertTrue(verifyResult);
    }

    private DefaultTOTPService totpService() {
        return new DefaultTOTPService(() -> time, DefaultTOTPService.T0_UTC, DefaultTOTPService.STEP_SIZE, DefaultTOTPService.DEFAULT_WINDOW_SIZE);
    }

}