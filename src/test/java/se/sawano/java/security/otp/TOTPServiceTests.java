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

import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static se.sawano.java.security.otp.TOTP.totp;

public class TOTPServiceTests {

    // Example data from RFC6238
    static final int TOTP_1 = 14050471;
    static final Instant TIME_1 = Instant.ofEpochSecond(1111111111);
    static final int TOTP_2 = 69279037;
    static final Instant TIME_2 = Instant.ofEpochSecond(2000000000);
    static final String SECRET_STR = "12345678901234567890";

    private Instant time;
    private TOTP totp;
    private SharedSecret secret;
    private TOTP createdTotp;
    private boolean verifyResult;

    @Test
    public void should_verify_totp_code_1() throws Exception {
        givenTime(TIME_1);
        givenTotp(TOTP_1);
        givenSecret(SECRET_STR);

        whenVerifyingTotp();

        thenTheTotpShouldBeValid();
    }

    @Test
    public void should_verify_totp_code_2() throws Exception {
        givenTime(TIME_2);
        givenTotp(TOTP_2);
        givenSecret(SECRET_STR);

        whenVerifyingTotp();

        thenTheTotpShouldBeValid();
    }

    @Test
    public void should_create_totp() throws Exception {
        givenTime(TIME_1);
        givenSecret(SECRET_STR);

        whenCreatingTotp();

        thenTotpIs(TOTP_1);
    }

    private void thenTotpIs(final int expectedTotp) {
        assertEquals(expectedTotp, Integer.parseInt(createdTotp.value()));
    }

    private void givenSecret(final String secret) {
        this.secret = TestObjectFactory.from(secret, ShaAlgorithm.SHA1);
        ;
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
        verifyResult = totpService().verify(totp, secret);
    }

    private void thenTheTotpShouldBeValid() {
        assertTrue(verifyResult);
    }

    private TOTPService totpService() {
        return new TOTPService(() -> time, TOTPService.T0_UTC, TOTPService.STEP_SIZE, TOTPService.DEFAULT_WINDOW_SIZE);
    }

}