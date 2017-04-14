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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import se.sawano.java.security.otp.ShaAlgorithm;
import se.sawano.java.security.otp.SharedSecret;
import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.TOTPService;
import se.sawano.java.security.otp.impl.Clock;
import se.sawano.java.security.otp.impl.WindowSize;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static se.sawano.java.security.otp.TOTP.totp;

@RunWith(Parameterized.class)
public class TOTPServiceWindowSizeTests {

    @Parameterized.Parameters(name = "{index} windowSize={0}, window={1}, {2}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {windowSize(1), andWindow(-1), isNotOk()},
                {windowSize(1), andWindow(0), isOk()},
                {windowSize(1), andWindow(1), isNotOk()},

                {windowSize(3), andWindow(-235234), isNotOk()},
                {windowSize(3), andWindow(-2), isNotOk()},
                {windowSize(3), andWindow(-1), isOk()},
                {windowSize(3), andWindow(0), isOk()},
                {windowSize(3), andWindow(1), isOk()},
                {windowSize(3), andWindow(1), isOk()},
                {windowSize(3), andWindow(2), isNotOk()},
                {windowSize(3), andWindow(3), isNotOk()},
                {windowSize(3), andWindow(98234), isNotOk()},

                {windowSize(5), andWindow(-5), isNotOk()},
                {windowSize(5), andWindow(-4), isNotOk()},
                {windowSize(5), andWindow(-3), isNotOk()},
                {windowSize(5), andWindow(-2), isOk()},
                {windowSize(5), andWindow(-1), isOk()},
                {windowSize(5), andWindow(0), isOk()},
                {windowSize(5), andWindow(1), isOk()},
                {windowSize(5), andWindow(2), isOk()},
                {windowSize(5), andWindow(3), isNotOk()},
                {windowSize(5), andWindow(4), isNotOk()},
                {windowSize(5), andWindow(5), isNotOk()}
        });

    }

    private static int windowSize(final int windowSize) {
        return windowSize;
    }

    private static int andWindow(final int window) {
        return window;
    }

    private static boolean isOk() {
        return true;
    }

    private static boolean isNotOk() {
        return false;
    }

    // Example data from RFC6238
    static final int EXPECTED_TOTP = 14050471;
    static final Instant TIME = Instant.ofEpochSecond(1111111111);
    static final String SECRET_STR = "12345678901234567890";
    static final SharedSecret SECRET = SharedSecret.from(SECRET_STR.getBytes(), ShaAlgorithm.SHA1);

    @Parameterized.Parameter(0)
    public int windowSize;
    @Parameterized.Parameter(1)
    public int window;
    @Parameterized.Parameter(2)
    public boolean isOk;

    @Test
    public void should_verify_totp_code_within_given_window() throws Exception {
        assertEquals(isOk, totpService().verify(totp(EXPECTED_TOTP, TOTP.Length.EIGHT), SECRET));
    }

    private TOTPService totpService() {
        final Clock clock = () -> TIME.plus(TOTPService.STEP_SIZE.multipliedBy(window));
        return new TOTPService(clock, TOTPService.T0_UTC, TOTPService.STEP_SIZE, WindowSize.windowSize(windowSize));
    }
}