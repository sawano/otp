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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static se.sawano.java.security.otp.Assertions.assertNotReadable;
import static se.sawano.java.security.otp.Assertions.assertNotWritable;
import static se.sawano.java.security.otp.TOTP.Length.*;

public class TOTPTest {

    @Rule
    public ExpectedException expectation = ExpectedException.none();

    @Test
    public void should_not_allow_numbers_greater_than_given_length() throws Exception {
        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Value must have length: 5. Was: 7"));

        totp(1234567, FIVE);
    }

    @Test
    public void should_pad_value_to_given_length() throws Exception {
        assertEquals("000123456", totp(123456, NINE).value());
    }

    @Test
    public void should_calculate_hash_from_value() throws Exception {
        assertEquals("12345678".hashCode(), totp(12345678, EIGHT).hashCode());
        assertEquals("00123456".hashCode(), totp(123456, EIGHT).hashCode());
        assertEquals("0012".hashCode(), totp(12, FOUR).hashCode());
    }

    @Test
    public void should_not_be_writable() throws Exception {
        assertNotWritable(totp(12, TWO));
    }

    @Test
    public void should_not_be_readable() throws Exception {
        assertNotReadable(totp(3456, SEVEN));
    }

    @Test
    public void should_not_allow_negative_values() throws Exception {
        expectation.expect(IllegalArgumentException.class);
        expectation.expectMessage(is("Value cannot be negative"));

        totp(-1, FIVE);
    }

    private TOTP totp(final int value, final TOTP.Length length) {
        return new TOTP(value, length);
    }
}