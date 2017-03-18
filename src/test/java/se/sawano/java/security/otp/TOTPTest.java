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

import static org.junit.Assert.assertEquals;

public class TOTPTest {

    @Test
    public void should_calculate_hash_from_value() throws Exception {
        assertEquals("12345678".hashCode(), new TOTP(12345678, TOTP.Length.EIGHT).hashCode());
        assertEquals("00123456".hashCode(), new TOTP(123456, TOTP.Length.EIGHT).hashCode());
        assertEquals("0012".hashCode(), new TOTP(12, TOTP.Length.FOUR).hashCode());
    }
}