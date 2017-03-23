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

package se.sawano.java.security.otp.keyuri.parameters;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DigitsTest {

    @Test
    public void should_have_the_correct_value() throws Exception {
        assertEquals(6, Digits.SIX.value());
        assertEquals(8, Digits.EIGHT.value());
    }

    @Test
    public void should_alert_if_new_enum_is_added() throws Exception {
        assertEquals("A new enum has been added, don't forget to add new tests", 2, Digits.values().length);
    }
}