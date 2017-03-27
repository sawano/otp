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

import org.junit.Test;

import static java.time.Duration.*;
import static org.junit.Assert.assertEquals;
import static se.sawano.java.security.otp.google.keyuri.parameters.Period.period;

public class PeriodTests {

    @Test
    public void should_return_value_in_seconds() throws Exception {
        assertEquals(30, period(ofSeconds(30)).value());
        assertEquals(60, period(ofMinutes(1)).value());
        assertEquals(1, period(ofMillis(1_000)).value());
    }

    @Test
    public void should_have_seconds_as_parameter_value() throws Exception {
        final String pair = period(ofSeconds(30)).parameterPair();

        assertEquals("period=30", pair);
    }
}