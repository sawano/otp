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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class UriEncoderTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {whenEncoding(""), thenResultShouldBe("")},
                {whenEncoding(" "), thenResultShouldBe("%20")},
                {whenEncoding("+"), thenResultShouldBe("%2B")},
                {whenEncoding("@"), thenResultShouldBe("%40")},
                {whenEncoding(":"), thenResultShouldBe("%3A")},
                {whenEncoding("abcdABCD"), thenResultShouldBe("abcdABCD")}
        });

    }

    private static String whenEncoding(final String value) {
        return value;
    }

    private static String thenResultShouldBe(final String expectedResult) {
        return expectedResult;
    }

    @Parameterized.Parameter(0)
    public String value;
    @Parameterized.Parameter(1)
    public String expectedResult;

    @Test
    public void should_encode() throws Exception {
        final String result = UriEncoder.encode(value);

        assertEquals(expectedResult, result);

    }
}