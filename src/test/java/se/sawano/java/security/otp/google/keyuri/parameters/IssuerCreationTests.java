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

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class IssuerCreationTests {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {value("Example Co"), isOk()},
                {value(":"), isOk()},
                {value("My:Company"), isOk()},
                {value(""), isNotOk()},
                {value("   "), isNotOk()},
                {value(StringUtils.repeat("a", Issuer.MAX_LENGTH - 1)), isOk()},
                {value(StringUtils.repeat("a", Issuer.MAX_LENGTH)), isOk()},
                {value(StringUtils.repeat("a", Issuer.MAX_LENGTH + 1)), isNotOk()}
        });

    }

    private static String value(final String value) {
        return value;
    }

    private static boolean isNotOk() {
        return false;
    }

    private static boolean isOk() {
        return true;
    }

    @Parameterized.Parameter(0)
    public String value;
    @Parameterized.Parameter(1)
    public boolean isValid;

    @Test
    public void should_test_creation() throws Exception {
        final Optional<String> errorMessage = tryCreate();

        assertEquals(isValid, !errorMessage.isPresent());
    }

    private Optional<String> tryCreate() {
        try {
            new Issuer(value);
            return Optional.empty();
        } catch (final IllegalArgumentException e) {
            return Optional.of(e.getMessage());
        }
    }
}