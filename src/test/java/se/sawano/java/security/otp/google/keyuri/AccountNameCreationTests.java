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

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import static org.junit.Assert.assertFalse;

@RunWith(Parameterized.class)
public class AccountNameCreationTests {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {value(null), isNotOk()},
                {value(""), isNotOk()},
                {value("  "), isNotOk()},
                {value("john.doe@example.com"), isOk()},
                {value("johnd"), isOk()},
                {value(" johnd "), isOk()},
                {value("john:doe"), isNotOk()},
                {value("john#€%&/()=?=)(/&%€#!"), isOk()},
                {value(StringUtils.repeat("a", Label.AccountName.MAX_LENGTH - 1)), isOk()},
                {value(StringUtils.repeat("a", Label.AccountName.MAX_LENGTH)), isOk()},
                {value(StringUtils.repeat("a", Label.AccountName.MAX_LENGTH + 1)), isNotOk()}
        });
    }

    private static boolean isOk() {
        return true;
    }

    private static boolean isNotOk() {
        return false;
    }

    private static String value(final String value) {
        return value;
    }

    @Parameterized.Parameter(0)
    public String value;
    @Parameterized.Parameter(1)
    public boolean isOk;

    @Test
    public void should_try_to_create_an_account_name() throws Exception {
        tryCreate(value).ifPresent(message -> {
            assertFalse(isOk);
        });
    }

    private static Optional<String> tryCreate(final String value) {
        try {
            Label.AccountName.accountName(value);
            return Optional.empty();
        } catch (final IllegalArgumentException | NullPointerException e) {
            return Optional.of(e.getMessage());
        }

    }
}