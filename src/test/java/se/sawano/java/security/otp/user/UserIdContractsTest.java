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

package se.sawano.java.security.otp.user;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class UserIdContractsTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {id(""), isNotOk()},
                {id("  "), isNotOk()},
                {id(null), isNotOk()},
                {id(StringUtils.repeat('a', UserId.MAX_LENGTH - 1)), isOk()},
                {id(StringUtils.repeat('a', UserId.MAX_LENGTH)), isOk()},
                {id(StringUtils.repeat('a', UserId.MAX_LENGTH) + "  "), isOk()},
                {id(StringUtils.repeat('a', UserId.MAX_LENGTH + 1)), isNotOk()},
                {id(StringUtils.repeat('a', UserId.MAX_LENGTH + 1_000)), isNotOk()},
        });
    }

    @Parameterized.Parameter(0)
    public String id;

    @Parameterized.Parameter(1)
    public boolean isOk;

    @Test
    public void should_verify_contracts() throws Exception {
        assertEquals(isOk, tryCreate());
    }

    private boolean tryCreate() {
        try {
            new UserId(id);
            return true;
        } catch (NullPointerException | IllegalArgumentException e) {
            return false;
        }
    }

    private static String id(final String id) {
        return id;
    }

    private static boolean isNotOk() {
        return false;
    }

    private static boolean isOk() {
        return true;
    }
}