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
import se.sawano.java.security.otp.google.keyuri.Label.AccountName;
import se.sawano.java.security.otp.google.keyuri.Label.Issuer;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class LabelValueTest {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {givenAcountName("john.doe@example.com"), andIssuer("My Company"), thenValueShouldBe("john.doe%40example.com%3AMy%20Company")},
                {givenAcountName("john.doe@example.com"), andNoIssuer(), thenValueShouldBe("john.doe%40example.com")},
                {givenAcountName("John Doe"), andNoIssuer(), thenValueShouldBe("John%20Doe")},
                {givenAcountName("John Doe"), andIssuer("My@Company"), thenValueShouldBe("John%20Doe%3AMy%40Company")}
        });

    }

    private static String givenAcountName(final String accountName) {
        return accountName;
    }

    private static String andIssuer(final String issuer) {
        return issuer;
    }

    private static String andNoIssuer() {
        return null;
    }

    private static String thenValueShouldBe(final String expectedValue) {
        return expectedValue;
    }

    @Parameterized.Parameter(0)
    public String accountName;
    @Parameterized.Parameter(1)
    public String issuer;
    @Parameterized.Parameter(2)
    public String expectedValue;

    @Test
    public void should_create_correct_value() throws Exception {
        assertEquals(expectedValue, getValue());
    }

    private String getValue() {
        if (issuer == null) {
            return new Label(accountName()).asUriString();
        }
        return new Label(accountName(), issuer()).asUriString();
    }

    private AccountName accountName() {
        return new AccountName(accountName);
    }

    private Issuer issuer() {
        return new Issuer(issuer);
    }
}