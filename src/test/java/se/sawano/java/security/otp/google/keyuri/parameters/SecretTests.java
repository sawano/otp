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
import se.sawano.java.security.otp.Assertions;

import static org.junit.Assert.assertEquals;

public class SecretTests {

    @Test
    public void should_base32_encode_value() throws Exception {
        assertEquals("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", secret("12345678901234567890").value());
    }

    @Test
    public void should_trim_padding_from_value() throws Exception {
        assertEquals("GEZDGNBVGY", secret("123456").value());
    }

    @Test
    public void should_have_base32_secret_as_parameter_value() throws Exception {
        final String pair = secret("12345678901234567890").parameterPair();

        assertEquals("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", pair);
    }

    @Test
    public void should_throw_unsupported_operation_exception_on_serialization() throws Exception {
        Assertions.assertNotWritable(secret("12345678901234567890"));
    }

    @Test
    public void should_throw_unsupported_operation_exception_on_deserialization() throws Exception {
        Assertions.assertNotReadable(secret("12345678901234567890"));
    }

    private Secret secret(final String value) {
        return Secret.secret(value.getBytes());
    }
}