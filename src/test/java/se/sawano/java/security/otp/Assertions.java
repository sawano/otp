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

import java.io.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class Assertions {

    public static void assertNotWritable(final Externalizable subject) {
        try {
            subject.writeExternal(objectOutputStream());
            fail("Did not expect subject to be writable");
        } catch (final Exception e) {
            assertEquals(UnsupportedOperationException.class, e.getClass());
        }
    }

    public static void assertNotReadable(final Externalizable subject) {
        try {
            subject.readExternal(objectInputStream());
            fail("Did not expect subject to be readable");
        } catch (final Exception e) {
            assertEquals(UnsupportedOperationException.class, e.getClass());
        }
    }

    private static ObjectOutputStream objectOutputStream() throws IOException {
        return new ObjectOutputStream(new ByteArrayOutputStream(100));
    }

    private static ObjectInputStream objectInputStream() throws IOException {
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream(100);
        new ObjectOutputStream(bOut).write("hello".getBytes());
        return new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
    }

}
