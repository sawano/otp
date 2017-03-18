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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.nio.charset.Charset;
import java.util.Arrays;

import static org.apache.commons.lang3.Validate.notNull;

// TODO should algorithm be included?
// TODO clean up factory methods
public final class SharedSecret implements Externalizable {

    private static final Charset UTF_8 = Charset.forName("UTF8");

    public static SharedSecret from(final String value) {
        return from(value, UTF_8);
    }

    public static SharedSecret from(final String value, final Charset charset) {
        notNull(value);
        notNull(charset);

        return fromHex(Hex.encodeHexString(value.getBytes(charset)));
    }

    public static SharedSecret fromHex(final String hexString) {
        notNull(hexString);

        try {
            final byte[] decode = Hex.decodeHex(hexString.toCharArray());
            return new SharedSecret(decode);
        } catch (final DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    private final byte[] value;

    private SharedSecret(final byte[] value) {
        // TODO check length
        this.value = value;
    }

    public byte[] value() {
        return value;
    }

    public String asHexString() {
        return Hex.encodeHexString(value);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final SharedSecret that = (SharedSecret) o;
        return Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "SharedSecret{value=*****}";
    }

    @Override
    public void writeExternal(final ObjectOutput out) throws IOException {
        deny();
    }

    @Override
    public void readExternal(final ObjectInput in) throws IOException, ClassNotFoundException {
        deny();
    }

    private static void deny() {
        throw new UnsupportedOperationException("Not allowed");
    }

}
