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

import org.apache.commons.lang3.StringUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import static org.apache.commons.lang3.Validate.isTrue;
import static org.apache.commons.lang3.Validate.notNull;

public final class TOTP implements Externalizable {

    public enum Length {
        ONE(1),
        TWO(2),
        THREE(3),
        FOUR(4),
        FIVE(5),
        SIX(6),
        SEVEN(7),
        EIGHT(8),
        NINE(9);

        private int value;

        Length(final int value) {
            this.value = value;
        }

        public int value() {
            return value;
        }

    }

    private final String value;
    private final Length length;

    public TOTP(final int value, final Length length) {
        notNull(length);
        isTrue(value >= 0, "Value cannot be negative");

        final String paddedString = StringUtils.leftPad(Integer.toString(value), length.value(), '0');
        isTrue(paddedString.length() == length.value(), "Value must have length: %d. Was: %d", length.value(), paddedString.length());

        this.value = paddedString;
        this.length = length;
    }

    public String value() {
        return value;
    }

    public Length length() {
        return length;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final TOTP totp = (TOTP) o;

        return value.equals(totp.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return "TOTP{value=*****}";
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
