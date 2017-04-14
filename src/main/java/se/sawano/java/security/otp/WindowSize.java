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

import static org.apache.commons.lang3.Validate.isTrue;

public final class WindowSize {

    public static WindowSize windowSize(final int value) {
        return new WindowSize(value);
    }

    private final int value;

    private WindowSize(final int value) {
        isTrue(value >= 0, "Window size cannot be negative");
        isTrue(value % 2 == 1, "Window size must be an odd number");
        this.value = value;
    }

    public int value() {
        return value;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final WindowSize that = (WindowSize) o;
        return value == that.value;
    }

    @Override
    public int hashCode() {
        return Integer.hashCode(value);
    }

    @Override
    public String toString() {
        return "WindowSize{" +
                "value=" + value +
                '}';
    }
}
