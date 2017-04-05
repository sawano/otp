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

/**
 * OPTIONAL: The digits parameter may have the values 6 or 8, and determines how long of a one-time passcode to display
 * to the user. The default is 6.
 * <p>
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#digits
 * </p>
 */
public enum Digits implements Parameter {

    SIX(6),
    EIGHT(8);

    private final int value;

    Digits(final int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }

    @Override
    public String parameterPair() {
        return "digits=" + value;
    }
}
