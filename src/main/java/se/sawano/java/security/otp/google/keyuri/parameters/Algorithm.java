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
 * OPTIONAL: The algorithm may have the values:
 * <ul>
 * <li>SHA1 (Default)</li>
 * <li>SHA256</li>
 * <li>SHA512</li>
 * </ul>
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#algorithm
 */
public enum Algorithm {

    SHA1("SHA1"),
    SHA256("SHA256"),
    SHA512("SHA512");

    private final String value;

    Algorithm(final String value) {this.value = value;}

    public String value() {
        return value;
    }
}
