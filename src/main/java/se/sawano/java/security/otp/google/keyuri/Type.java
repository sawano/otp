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

/**
 * Valid types are hotp and totp, to distinguish whether the key will be used for counter-based HOTP or for TOTP.
 *
 * <p>
 * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format#types
 * </p>
 */
public enum Type {

    HOTP,

    TOTP
}
