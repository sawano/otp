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

import static se.sawano.java.security.otp.CodecUtils.decodeBase32;

public class TestObjectFactory {

    public static SharedSecret sharedSecretFromBase32(final String base32Secret, final ShaAlgorithm algorithm) {
        final byte[] bytes = decodeBase32(base32Secret.getBytes());
        return SharedSecret.from(bytes, algorithm);
    }

}
