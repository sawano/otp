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
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.Charset;

class CodecUtils {

    public static String encodeHexString(final String value, final Charset charset) {
        return Hex.encodeHexString(value.getBytes(charset));
    }

    public static byte[] decodeHex(final String hexString) {
        try {
            return Hex.decodeHex(hexString.toCharArray());
        } catch (final DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decodeBase32(final byte[] base32Bytes) {
        return new Base32(false).decode(base32Bytes);
    }

    public static char[] encodeToHex(final byte[] value) {
        return Hex.encodeHex(value);
    }
}
