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

import com.google.common.net.PercentEscaper;

import static org.apache.commons.lang3.Validate.notNull;

public class UriEncoder {

    public static String encode(final String value) {
        notNull(value);

        // TODO find another lib for escaping. Guava is a bit big for just this dependency.
        return new PercentEscaper("-._~" + ".", false).escape(value);
    }
}
