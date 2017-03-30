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

package se.sawano.java.security.otp.user;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import se.sawano.java.security.otp.user.UserId;

public class UserIdTest {

    @Test
    public void should_not_accept_user_id_longer_than_max_length() throws Exception {
        final UserId userId = new UserId(StringUtils.repeat("a", UserId.MAX_LENGTH));
    }
}