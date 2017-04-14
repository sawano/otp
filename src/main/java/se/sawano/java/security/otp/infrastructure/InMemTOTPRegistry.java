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

package se.sawano.java.security.otp.infrastructure;

import se.sawano.java.security.otp.TOTP;
import se.sawano.java.security.otp.user.UserId;
import se.sawano.java.security.otp.user.persistence.TOTPRegistry;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import static org.apache.commons.lang3.Validate.notNull;

/**
 * In-memory implementation of a {@link TOTPRegistry}. This is not intended for production use.
 */
public class InMemTOTPRegistry implements TOTPRegistry {

    private final ConcurrentHashMap<UserId, ConcurrentSkipListSet<Entry>> store = new ConcurrentHashMap<>();

    @Override
    public void markConsumed(final TOTP totp, final UserId userId) {
        notNull(userId);
        notNull(totp);

        getConsumedTotpsFor(userId).add(new Entry(totp));
    }

    @Override
    public boolean isConsumed(final TOTP totp, final UserId userId) {
        notNull(totp);
        notNull(userId);

        return Optional.ofNullable(store.get(userId))
                       .map(set -> set.contains(new Entry(totp)))
                       .orElse(false);
    }

    private ConcurrentSkipListSet<Entry> getConsumedTotpsFor(final UserId userId) {
        return store.computeIfAbsent(userId, id -> new ConcurrentSkipListSet<>());
    }

    private static final class Entry implements Comparable<Entry> {

        private final TOTP totp;

        private Entry(final TOTP totp) {this.totp = totp;}

        @Override
        public int compareTo(final Entry o) {
            return totp.value().compareTo(o.totp.value());
        }
    }

}
