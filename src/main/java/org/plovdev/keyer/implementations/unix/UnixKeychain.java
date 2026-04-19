package org.plovdev.keyer.implementations.unix;

import org.plovdev.keyer.Keychain;

public class UnixKeychain implements Keychain {
    @Override
    public void init(String appId) {
        throw new UnsupportedOperationException("Unix systems not implementated yet!");
    }

    @Override
    public char[] getPassword(String alias) {
        throw new UnsupportedOperationException("Unix systems not implementated yet!");
    }

    @Override
    public boolean setPassword(String alias, char[] newPassword) {
        throw new UnsupportedOperationException("Unix systems not implementated yet!");
    }

    @Override
    public boolean deletePassword(String alias) {
        throw new UnsupportedOperationException("Unix systems not implementated yet!");
    }
}