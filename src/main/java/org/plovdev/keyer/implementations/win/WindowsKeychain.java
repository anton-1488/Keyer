package org.plovdev.keyer.implementations.win;

import org.plovdev.keyer.Keychain;

public class WindowsKeychain implements Keychain {
    @Override
    public void init(String appId) {

    }

    @Override
    public char[] getPassword(String alias) {
        return new char[0];
    }

    @Override
    public boolean setPassword(String alias, char[] newPassword) {
        return false;
    }

    @Override
    public boolean deletePassword(String alias) {
        return false;
    }
}