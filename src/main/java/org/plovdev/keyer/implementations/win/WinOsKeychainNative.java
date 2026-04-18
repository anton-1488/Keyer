package org.plovdev.keyer.implementations.win;

public class WinOsKeychainNative {
    public char[] getPassword(String appId, String alias) {
        return new char[0];
    }

    public void setPassword(String appId, String alias, char[] newPassword) {
    }

    public void deletePassword(String appId, String alias) {
    }
}