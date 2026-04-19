package org.plovdev.keyer.utils;

import org.jetbrains.annotations.NotNull;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

public final class NativeUtils {
    /**
     * Private constructor to prevent instantiation of this utility class.
     *
     * @throws UnsupportedOperationException always.
     */
    private NativeUtils() {
        throw new UnsupportedOperationException();
    }

    /**
     * Converts a char array to a UTF-8 byte array.
     */
    public static byte @NotNull [] charsUTF_8ToBytes(char[] chars) {
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }

    /**
     * Converts a UTF-8 byte array to a char array.
     */
    public static char @NotNull [] bytesToCharsUTF_8(byte[] bytes) {
        CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
        char[] chars = new char[cb.remaining()];
        cb.get(chars);
        return chars;
    }

    /**
     * Converts a char array to a UTF-16LE byte array.
     */
    public static byte @NotNull [] charsUTF_16LEToBytes(char[] chars) {
        ByteBuffer bb = StandardCharsets.UTF_16LE.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        return bytes;
    }

    /**
     * Converts a UTF-16LE byte array to a char array.
     */
    public static char @NotNull [] bytesToCharsUTF_16LE(byte[] bytes) {
        CharBuffer cb = StandardCharsets.UTF_16LE.decode(ByteBuffer.wrap(bytes));
        char[] chars = new char[cb.remaining()];
        cb.get(chars);
        return chars;
    }

    /**
     * Finds and links a native function by name.
     *
     * @param name native function name
     * @param desc function signature descriptor
     * @return linked MethodHandle
     * @throws java.util.NoSuchElementException if the symbol is not found
     */
    public static @NotNull MethodHandle find(@NotNull SymbolLookup lookup, Linker linker, String name, FunctionDescriptor desc) {
        return lookup.find(name).map(s -> linker.downcallHandle(s, desc)).orElseThrow();
    }
}