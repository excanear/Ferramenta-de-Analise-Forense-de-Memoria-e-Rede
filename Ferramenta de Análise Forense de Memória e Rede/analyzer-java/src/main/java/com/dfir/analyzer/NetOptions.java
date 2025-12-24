package com.dfir.analyzer;

public class NetOptions {
    private static volatile boolean allowNetwork = true;

    public static void setAllowNetwork(boolean allow) { allowNetwork = allow; }
    public static boolean isAllowNetwork() { return allowNetwork; }
}
