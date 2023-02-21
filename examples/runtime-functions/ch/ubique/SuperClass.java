package ch.ubique;

public class SuperClass {
    public static String getArgument() {
        throw new NoSuchMethodError();
    }
    public static void print(String argument) {
        throw new NoSuchMethodError();
    }
}