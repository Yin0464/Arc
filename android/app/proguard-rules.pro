-keep class com.arc.app.Native { *; }
-keep class com.arc.app.Native$LatencyListener { *; }
-keepclassmembers class com.arc.app.Native {
    native <methods>;
    public static *;
}
