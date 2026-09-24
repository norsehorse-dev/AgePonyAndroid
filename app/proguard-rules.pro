# AgePony release keep rules (R8), applied on top of proguard-android-optimize.txt.
#
# What each block is for:
#   1. Attributes: generic signatures, inner classes and annotations that kotlinx.serialization
#      and Kotlin need at runtime, plus line numbers so crash reports stay readable. The source
#      file name is replaced by a constant so no build path or file name leaks into the APK.
#   2. kotlinx.serialization: the library ships its own consumer rules; these are the standard
#      extra rules for our own @Serializable classes (vault snapshot, identities, recipients,
#      signers, notes, transfer metadata). The vault file format depends on them, so the
#      classes, their companions and generated serializers are kept whole. Cheap: a handful of
#      small model classes.
#   3. Enums: rememberSaveable puts enums in the saved-state Bundle (Java serialization, which
#      looks up values() by reflection), and AgeTab is restored by name(). The default file
#      already keeps values()/valueOf(); repeated here so it does not depend on that file.
#   4. ViewModel: VaultViewModel is created reflectively by the default factory through its
#      (Application) constructor. lifecycle ships this rule too; kept explicitly.
#   5. BouncyCastle: only the lightweight API is used (org.bouncycastle.crypto, math, asn1,
#      pqc.crypto.mlkem, jce.ECNamedCurveTable). No JCA provider is registered or looked up by
#      name ("BC" is never requested; MessageDigest/Mac/KeyStore lookups go to the platform
#      providers), and the lightweight classes use no reflection, so nothing is kept and R8 may
#      shrink BC freely. Unused provider and LDAP classes reference javax.naming, which Android
#      does not have.
#   6. OkHttp / Okio: ship their own rules. The -dontwarn lines cover the optional TLS
#      providers OkHttp probes for on the JVM (Conscrypt, BouncyCastle JSSE, OpenJSSE).
#   7. zxing core, CameraX, Compose, AndroidX biometric/fragment/lifecycle, kotlinx.coroutines,
#      and Google Play In-App Review (play flavor only): all ship consumer rules or use no
#      reflection, so no rules are needed here. Listed so nobody adds broad keeps "just in case".
#
# Reproducibility: no -printmapping, -printseeds, -printusage or -dump to absolute paths (AGP
# writes the mapping under build/outputs/mapping/ on its own), and nothing here depends on time
# or environment, so the same sources and toolchain give the same APK.

# ---- 1. Attributes ----
-keepattributes Signature,InnerClasses,EnclosingMethod
-keepattributes RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations,AnnotationDefault
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ---- 2. kotlinx.serialization (our @Serializable classes) ----
# Keep the classes, their members and names, so the persisted vault JSON never depends on
# obfuscation. Generated serializers are nested classes named $$serializer.
-keep @kotlinx.serialization.Serializable class com.agepony.** { *; }
-keep class com.agepony.**$$serializer { *; }
-keepclassmembers class com.agepony.** {
    *** Companion;
}
-keepclasseswithmembers class com.agepony.** {
    kotlinx.serialization.KSerializer serializer(...);
}
# Standard rules from the kotlinx.serialization README, scoped to our package.
# (<1> matches only what the wildcard after "com.agepony." caught, hence the prefix.)
-if @kotlinx.serialization.Serializable class com.agepony.**
-keepclassmembers class com.agepony.<1> {
    static com.agepony.<1>$Companion Companion;
}
-if @kotlinx.serialization.Serializable class com.agepony.** {
    static **$* *;
}
-keepclassmembers class <2>$<3> {
    kotlinx.serialization.KSerializer serializer(...);
}
-if @kotlinx.serialization.Serializable class com.agepony.** {
    public static ** INSTANCE;
}
-keepclassmembers class com.agepony.<1> {
    public static com.agepony.<1> INSTANCE;
    kotlinx.serialization.KSerializer serializer(...);
}

# ---- 3. Enums ----
-keepclassmembers enum com.agepony.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ---- 4. ViewModel ----
-keepclassmembers class com.agepony.app.vault.VaultViewModel {
    <init>(android.app.Application);
}

# ---- 5. BouncyCastle ----
-dontwarn javax.naming.**

# ---- 6. OkHttp / Okio ----
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.jsse.**
-dontwarn org.openjsse.**
