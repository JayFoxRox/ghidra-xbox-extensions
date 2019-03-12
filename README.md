# Original Xbox Extensions for the Ghidra SRE Framework

**These extensions are not stable (yet)**

It is strongly discouraged to use these extensions for actual work.

Many features are incomplete or broken, and might result in broken projects.


## Requirements

* [Java Development Kit (JDK)](https://openjdk.java.net/)
* [Gradle Build Tool](https://gradle.org/)
* [Ghidra SRE Framework source code](https://github.com/NationalSecurityAgency/ghidra)


## Compiling

```
gradle -PGHIDRA_INSTALL_DIR=<ghidra-path>
```

*(Replace `<ghidra-path>` with the absolute path to the Ghidra SRE Framework source code)*


## Installing

In Ghidra, select "File" &rarr; "Install Extensions..." &rarr; "+" ("Add Extension") and choose the ZIP file from the dist folder.


## Using

The extension should automatically pick the "Xbox Exectuable (XBE)" format when importing a XBE file.


## License

See the license header in each source file.
