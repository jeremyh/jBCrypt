# Change Log

## 0.4.1 "StringBuilder"
 - Replaced StringBuffer with StringBuilder because it is more efficient.
 Efficiency is important because of the "work" required by this algorithm.
 - Added maven.compiler.source/target = 1.8 since that's the earliest still-maintained version of Java.
 - Added Maven enforcer plugin to be sure we are building with the latest defaults for Maven.
 Use the following to check plugin and dependency versions:
 ```text
mvn -U clean versions:display-plugin-updates
mvn -U clean versions:display-dependency-updates
```
 - Upgraded Junit from 3.8.1 to 4.13.1 (the latest).
 - Added Changelog file

## 0.4(.0) jeremyh/jBCrypt taken from djmdjm/jBCrypt

This is an alternative distribution of jBCrypt. It has been packaged to ease use in existing applications — especially those using Apache Maven.

The code is unchanged from the original jBCrypt 0.4, however:

The classes have been moved to a java package to avoid pollution of the global namespace. org.mindrot was chosen to reflect their original origin.
The JBCrypt class javadoc has been changed to version 0.4. The official package incorrectly contains 0.2 as the stated version.
A pom.xml file has been added for use with Maven