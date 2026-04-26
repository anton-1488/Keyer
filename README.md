# Keyer

**Keyer** — это современная и легковесная библиотека для работы с системными хранилищами паролей напрямую из Java.

![Java Version](https://img.shields.io/badge/Java-25%2B-blue)
![License](https://img.shields.io/badge/License-Public%20Domain-blue)

## Особенности

- **Project Panama**: Максимальная производительность нативных вызовов без тяжелых зависимостей.
- **Безопасность**: Работа с секретами через `char[]` для минимизации следов в памяти JVM.
- **Кроссплатформенность**: Единый интерфейс для macOS, Windows и Linux.
- **Zero Dependencies**: Только стандартная JDK, SLF4J для логирования и JUnit для тестов.

## Доступно на Maven central
```xml
<dependency>
    <groupId>io.github.anton-1488</groupId>
    <artifactId>Keyer</artifactId>
    <version>1.6</version>
</dependency>
```

## Быстрый старт

### Инициализация

Библиотека автоматически определит вашу ОС и выберет нужный бэкенд:

```java
Keychain keychain = Keychain.getKeychain("MyAwesomeApp");

keychain.setPassword("alias","123".toCharArray()); // set password
char[] password = keychain.getPassword(alias); // get password
```

### See also examples and tests

# Не забудьте добавить --enable-native-access=ALL-UNNAMED в VM-OPTIONS:)