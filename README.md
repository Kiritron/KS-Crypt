### **КС Крипт**

##### Версия: 1.0
##### Описание

Java библиотека для простой реализации шифрования с симметричным ключом по алгоритму КС.

##### Обратите внимание
Мы не рекомендуем использовать этот алгоритм шифрования единственным методом шифрования в проекте. По возможности старайтесь комбинировать этот алгоритм с другими.

##### Использование
Импортируйте методы из класса KSCrypt
```java
import static space.kiritron.crypt.KSCrypt.encrypt;
import static space.kiritron.crypt.KSCrypt.decrypt;
```
Думаю, что где что комментировать не обязательно :)

Чтобы зашифровать строку, используйте следующий код
```java
encrypt("Строка, которую нужно зашифровать", "Ключ", "Соль");
```
Чтобы расшифровать строку
```java
decrypt("Строка, которую нужно расшифровать", "Ключ", "Соль");
```
Всё просто!

##### Совет
Пусть этой библиотекой просто так файл не зашифруешь, но файл можно конвертировать в Base64, а строку Base64 пропустить через КС Крипт.

#### Приятного пользования!
