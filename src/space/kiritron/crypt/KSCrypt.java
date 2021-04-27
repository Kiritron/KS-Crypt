/*
 * Copyright 2021 Kiritron's Space
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package space.kiritron.crypt;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Класс с методами для шифрования и дешифрования по стандартам шифрования Киритрон'с Спэйс.
 * @author Киритрон Стэйблкор
 */

public class KSCrypt {
    /**
     * Шифрование String по стандартам КС Крипт.
     * @param DataToCrypt Данные в String, которые нужно зашифровать.
     * @param Key Ключ в String.
     * @return возвращает шифр.
     */
    public static String encrypt(String DataToCrypt, String Key) throws NoSuchAlgorithmException, IOException {
        if (DataToCrypt == null || Key == null) {
            throw new IOException("Данные и/или ключ не должны быть равны NULL");
        }

        DataToCrypt = EncodeBase64(DataToCrypt); // Кодировать в Base64
        DataToCrypt = encodeSymbols(DataToCrypt + "!0!0!09912912921257128510!0!0!"); // Кодировать согласно таблице КС Крипт

        String HashKey;
        HashKey = getHashKey(Key);
        HashKey = DeleteLettersFromHashKey(HashKey);

        String SecretCode;
        SecretCode = GetSecretCodeFromHashKey(HashKey);

        boolean[] Index = new boolean[10];
        if (SecretCode.contains("0")) {Index[0] = true;} else {Index[0] = false;}
        if (SecretCode.contains("1")) {Index[1] = true;} else {Index[1] = false;}
        if (SecretCode.contains("2")) {Index[2] = true;} else {Index[2] = false;}
        if (SecretCode.contains("3")) {Index[3] = true;} else {Index[3] = false;}
        if (SecretCode.contains("4")) {Index[4] = true;} else {Index[4] = false;}
        if (SecretCode.contains("5")) {Index[5] = true;} else {Index[5] = false;}
        if (SecretCode.contains("6")) {Index[6] = true;} else {Index[6] = false;}
        if (SecretCode.contains("7")) {Index[7] = true;} else {Index[7] = false;}
        if (SecretCode.contains("8")) {Index[8] = true;} else {Index[8] = false;}
        if (SecretCode.contains("9")) {Index[9] = true;} else {Index[9] = false;}

        DataToCrypt = genEncryptedString(DataToCrypt, Index);
        DataToCrypt = EncodeBase64(DataToCrypt);

        return DataToCrypt;
    }

    /**
     * Дешифрование String по стандартам КС Крипт.
     * @param DataToDecrypt Данные, которые нужно дешифровать.
     * @param Key Ключ в String.
     * @return возвращает текст до шифрования.
     */
    public static String decrypt(String DataToDecrypt, String Key) throws NoSuchAlgorithmException, IOException {
        DataToDecrypt = DecodeBase64(DataToDecrypt);

        String HashKey;
        HashKey = getHashKey(Key);
        HashKey = DeleteLettersFromHashKey(HashKey);

        String SecretCode;
        SecretCode = GetSecretCodeFromHashKey(HashKey);

        boolean[] Index = new boolean[10];
        if (SecretCode.contains("0")) {Index[0] = true;} else {Index[0] = false;}
        if (SecretCode.contains("1")) {Index[1] = true;} else {Index[1] = false;}
        if (SecretCode.contains("2")) {Index[2] = true;} else {Index[2] = false;}
        if (SecretCode.contains("3")) {Index[3] = true;} else {Index[3] = false;}
        if (SecretCode.contains("4")) {Index[4] = true;} else {Index[4] = false;}
        if (SecretCode.contains("5")) {Index[5] = true;} else {Index[5] = false;}
        if (SecretCode.contains("6")) {Index[6] = true;} else {Index[6] = false;}
        if (SecretCode.contains("7")) {Index[7] = true;} else {Index[7] = false;}
        if (SecretCode.contains("8")) {Index[8] = true;} else {Index[8] = false;}
        if (SecretCode.contains("9")) {Index[9] = true;} else {Index[9] = false;}

        DataToDecrypt = genDecryptedString(DataToDecrypt, Index);
        DataToDecrypt = decodeSymbols(DataToDecrypt);
        if (DataToDecrypt.contains("!0!0!09912912921257128510!0!0!")) {
            DataToDecrypt = DataToDecrypt.replace("!0!0!09912912921257128510!0!0!", "");
        } else {
            throw new IOException("Дешифрование не удалось. Неправильный ключ.");
        }
        DataToDecrypt = DecodeBase64(DataToDecrypt);

        return DataToDecrypt;
    }

    private static String GenHashMD5(String Message) throws NoSuchAlgorithmException {
        String TranslateKey = Message;
        MessageDigest m = MessageDigest.getInstance("MD5");
        m.reset();
        m.update(TranslateKey.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String hashtext = bigInt.toString(16);
        while(hashtext.length() < 32 ){
            hashtext = "0"+hashtext;
        }
        return hashtext;
    }

    private static String GenHashSHA1(String Message) throws NoSuchAlgorithmException {
        String TranslateKey = Message;
        MessageDigest m = MessageDigest.getInstance("SHA1");
        m.reset();
        m.update(TranslateKey.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String hashtext = bigInt.toString(16);
        while(hashtext.length() < 32 ){
            hashtext = "0"+hashtext;
        }
        return hashtext;
    }

    private static String GenHashSHA256(String Message) throws NoSuchAlgorithmException {
        String TranslateKey = Message;
        MessageDigest m = MessageDigest.getInstance("SHA-256");
        m.reset();
        m.update(TranslateKey.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String hashtext = bigInt.toString(16);
        while(hashtext.length() < 32 ){
            hashtext = "0"+hashtext;
        }
        return hashtext;
    }

    private static String EncodeBase64(String Message) {
        return Base64.getEncoder().withoutPadding().encodeToString(Message.getBytes());
    }

    private static String DecodeBase64(String Message) {
        return new String(Base64.getDecoder().decode(Message));
    }
    
    private static String getHashKey(String Key) throws NoSuchAlgorithmException {
        String hashtext = GenHash(Key);
        return hashtext;
    }

    private static String GenHash(String Key) throws NoSuchAlgorithmException {
        String out = GenHashMD5(GenHashSHA256(GenHashSHA1(GenHashMD5(GenHashSHA256(Key)))));
        return out;
    }

    private static String DeleteLettersFromHashKey(String HashKey) {
        return HashKey.chars().filter(c -> !Character.isLetter(c)).mapToObj(c -> String.valueOf((char) c)).collect(Collectors.joining());
    }

    private static String GetSecretCodeFromHashKey(String HashKey) throws IOException {
        long longOfHashKey;

        if (HashKey.length() > 19) {
            HashKey = HashKey.substring(0, 19);
        }

        if (HashKey.matches("[-+]?\\d+")) { // На всякий случай...
            longOfHashKey = new Long(HashKey);
            if (longOfHashKey % 2 == 0) {
                if (String.valueOf(longOfHashKey).length() % 2 == 0) {
                    longOfHashKey = longOfHashKey % String.valueOf(longOfHashKey).length();
                } else {
                    longOfHashKey = longOfHashKey % (String.valueOf(longOfHashKey).length() + 1);
                }
            } else {
                if (String.valueOf(longOfHashKey).length() % 2 == 0) {
                    longOfHashKey = longOfHashKey % (String.valueOf(longOfHashKey).length() + 1);
                } else {
                    longOfHashKey = longOfHashKey % (String.valueOf(longOfHashKey).length());
                }
            }
        } else {
            throw new IOException("Полученный хеш ключа не содержит чисел. Придумайте другой ключ или измените его. Вы, кстати, везунчик, ведь ожидалось, что это" +
                    "будет очень редким явлением.");
        }

        String longOfHashKey_inString;
        longOfHashKey_inString = String.valueOf(longOfHashKey);
        if (longOfHashKey_inString.length() > 5) {
            longOfHashKey_inString = longOfHashKey_inString.substring(0, 5);
        }

        return longOfHashKey_inString;
    }

    private static String encodeSymbols(String Message) {
        String Data = Message;

        Data = Data.replaceAll(" ","/%%%");

        Data = Data.replaceAll("A","/0000000");
        Data = Data.replaceAll("B","/0000002");
        Data = Data.replaceAll("C","/0000004");
        Data = Data.replaceAll("D","/0000006");
        Data = Data.replaceAll("E","/0000008");
        Data = Data.replaceAll("F","/0000010");
        Data = Data.replaceAll("G","/0000012");
        Data = Data.replaceAll("H","/0000014");
        Data = Data.replaceAll("I","/0000016");
        Data = Data.replaceAll("J","/0000018");
        Data = Data.replaceAll("K","/0000020");
        Data = Data.replaceAll("L","/0000022");
        Data = Data.replaceAll("M","/0000024");
        Data = Data.replaceAll("N","/0000026");
        Data = Data.replaceAll("O","/0000028");
        Data = Data.replaceAll("P","/0000030");
        Data = Data.replaceAll("Q","/0000032");
        Data = Data.replaceAll("R","/0000034");
        Data = Data.replaceAll("S","/0000036");
        Data = Data.replaceAll("T","/0000038");
        Data = Data.replaceAll("U","/0000040");
        Data = Data.replaceAll("V","/0000042");
        Data = Data.replaceAll("W","/0000044");
        Data = Data.replaceAll("X","/0000046");
        Data = Data.replaceAll("Y","/0000048");
        Data = Data.replaceAll("Z","/0000050");

        Data = Data.replaceAll("a","/0000052");
        Data = Data.replaceAll("b","/0000054");
        Data = Data.replaceAll("c","/0000056");
        Data = Data.replaceAll("d","/0000058");
        Data = Data.replaceAll("e","/0000060");
        Data = Data.replaceAll("f","/0000062");
        Data = Data.replaceAll("g","/0000064");
        Data = Data.replaceAll("h","/0000066");
        Data = Data.replaceAll("i","/0000068");
        Data = Data.replaceAll("j","/0000070");
        Data = Data.replaceAll("k","/0000072");
        Data = Data.replaceAll("l","/0000074");
        Data = Data.replaceAll("m","/0000076");
        Data = Data.replaceAll("n","/0000078");
        Data = Data.replaceAll("o","/0000080");
        Data = Data.replaceAll("p","/0000082");
        Data = Data.replaceAll("q","/0000084");
        Data = Data.replaceAll("r","/0000086");
        Data = Data.replaceAll("s","/0000088");
        Data = Data.replaceAll("t","/0000090");
        Data = Data.replaceAll("u","/0000092");
        Data = Data.replaceAll("v","/0000094");
        Data = Data.replaceAll("w","/0000096");
        Data = Data.replaceAll("x","/0000098");
        Data = Data.replaceAll("y","/0000100");
        Data = Data.replaceAll("z","/0000102");

        Data = Data.replaceAll("!","/0000132");
        Data = Data.replaceAll("\\?","/0000133");
        Data = Data.replaceAll("<","/0000134");
        Data = Data.replaceAll(">","/0000135");
        Data = Data.replaceAll("\\.","/0000136");
        Data = Data.replaceAll(",","/0000137");
        Data = Data.replaceAll("`","/0000138");
        Data = Data.replaceAll("~","/0000139");
        Data = Data.replaceAll("\\^","/0000140");
        Data = Data.replaceAll(":","/0000141");
        Data = Data.replaceAll("\\$","/0000142");
        Data = Data.replaceAll(";","/0000143");
        Data = Data.replaceAll("№","/0000144");
        Data = Data.replaceAll("#","/0000145");
        Data = Data.replaceAll("@","/0000146");
        Data = Data.replaceAll("'","/0000147");
        Data = Data.replaceAll("\\(","/0000148");
        Data = Data.replaceAll("\\)","/0000149");
        Data = Data.replaceAll("\\*","/0000150");
        Data = Data.replaceAll("\\|","/0000151");
        Data = Data.replaceAll("&","/0000152");
        Data = Data.replaceAll("=","/0000153");
        Data = Data.replaceAll("\\+","/0000154");
        Data = Data.replaceAll("-","/0000155");
        Data = Data.replaceAll("_","/0000156");
        Data = Data.replaceAll("\\{","/0000157");
        Data = Data.replaceAll("}","/0000158");
        Data = Data.replaceAll("\\[","/0000159");
        Data = Data.replaceAll("]","/0000160");

        return Data;
    }

    private static String decodeSymbols(String Message) {
        String Data = Message;

        Data = Data.replaceAll("/0000102","z");
        Data = Data.replaceAll("/0000100","y");
        Data = Data.replaceAll("/0000098","x");
        Data = Data.replaceAll("/0000096","w");
        Data = Data.replaceAll("/0000094","v");
        Data = Data.replaceAll("/0000092","u");
        Data = Data.replaceAll("/0000090","t");
        Data = Data.replaceAll("/0000088","s");
        Data = Data.replaceAll("/0000086","r");
        Data = Data.replaceAll("/0000084","q");
        Data = Data.replaceAll("/0000082","p");
        Data = Data.replaceAll("/0000080","o");
        Data = Data.replaceAll("/0000078","n");
        Data = Data.replaceAll("/0000076","m");
        Data = Data.replaceAll("/0000074","l");
        Data = Data.replaceAll("/0000072","k");
        Data = Data.replaceAll("/0000070","j");
        Data = Data.replaceAll("/0000068","i");
        Data = Data.replaceAll("/0000066","h");
        Data = Data.replaceAll("/0000064","g");
        Data = Data.replaceAll("/0000062","f");
        Data = Data.replaceAll("/0000060","e");
        Data = Data.replaceAll("/0000058","d");
        Data = Data.replaceAll("/0000056","c");
        Data = Data.replaceAll("/0000054","b");
        Data = Data.replaceAll("/0000052","a");

        Data = Data.replaceAll("/0000050","Z");
        Data = Data.replaceAll("/0000048","Y");
        Data = Data.replaceAll("/0000046","X");
        Data = Data.replaceAll("/0000044","W");
        Data = Data.replaceAll("/0000042","V");
        Data = Data.replaceAll("/0000040","U");
        Data = Data.replaceAll("/0000038","T");
        Data = Data.replaceAll("/0000036","S");
        Data = Data.replaceAll("/0000034","R");
        Data = Data.replaceAll("/0000032","Q");
        Data = Data.replaceAll("/0000030","P");
        Data = Data.replaceAll("/0000028","O");
        Data = Data.replaceAll("/0000026","N");
        Data = Data.replaceAll("/0000024","M");
        Data = Data.replaceAll("/0000022","L");
        Data = Data.replaceAll("/0000020","K");
        Data = Data.replaceAll("/0000018","J");
        Data = Data.replaceAll("/0000016","I");
        Data = Data.replaceAll("/0000014","H");
        Data = Data.replaceAll("/0000012","G");
        Data = Data.replaceAll("/0000010","F");
        Data = Data.replaceAll("/0000008","E");
        Data = Data.replaceAll("/0000006","D");
        Data = Data.replaceAll("/0000004","C");
        Data = Data.replaceAll("/0000002","B");
        Data = Data.replaceAll("/0000000","A");

        Data = Data.replaceAll("/0000132","!");
        Data = Data.replaceAll("/0000133","\\?");
        Data = Data.replaceAll("/0000134","<");
        Data = Data.replaceAll("/0000135",">");
        Data = Data.replaceAll("/0000136","\\.");
        Data = Data.replaceAll("/0000137",",");
        Data = Data.replaceAll("/0000138","`");
        Data = Data.replaceAll("/0000139","~");
        Data = Data.replaceAll("/0000140","\\^");
        Data = Data.replaceAll("/0000141",":");
        Data = Data.replaceAll("/0000142","\\$");
        Data = Data.replaceAll("/0000143",";");
        Data = Data.replaceAll("/0000144","№");
        Data = Data.replaceAll("/0000145","#");
        Data = Data.replaceAll("/0000146","@");
        Data = Data.replaceAll("/0000147","'");
        Data = Data.replaceAll("/0000148","\\(");
        Data = Data.replaceAll("/0000149","\\)");
        Data = Data.replaceAll("/0000150","\\*");
        Data = Data.replaceAll("/0000151","\\|");
        Data = Data.replaceAll("/0000152","&");
        Data = Data.replaceAll("/0000153","=");
        Data = Data.replaceAll("/0000154","\\+");
        Data = Data.replaceAll("/0000155","-");
        Data = Data.replaceAll("/0000156","_");
        Data = Data.replaceAll("/0000157","\\{");
        Data = Data.replaceAll("/0000158","}");
        Data = Data.replaceAll("/0000159","\\[");
        Data = Data.replaceAll("/0000160","]");

        Data = Data.replaceAll("/%%%"," ");

        return Data;
    }

    private static String genEncryptedString(String Data, boolean[] Index) {
        if (Index[0]) {
            Data = Data.replaceAll("0","/%%k");
        } else {
            Data = Data.replaceAll("0","/%%a");
        }

        if (Index[1]) {
            if (Index[0]) {
                Data = Data.replaceAll("1","/%%l");
            } else {
                Data = Data.replaceAll("1", "/%%k");
            }
        } else {
            if (Index[0]) {
                Data = Data.replaceAll("1","/%%a");
            } else {
                Data = Data.replaceAll("1", "/%%b");
            }
        }

        if (Index[2]) {
            Data = Data.replaceAll("2","/%%m");
        } else {
            Data = Data.replaceAll("2","/%%c");
        }

        if (Index[3]) {
            if (Index[2]) {
                Data = Data.replaceAll("3","/%%c");
            } else {
                Data = Data.replaceAll("3","/%%n");
            }
        } else {
            if (Index[2]) {
                Data = Data.replaceAll("3","/%%d");
            } else {
                Data = Data.replaceAll("3","/%%m");
            }
        }

        if (Index[4]) {
            Data = Data.replaceAll("4","/%%o");
        } else {
            Data = Data.replaceAll("4","/%%e");
        }

        if (Index[5]) {
            if (Index[4]) {
                Data = Data.replaceAll("5","/%%e");
            } else {
                Data = Data.replaceAll("5","/%%p");
            }
        } else {
            if (Index[4]) {
                Data = Data.replaceAll("5","/%%f");
            } else {
                Data = Data.replaceAll("5","/%%o");
            }
        }

        if (Index[6]) {
            Data = Data.replaceAll("6","/%%q");
        } else {
            Data = Data.replaceAll("6","/%%g");
        }

        if (Index[7]) {
            if (Index[6]) {
                Data = Data.replaceAll("7","/%%r");
            } else {
                Data = Data.replaceAll("7","/%%q");
            }
        } else {
            if (Index[6]) {
                Data = Data.replaceAll("7","/%%g");
            } else {
                Data = Data.replaceAll("7","/%%h");
            }
        }

        if (Index[8]) {
            Data = Data.replaceAll("8","/%%s");
        } else {
            Data = Data.replaceAll("8","/%%i");
        }

        if (Index[9]) {
            if (Index[8]) {
                Data = Data.replaceAll("9","/%%i");
            } else {
                Data = Data.replaceAll("9","/%%t");
            }
        } else {
            if (Index[8]) {
                Data = Data.replaceAll("9","/%%j");
            } else {
                Data = Data.replaceAll("9","/%%s");
            }
        }

        return Data;
    }

    private static String genDecryptedString(String Data, boolean[] Index) {
        if (Index[0]) {
            Data = Data.replaceAll("/%%k","0");
        } else {
            Data = Data.replaceAll("/%%a","0");
        }

        if (Index[1]) {
            if (Index[0]) {
                Data = Data.replaceAll("/%%l","1");
            } else {
                Data = Data.replaceAll("/%%k","1");
            }
        } else {
            if (Index[0]) {
                Data = Data.replaceAll("/%%a","1");
            } else {
                Data = Data.replaceAll( "/%%b","1");
            }
        }

        if (Index[2]) {
            Data = Data.replaceAll("/%%m","2");
        } else {
            Data = Data.replaceAll("/%%c","2");
        }

        if (Index[3]) {
            if (Index[2]) {
                Data = Data.replaceAll("/%%c","3");
            } else {
                Data = Data.replaceAll("/%%n","3");
            }
        } else {
            if (Index[2]) {
                Data = Data.replaceAll("/%%d","3");
            } else {
                Data = Data.replaceAll("/%%m","3");
            }
        }

        if (Index[4]) {
            Data = Data.replaceAll("/%%o","4");
        } else {
            Data = Data.replaceAll("/%%e","4");
        }

        if (Index[5]) {
            if (Index[4]) {
                Data = Data.replaceAll("/%%e","5");
            } else {
                Data = Data.replaceAll("/%%p","5");
            }
        } else {
            if (Index[4]) {
                Data = Data.replaceAll("/%%f","5");
            } else {
                Data = Data.replaceAll("/%%o","5");
            }
        }

        if (Index[6]) {
            Data = Data.replaceAll("/%%q","6");
        } else {
            Data = Data.replaceAll("/%%g","6");
        }

        if (Index[7]) {
            if (Index[6]) {
                Data = Data.replaceAll("/%%r","7");
            } else {
                Data = Data.replaceAll("/%%q","7");
            }
        } else {
            if (Index[6]) {
                Data = Data.replaceAll("/%%g","7");
            } else {
                Data = Data.replaceAll("/%%h","7");
            }
        }

        if (Index[8]) {
            Data = Data.replaceAll("/%%s","8");
        } else {
            Data = Data.replaceAll("/%%i","8");
        }

        if (Index[9]) {
            if (Index[8]) {
                Data = Data.replaceAll("/%%i","9");
            } else {
                Data = Data.replaceAll("/%%t","9");
            }
        } else {
            if (Index[8]) {
                Data = Data.replaceAll("/%%j","9");
            } else {
                Data = Data.replaceAll("/%%s","9");
            }
        }

        return Data;
    }
}
