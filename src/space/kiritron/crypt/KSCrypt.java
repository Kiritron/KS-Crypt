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
    // Таблица с кодами символов //
    static String Char_SPACE = "/0000000";

    static String Char_A = "/0000001";
    static String Char_B = "/0000002";
    static String Char_C = "/0000004";
    static String Char_D = "/0000006";
    static String Char_E = "/0000008";
    static String Char_F = "/0000010";
    static String Char_G = "/0000012";
    static String Char_H = "/0000014";
    static String Char_I = "/0000016";
    static String Char_J = "/0000018";
    static String Char_K = "/0000020";
    static String Char_L = "/0000022";
    static String Char_M = "/0000024";
    static String Char_N = "/0000026";
    static String Char_O = "/0000028";
    static String Char_P = "/0000030";
    static String Char_Q = "/0000032";
    static String Char_R = "/0000034";
    static String Char_S = "/0000036";
    static String Char_T = "/0000038";
    static String Char_U = "/0000040";
    static String Char_V = "/0000042";
    static String Char_W = "/0000044";
    static String Char_X = "/0000046";
    static String Char_Y = "/0000048";
    static String Char_Z = "/0000050";

    static String Char_a = "/0000003";
    static String Char_b = "/0000005";
    static String Char_c = "/0000007";
    static String Char_d = "/0000009";
    static String Char_e = "/0000011";
    static String Char_f = "/0000013";
    static String Char_g = "/0000015";
    static String Char_h = "/0000017";
    static String Char_i = "/0000019";
    static String Char_j = "/0000021";
    static String Char_k = "/0000023";
    static String Char_l = "/0000025";
    static String Char_m = "/0000027";
    static String Char_n = "/0000029";
    static String Char_o = "/0000031";
    static String Char_p = "/0000033";
    static String Char_q = "/0000035";
    static String Char_r = "/0000037";
    static String Char_s = "/0000039";
    static String Char_t = "/0000041";
    static String Char_u = "/0000043";
    static String Char_v = "/0000045";
    static String Char_w = "/0000047";
    static String Char_x = "/0000049";
    static String Char_y = "/0000051";
    static String Char_z = "/0000053";

    static String Char_0 = "/0000052";
    static String Char_1 = "/0000054";
    static String Char_2 = "/0000055";
    static String Char_3 = "/0000056";
    static String Char_4 = "/0000057";
    static String Char_5 = "/0000058";
    static String Char_6 = "/0000059";
    static String Char_7 = "/0000060";
    static String Char_8 = "/0000061";
    static String Char_9 = "/0000062";

    static String Char_PLUS = "/0000063";
    static String Char_SOLIDUS = "/0000064";

    // Метод для проведения тестирования //

    /**
     * Метод для проведения тестирования шифрования и дешифрования строки алгоритмом КС Крипт. Данный метод полезен в случаях, когда вы что-то изменили в коде, например, таблицу кодирования, и хотите проверить, всё ли работает.
     * @param Data Данные, которые будут участвовать в тестировании.
     * @param KeyForEncrypt Ключ, который будет использован для шифрования данных.
     * @param KeyForDecrypt Ключ, который будет использован для дешифрования данных.
     */
    public static void crypt_test(String Data, String KeyForEncrypt, String KeyForDecrypt) {
        try {
            System.out.println("Данные до шифровки: " + Data);
            System.out.println("Ключ, который используется для шифрования: " + KeyForEncrypt);
            System.out.println("Ключ, который используется для дешифрования: " + KeyForDecrypt);
            System.out.println("===============");
            System.out.println("~ШиФрУеМ~");
            System.out.println("===============");
            Data = encrypt(Data, KeyForEncrypt);
            System.out.println("Зашифрованные данные: " + Data);
            System.out.println("===============");
            System.out.println("~ДеШиФрУеМ~");
            System.out.println("===============");
            Data = decrypt(Data, KeyForDecrypt);
            System.out.println("Дешифрованные данные: " + Data);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    // Сам код //

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
        DataToCrypt = encodeSymbols(DataToCrypt + "+0+0+09912912921257128510+0+0+"); // Кодировать согласно таблице КС Крипт

        String HashKey;
        HashKey = getHashKey(Key);
        HashKey = DeleteLettersFromHashKey(HashKey);

        String SecretCode;
        SecretCode = GetSecretCodeFromHashKey(HashKey);

        boolean[] Index = new boolean[10];
        Index[0] = SecretCode.contains("0");
        Index[1] = SecretCode.contains("1");
        Index[2] = SecretCode.contains("2");
        Index[3] = SecretCode.contains("3");
        Index[4] = SecretCode.contains("4");
        Index[5] = SecretCode.contains("5");
        Index[6] = SecretCode.contains("6");
        Index[7] = SecretCode.contains("7");
        Index[8] = SecretCode.contains("8");
        Index[9] = SecretCode.contains("9");

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
        Index[0] = SecretCode.contains("0");
        Index[1] = SecretCode.contains("1");
        Index[2] = SecretCode.contains("2");
        Index[3] = SecretCode.contains("3");
        Index[4] = SecretCode.contains("4");
        Index[5] = SecretCode.contains("5");
        Index[6] = SecretCode.contains("6");
        Index[7] = SecretCode.contains("7");
        Index[8] = SecretCode.contains("8");
        Index[9] = SecretCode.contains("9");

        DataToDecrypt = genDecryptedString(DataToDecrypt, Index);
        DataToDecrypt = decodeSymbols(DataToDecrypt);
        if (DataToDecrypt.contains("+0+0+09912912921257128510+0+0+")) {
            DataToDecrypt = DataToDecrypt.replace("+0+0+09912912921257128510+0+0+", "");
        } else {
            throw new IOException("Дешифрование не удалось. Неправильный ключ.");
        }
        DataToDecrypt = DecodeBase64(DataToDecrypt);

        return DataToDecrypt;
    }

    private static String GenHashMD5(String Message) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance("MD5");
        m.reset();
        m.update(Message.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        StringBuilder hashtext = new StringBuilder(bigInt.toString(16));
        while(hashtext.length() < 32 ){
            hashtext.insert(0, "0");
        }
        return hashtext.toString();
    }

    private static String GenHashSHA1(String Message) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance("SHA1");
        m.reset();
        m.update(Message.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        StringBuilder hashtext = new StringBuilder(bigInt.toString(16));
        while(hashtext.length() < 32 ){
            hashtext.insert(0, "0");
        }
        return hashtext.toString();
    }

    private static String GenHashSHA256(String Message) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance("SHA-256");
        m.reset();
        m.update(Message.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        StringBuilder hashtext = new StringBuilder(bigInt.toString(16));
        while(hashtext.length() < 32 ){
            hashtext.insert(0, "0");
        }
        return hashtext.toString();
    }

    private static String EncodeBase64(String Message) {
        return Base64.getEncoder().withoutPadding().encodeToString(Message.getBytes());
    }

    private static String DecodeBase64(String Message) {
        return new String(Base64.getDecoder().decode(Message));
    }
    
    private static String getHashKey(String Key) throws NoSuchAlgorithmException {
        return GenHash(Key);
    }

    private static String GenHash(String Key) throws NoSuchAlgorithmException {
        return GenHashMD5(GenHashSHA256(GenHashSHA1(GenHashMD5(GenHashSHA256(Key)))));
    }

    private static String DeleteLettersFromHashKey(String HashKey) {
        return HashKey.chars().filter(c -> !Character.isLetter(c)).mapToObj(c -> String.valueOf((char) c)).collect(Collectors.joining());
    }

    private static String GetSecretCodeFromHashKey(String HashKey) throws IOException {
        long longOfHashKey;

        if (HashKey.length() > 18) {
            HashKey = HashKey.substring(0, 18);
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

        Data = Data.replaceAll(" ", Char_SPACE);

        Data = Data.replaceAll("A", Char_A);
        Data = Data.replaceAll("B", Char_B);
        Data = Data.replaceAll("C", Char_C);
        Data = Data.replaceAll("D", Char_D);
        Data = Data.replaceAll("E", Char_E);
        Data = Data.replaceAll("F", Char_F);
        Data = Data.replaceAll("G", Char_G);
        Data = Data.replaceAll("H", Char_H);
        Data = Data.replaceAll("I", Char_I);
        Data = Data.replaceAll("J", Char_J);
        Data = Data.replaceAll("K", Char_K);
        Data = Data.replaceAll("L", Char_L);
        Data = Data.replaceAll("M", Char_M);
        Data = Data.replaceAll("N", Char_N);
        Data = Data.replaceAll("O", Char_O);
        Data = Data.replaceAll("P", Char_P);
        Data = Data.replaceAll("Q", Char_Q);
        Data = Data.replaceAll("R", Char_R);
        Data = Data.replaceAll("S", Char_S);
        Data = Data.replaceAll("T", Char_T);
        Data = Data.replaceAll("U", Char_U);
        Data = Data.replaceAll("V", Char_V);
        Data = Data.replaceAll("W", Char_W);
        Data = Data.replaceAll("X", Char_X);
        Data = Data.replaceAll("Y", Char_Y);
        Data = Data.replaceAll("Z", Char_Z);

        Data = Data.replaceAll("a", Char_a);
        Data = Data.replaceAll("b", Char_b);
        Data = Data.replaceAll("c", Char_c);
        Data = Data.replaceAll("d", Char_d);
        Data = Data.replaceAll("e", Char_e);
        Data = Data.replaceAll("f", Char_f);
        Data = Data.replaceAll("g", Char_g);
        Data = Data.replaceAll("h", Char_h);
        Data = Data.replaceAll("i", Char_i);
        Data = Data.replaceAll("j", Char_j);
        Data = Data.replaceAll("k", Char_k);
        Data = Data.replaceAll("l", Char_l);
        Data = Data.replaceAll("m", Char_m);
        Data = Data.replaceAll("n", Char_n);
        Data = Data.replaceAll("o", Char_o);
        Data = Data.replaceAll("p", Char_p);
        Data = Data.replaceAll("q", Char_q);
        Data = Data.replaceAll("r", Char_r);
        Data = Data.replaceAll("s", Char_s);
        Data = Data.replaceAll("t", Char_t);
        Data = Data.replaceAll("u", Char_u);
        Data = Data.replaceAll("v", Char_v);
        Data = Data.replaceAll("w", Char_w);
        Data = Data.replaceAll("x", Char_x);
        Data = Data.replaceAll("y", Char_y);
        Data = Data.replaceAll("z", Char_z);

        Data = Data.replaceAll("0", Char_0);
        Data = Data.replaceAll("1", Char_1);
        Data = Data.replaceAll("2", Char_2);
        Data = Data.replaceAll("3", Char_3);
        Data = Data.replaceAll("4", Char_4);
        Data = Data.replaceAll("5", Char_5);
        Data = Data.replaceAll("6", Char_6);
        Data = Data.replaceAll("7", Char_7);
        Data = Data.replaceAll("8", Char_8);
        Data = Data.replaceAll("9", Char_9);

        Data = Data.replaceAll("\\+", Char_PLUS);
        Data = Data.replaceAll("/", Char_SOLIDUS);

        return Data;
    }

    private static String decodeSymbols(String Message) {
        String Data = Message;

        Data = Data.replaceAll(Char_SOLIDUS, "/");
        Data = Data.replaceAll(Char_PLUS, "+");

        Data = Data.replaceAll(Char_9, "9");
        Data = Data.replaceAll(Char_8, "8");
        Data = Data.replaceAll(Char_7, "7");
        Data = Data.replaceAll(Char_6, "6");
        Data = Data.replaceAll(Char_5, "5");
        Data = Data.replaceAll(Char_4, "4");
        Data = Data.replaceAll(Char_3, "3");
        Data = Data.replaceAll(Char_2, "2");
        Data = Data.replaceAll(Char_1, "1");
        Data = Data.replaceAll(Char_0, "0");

        Data = Data.replaceAll(Char_z, "z");
        Data = Data.replaceAll(Char_y, "y");
        Data = Data.replaceAll(Char_x, "x");
        Data = Data.replaceAll(Char_w, "w");
        Data = Data.replaceAll(Char_v, "v");
        Data = Data.replaceAll(Char_u, "u");
        Data = Data.replaceAll(Char_t, "t");
        Data = Data.replaceAll(Char_s, "s");
        Data = Data.replaceAll(Char_r, "r");
        Data = Data.replaceAll(Char_q, "q");
        Data = Data.replaceAll(Char_p, "p");
        Data = Data.replaceAll(Char_o, "o");
        Data = Data.replaceAll(Char_n, "n");
        Data = Data.replaceAll(Char_m, "m");
        Data = Data.replaceAll(Char_l, "l");
        Data = Data.replaceAll(Char_k, "k");
        Data = Data.replaceAll(Char_j, "j");
        Data = Data.replaceAll(Char_i, "i");
        Data = Data.replaceAll(Char_h, "h");
        Data = Data.replaceAll(Char_g, "g");
        Data = Data.replaceAll(Char_f, "f");
        Data = Data.replaceAll(Char_e, "e");
        Data = Data.replaceAll(Char_d, "d");
        Data = Data.replaceAll(Char_c, "c");
        Data = Data.replaceAll(Char_b, "b");
        Data = Data.replaceAll(Char_a, "a");

        Data = Data.replaceAll(Char_Z, "Z");
        Data = Data.replaceAll(Char_Y, "Y");
        Data = Data.replaceAll(Char_X, "X");
        Data = Data.replaceAll(Char_W, "W");
        Data = Data.replaceAll(Char_V, "V");
        Data = Data.replaceAll(Char_U, "U");
        Data = Data.replaceAll(Char_T, "T");
        Data = Data.replaceAll(Char_S, "S");
        Data = Data.replaceAll(Char_R, "R");
        Data = Data.replaceAll(Char_Q, "Q");
        Data = Data.replaceAll(Char_P, "P");
        Data = Data.replaceAll(Char_O, "O");
        Data = Data.replaceAll(Char_N, "N");
        Data = Data.replaceAll(Char_M, "M");
        Data = Data.replaceAll(Char_L, "L");
        Data = Data.replaceAll(Char_K, "K");
        Data = Data.replaceAll(Char_J, "J");
        Data = Data.replaceAll(Char_I, "I");
        Data = Data.replaceAll(Char_H, "H");
        Data = Data.replaceAll(Char_G, "G");
        Data = Data.replaceAll(Char_F, "F");
        Data = Data.replaceAll(Char_E, "E");
        Data = Data.replaceAll(Char_D, "D");
        Data = Data.replaceAll(Char_C, "C");
        Data = Data.replaceAll(Char_B, "B");
        Data = Data.replaceAll(Char_A, "A");

        Data = Data.replaceAll(Char_SPACE, " ");

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
