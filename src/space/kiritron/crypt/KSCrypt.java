package space.kiritron.crypt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Класс с методами для шифрования и дешифрования по стандартам КС Крипт.
 * @author Киритрон Стэйблкор
 * @version 1.0
 */

public class KSCrypt {
    /**
     * Шифрование String по стандартам КС Крипт.
     * @param DataToCrypt - Данные, которые нужно зашифровать.
     * @param Key - Ключ.
     * @param Salt - Соль.
     * @return возвращает шифр.
     */
    public static String encrypt(String DataToCrypt, String Key, String Salt) throws NoSuchAlgorithmException {
        DataToCrypt = DataToCrypt.replaceAll(" ","/%%%");
        
        DataToCrypt = DataToCrypt.replaceAll("А","/0000001");
        DataToCrypt = DataToCrypt.replaceAll("Б","/0000003");
        DataToCrypt = DataToCrypt.replaceAll("В","/0000005");
        DataToCrypt = DataToCrypt.replaceAll("Г","/0000007");
        DataToCrypt = DataToCrypt.replaceAll("Д","/0000009");
        DataToCrypt = DataToCrypt.replaceAll("Е","/0000011");
        DataToCrypt = DataToCrypt.replaceAll("Ё","/0000013");
        DataToCrypt = DataToCrypt.replaceAll("Ж","/0000015");
        DataToCrypt = DataToCrypt.replaceAll("З","/0000017");
        DataToCrypt = DataToCrypt.replaceAll("И","/0000019");
        DataToCrypt = DataToCrypt.replaceAll("Й","/0000021");
        DataToCrypt = DataToCrypt.replaceAll("К","/0000023");
        DataToCrypt = DataToCrypt.replaceAll("Л","/0000025");
        DataToCrypt = DataToCrypt.replaceAll("М","/0000027");
        DataToCrypt = DataToCrypt.replaceAll("Н","/0000029");
        DataToCrypt = DataToCrypt.replaceAll("О","/0000031");
        DataToCrypt = DataToCrypt.replaceAll("П","/0000033");
        DataToCrypt = DataToCrypt.replaceAll("Р","/0000035");
        DataToCrypt = DataToCrypt.replaceAll("С","/0000037");
        DataToCrypt = DataToCrypt.replaceAll("Т","/0000039");
        DataToCrypt = DataToCrypt.replaceAll("У","/0000041");
        DataToCrypt = DataToCrypt.replaceAll("Ф","/0000043");
        DataToCrypt = DataToCrypt.replaceAll("Х","/0000045");
        DataToCrypt = DataToCrypt.replaceAll("Ц","/0000047");
        DataToCrypt = DataToCrypt.replaceAll("Ч","/0000049");
        DataToCrypt = DataToCrypt.replaceAll("Ш","/0000051");
        DataToCrypt = DataToCrypt.replaceAll("Щ","/0000053");
        DataToCrypt = DataToCrypt.replaceAll("Ъ","/0000055");
        DataToCrypt = DataToCrypt.replaceAll("Ы","/0000057");
        DataToCrypt = DataToCrypt.replaceAll("Ь","/0000059");
        DataToCrypt = DataToCrypt.replaceAll("Э","/0000061");
        DataToCrypt = DataToCrypt.replaceAll("Ю","/0000063");
        DataToCrypt = DataToCrypt.replaceAll("Я","/0000065");
            
        DataToCrypt = DataToCrypt.replaceAll("а","/0000067");
        DataToCrypt = DataToCrypt.replaceAll("б","/0000069");
        DataToCrypt = DataToCrypt.replaceAll("в","/0000071");
        DataToCrypt = DataToCrypt.replaceAll("г","/0000073");
        DataToCrypt = DataToCrypt.replaceAll("д","/0000075");
        DataToCrypt = DataToCrypt.replaceAll("е","/0000077");
        DataToCrypt = DataToCrypt.replaceAll("ё","/0000079");
        DataToCrypt = DataToCrypt.replaceAll("ж","/0000081");
        DataToCrypt = DataToCrypt.replaceAll("з","/0000083");
        DataToCrypt = DataToCrypt.replaceAll("и","/0000085");
        DataToCrypt = DataToCrypt.replaceAll("й","/0000087");
        DataToCrypt = DataToCrypt.replaceAll("к","/0000089");
        DataToCrypt = DataToCrypt.replaceAll("л","/0000091");
        DataToCrypt = DataToCrypt.replaceAll("м","/0000093");
        DataToCrypt = DataToCrypt.replaceAll("н","/0000095");
        DataToCrypt = DataToCrypt.replaceAll("о","/0000097");
        DataToCrypt = DataToCrypt.replaceAll("п","/0000099");
        DataToCrypt = DataToCrypt.replaceAll("р","/0000101");
        DataToCrypt = DataToCrypt.replaceAll("с","/0000103");
        DataToCrypt = DataToCrypt.replaceAll("т","/0000105");
        DataToCrypt = DataToCrypt.replaceAll("у","/0000107");
        DataToCrypt = DataToCrypt.replaceAll("ф","/0000109");
        DataToCrypt = DataToCrypt.replaceAll("х","/0000111");
        DataToCrypt = DataToCrypt.replaceAll("ц","/0000113");
        DataToCrypt = DataToCrypt.replaceAll("ч","/0000115");
        DataToCrypt = DataToCrypt.replaceAll("ш","/0000117");
        DataToCrypt = DataToCrypt.replaceAll("щ","/0000119");
        DataToCrypt = DataToCrypt.replaceAll("ъ","/0000121");
        DataToCrypt = DataToCrypt.replaceAll("ы","/0000123");
        DataToCrypt = DataToCrypt.replaceAll("ь","/0000125");
        DataToCrypt = DataToCrypt.replaceAll("э","/0000127");
        DataToCrypt = DataToCrypt.replaceAll("ю","/0000129");
        DataToCrypt = DataToCrypt.replaceAll("я","/0000131");
        
        DataToCrypt = DataToCrypt.replaceAll("A","/0000000");
        DataToCrypt = DataToCrypt.replaceAll("B","/0000002");
        DataToCrypt = DataToCrypt.replaceAll("C","/0000004");
        DataToCrypt = DataToCrypt.replaceAll("D","/0000006");
        DataToCrypt = DataToCrypt.replaceAll("E","/0000008");
        DataToCrypt = DataToCrypt.replaceAll("F","/0000010");
        DataToCrypt = DataToCrypt.replaceAll("G","/0000012");
        DataToCrypt = DataToCrypt.replaceAll("H","/0000014");
        DataToCrypt = DataToCrypt.replaceAll("I","/0000016");
        DataToCrypt = DataToCrypt.replaceAll("J","/0000018");
        DataToCrypt = DataToCrypt.replaceAll("K","/0000020");
        DataToCrypt = DataToCrypt.replaceAll("L","/0000022");
        DataToCrypt = DataToCrypt.replaceAll("M","/0000024");
        DataToCrypt = DataToCrypt.replaceAll("N","/0000026");
        DataToCrypt = DataToCrypt.replaceAll("O","/0000028");
        DataToCrypt = DataToCrypt.replaceAll("P","/0000030");
        DataToCrypt = DataToCrypt.replaceAll("Q","/0000032");
        DataToCrypt = DataToCrypt.replaceAll("R","/0000034");
        DataToCrypt = DataToCrypt.replaceAll("S","/0000036");
        DataToCrypt = DataToCrypt.replaceAll("T","/0000038");
        DataToCrypt = DataToCrypt.replaceAll("U","/0000040");
        DataToCrypt = DataToCrypt.replaceAll("V","/0000042");
        DataToCrypt = DataToCrypt.replaceAll("W","/0000044");
        DataToCrypt = DataToCrypt.replaceAll("X","/0000046");
        DataToCrypt = DataToCrypt.replaceAll("Y","/0000048");
        DataToCrypt = DataToCrypt.replaceAll("Z","/0000050");
            
        DataToCrypt = DataToCrypt.replaceAll("a","/0000052");
        DataToCrypt = DataToCrypt.replaceAll("b","/0000054");
        DataToCrypt = DataToCrypt.replaceAll("c","/0000056");
        DataToCrypt = DataToCrypt.replaceAll("d","/0000058");
        DataToCrypt = DataToCrypt.replaceAll("e","/0000060");
        DataToCrypt = DataToCrypt.replaceAll("f","/0000062");
        DataToCrypt = DataToCrypt.replaceAll("g","/0000064");
        DataToCrypt = DataToCrypt.replaceAll("h","/0000066");
        DataToCrypt = DataToCrypt.replaceAll("i","/0000068");
        DataToCrypt = DataToCrypt.replaceAll("j","/0000070");
        DataToCrypt = DataToCrypt.replaceAll("k","/0000072");
        DataToCrypt = DataToCrypt.replaceAll("l","/0000074");
        DataToCrypt = DataToCrypt.replaceAll("m","/0000076");
        DataToCrypt = DataToCrypt.replaceAll("n","/0000078");
        DataToCrypt = DataToCrypt.replaceAll("o","/0000080");
        DataToCrypt = DataToCrypt.replaceAll("p","/0000082");
        DataToCrypt = DataToCrypt.replaceAll("q","/0000084");
        DataToCrypt = DataToCrypt.replaceAll("r","/0000086");
        DataToCrypt = DataToCrypt.replaceAll("s","/0000088");
        DataToCrypt = DataToCrypt.replaceAll("t","/0000090");
        DataToCrypt = DataToCrypt.replaceAll("u","/0000092");
        DataToCrypt = DataToCrypt.replaceAll("v","/0000094");
        DataToCrypt = DataToCrypt.replaceAll("w","/0000096");
        DataToCrypt = DataToCrypt.replaceAll("x","/0000098");
        DataToCrypt = DataToCrypt.replaceAll("y","/0000100");
        DataToCrypt = DataToCrypt.replaceAll("z","/0000102");
        
        DataToCrypt = DataToCrypt.replaceAll("!","/0000132");
        DataToCrypt = DataToCrypt.replaceAll("\\?","/0000133");
        DataToCrypt = DataToCrypt.replaceAll("<","/0000134");
        DataToCrypt = DataToCrypt.replaceAll(">","/0000135");
        DataToCrypt = DataToCrypt.replaceAll("\\.","/0000136");
        DataToCrypt = DataToCrypt.replaceAll(",","/0000137");
        DataToCrypt = DataToCrypt.replaceAll("`","/0000138");
        DataToCrypt = DataToCrypt.replaceAll("~","/0000139");
        DataToCrypt = DataToCrypt.replaceAll("\\^","/0000140");
        DataToCrypt = DataToCrypt.replaceAll(":","/0000141");
        DataToCrypt = DataToCrypt.replaceAll("\\$","/0000142");
        DataToCrypt = DataToCrypt.replaceAll(";","/0000143");
        DataToCrypt = DataToCrypt.replaceAll("№","/0000144");
        DataToCrypt = DataToCrypt.replaceAll("#","/0000145");
        DataToCrypt = DataToCrypt.replaceAll("@","/0000146");
        DataToCrypt = DataToCrypt.replaceAll("'","/0000147");
        DataToCrypt = DataToCrypt.replaceAll("\\(","/0000148");
        DataToCrypt = DataToCrypt.replaceAll("\\)","/0000149");
        DataToCrypt = DataToCrypt.replaceAll("\\*","/0000150");
        DataToCrypt = DataToCrypt.replaceAll("\\|","/0000151");
        DataToCrypt = DataToCrypt.replaceAll("&","/0000152");
        DataToCrypt = DataToCrypt.replaceAll("=","/0000153");
        DataToCrypt = DataToCrypt.replaceAll("\\+","/0000154");
        DataToCrypt = DataToCrypt.replaceAll("-","/0000155");
        DataToCrypt = DataToCrypt.replaceAll("_","/0000156");
        DataToCrypt = DataToCrypt.replaceAll("\\{","/0000157");
        DataToCrypt = DataToCrypt.replaceAll("}","/0000158");
        DataToCrypt = DataToCrypt.replaceAll("\\[","/0000159");
        DataToCrypt = DataToCrypt.replaceAll("]","/0000160");
        
        DataToCrypt = DataToCrypt.replaceAll("✿","/0000161");
        DataToCrypt = DataToCrypt.replaceAll("•","/0000162");
        DataToCrypt = DataToCrypt.replaceAll("●","/0000163");
        DataToCrypt = DataToCrypt.replaceAll("†","/0000164");
        DataToCrypt = DataToCrypt.replaceAll("ಠ","/0000165");
        DataToCrypt = DataToCrypt.replaceAll("≦","/0000166");
        DataToCrypt = DataToCrypt.replaceAll("≧","/0000167");
        DataToCrypt = DataToCrypt.replaceAll("ω","/0000168");
        DataToCrypt = DataToCrypt.replaceAll("◐","/0000169");
        DataToCrypt = DataToCrypt.replaceAll("◑","/0000170");
        DataToCrypt = DataToCrypt.replaceAll("◕","/0000171");
        DataToCrypt = DataToCrypt.replaceAll("‿","/0000172");
        DataToCrypt = DataToCrypt.replaceAll("¬","/0000173");
        DataToCrypt = DataToCrypt.replaceAll("◎","/0000174");
        DataToCrypt = DataToCrypt.replaceAll("⊙","/0000175");
        DataToCrypt = DataToCrypt.replaceAll("♥","/0000176");
        DataToCrypt = DataToCrypt.replaceAll("❤","/0000177");
        DataToCrypt = DataToCrypt.replaceAll("❤","/0000178");
        DataToCrypt = DataToCrypt.replaceAll("｡","/0000179");
        DataToCrypt = DataToCrypt.replaceAll("～","/0000180");
        DataToCrypt = DataToCrypt.replaceAll("ಊ","/0000181");
        DataToCrypt = DataToCrypt.replaceAll("╯","/0000182");
        DataToCrypt = DataToCrypt.replaceAll("╰","/0000183");
        DataToCrypt = DataToCrypt.replaceAll("⋌","/0000184");
        DataToCrypt = DataToCrypt.replaceAll("⋋","/0000185");
        DataToCrypt = DataToCrypt.replaceAll("✖","/0000186");
        DataToCrypt = DataToCrypt.replaceAll("∫","/0000187");
        
        DataToCrypt = DataToCrypt.replaceAll("☺","/0000188");
        DataToCrypt = DataToCrypt.replaceAll("☹","/0000189");
        DataToCrypt = DataToCrypt.replaceAll("☻","/0000190");
        DataToCrypt = DataToCrypt.replaceAll("😁","/0000191");
        DataToCrypt = DataToCrypt.replaceAll("😂","/0000192");
        DataToCrypt = DataToCrypt.replaceAll("😃","/0000193");
        DataToCrypt = DataToCrypt.replaceAll("😄","/0000194");
        DataToCrypt = DataToCrypt.replaceAll("😅","/0000195");
        DataToCrypt = DataToCrypt.replaceAll("😆","/0000196");
        DataToCrypt = DataToCrypt.replaceAll("😇","/0000197");
        DataToCrypt = DataToCrypt.replaceAll("😈","/0000198");
        DataToCrypt = DataToCrypt.replaceAll("😉","/0000199");
        DataToCrypt = DataToCrypt.replaceAll("😊","/0000200");
        DataToCrypt = DataToCrypt.replaceAll("😋","/0000201");
        DataToCrypt = DataToCrypt.replaceAll("😌","/0000202");
        DataToCrypt = DataToCrypt.replaceAll("😍","/0000203");
        DataToCrypt = DataToCrypt.replaceAll("😎","/0000204");
        DataToCrypt = DataToCrypt.replaceAll("😏","/0000205");
        DataToCrypt = DataToCrypt.replaceAll("😐","/0000206");
        DataToCrypt = DataToCrypt.replaceAll("😒","/0000207");
        DataToCrypt = DataToCrypt.replaceAll("😓","/0000208");
        DataToCrypt = DataToCrypt.replaceAll("😔","/0000209");
        DataToCrypt = DataToCrypt.replaceAll("😖","/0000210");
        DataToCrypt = DataToCrypt.replaceAll("😘","/0000211");
        DataToCrypt = DataToCrypt.replaceAll("😚","/0000212");
        DataToCrypt = DataToCrypt.replaceAll("😜","/0000213");
        DataToCrypt = DataToCrypt.replaceAll("😝","/0000214");
        DataToCrypt = DataToCrypt.replaceAll("😞","/0000215");
        DataToCrypt = DataToCrypt.replaceAll("😠","/0000216");
        DataToCrypt = DataToCrypt.replaceAll("😡","/0000217");
        DataToCrypt = DataToCrypt.replaceAll("😢","/0000218");
        DataToCrypt = DataToCrypt.replaceAll("😣","/0000219");
        DataToCrypt = DataToCrypt.replaceAll("😤","/0000220");
        DataToCrypt = DataToCrypt.replaceAll("😥","/0000221");
        DataToCrypt = DataToCrypt.replaceAll("😨","/0000222");
        DataToCrypt = DataToCrypt.replaceAll("😩","/0000223");
        DataToCrypt = DataToCrypt.replaceAll("😪","/0000224");
        DataToCrypt = DataToCrypt.replaceAll("😫","/0000225");
        DataToCrypt = DataToCrypt.replaceAll("😭","/0000226");
        DataToCrypt = DataToCrypt.replaceAll("😰","/0000227");
        DataToCrypt = DataToCrypt.replaceAll("😱","/0000228");
        DataToCrypt = DataToCrypt.replaceAll("😲","/0000229");
        DataToCrypt = DataToCrypt.replaceAll("😳","/0000230");
        DataToCrypt = DataToCrypt.replaceAll("😵","/0000231");
        DataToCrypt = DataToCrypt.replaceAll("😶","/0000232");
        DataToCrypt = DataToCrypt.replaceAll("😷","/0000233");
        DataToCrypt = DataToCrypt.replaceAll("😸","/0000234");
        DataToCrypt = DataToCrypt.replaceAll("😹","/0000235");
        DataToCrypt = DataToCrypt.replaceAll("😺","/0000236");
        DataToCrypt = DataToCrypt.replaceAll("😻","/0000237");
        DataToCrypt = DataToCrypt.replaceAll("😼","/0000238");
        DataToCrypt = DataToCrypt.replaceAll("😽","/0000239");
        DataToCrypt = DataToCrypt.replaceAll("😾","/0000240");
        DataToCrypt = DataToCrypt.replaceAll("😿","/0000241");
        DataToCrypt = DataToCrypt.replaceAll("🙀","/0000242");
        
        int Count0 = geneKey(Key, Salt).indexOf("0");
        int Count1 = geneKey(Key, Salt).indexOf("1");
        int Count2 = geneKey(Key, Salt).indexOf("2");
        int Count3 = geneKey(Key, Salt).indexOf("3");
        int Count4 = geneKey(Key, Salt).indexOf("4");
        int Count5 = geneKey(Key, Salt).indexOf("5");
        int Count6 = geneKey(Key, Salt).indexOf("6");
        int Count7 = geneKey(Key, Salt).indexOf("7");
        int Count8 = geneKey(Key, Salt).indexOf("8");
        int Count9 = geneKey(Key, Salt).indexOf("9");
        
        if (Count0 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("0","/%%k");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("0","/%%a");
        }
        
        if (Count1 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("1","/%%l");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("1","/%%b");
        }
        
        if (Count2 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("2","/%%m");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("2","/%%c");
        }
        
        if (Count3 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("3","/%%n");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("3","/%%d");
        }
        
        if (Count4 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("4","/%%o");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("4","/%%e");
        }
        
        if (Count5 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("5","/%%p");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("5","/%%f");
        }
        
        if (Count6 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("6","/%%q");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("6","/%%g");
        }
        
        if (Count7 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("7","/%%r");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("7","/%%h");
        }
        
        if (Count8 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("8","/%%s");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("8","/%%i");
        }
        
        if (Count9 != -1) {
            DataToCrypt = DataToCrypt.replaceAll("9","/%%t");
        } else {
            DataToCrypt = DataToCrypt.replaceAll("9","/%%j");
        }
        
        return DataToCrypt;
    }

    /**
     * Дешифрование String по стандартам КС Крипт.
     * @param DataToDecrypt - Данные, которые нужно дешифровать. На вход должен поступать шифр стандарта КС Крипт.
     * @param Key - Ключ.
     * @param Salt - Соль.
     * @return возвращает шифр.
     */
    public static String decrypt(String DataToDecrypt, String Key, String Salt) throws NoSuchAlgorithmException {
        int Count0 = geneKey(Key, Salt).indexOf("0");
        int Count1 = geneKey(Key, Salt).indexOf("1");
        int Count2 = geneKey(Key, Salt).indexOf("2");
        int Count3 = geneKey(Key, Salt).indexOf("3");
        int Count4 = geneKey(Key, Salt).indexOf("4");
        int Count5 = geneKey(Key, Salt).indexOf("5");
        int Count6 = geneKey(Key, Salt).indexOf("6");
        int Count7 = geneKey(Key, Salt).indexOf("7");
        int Count8 = geneKey(Key, Salt).indexOf("8");
        int Count9 = geneKey(Key, Salt).indexOf("9");
        
        if (Count9 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%t", "9");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%j", "9");
        }
        
        if (Count8 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%s", "8");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%i", "8");
        }
        
        if (Count7 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%r", "7");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%h", "7");
        }
        
        if (Count6 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%q", "6");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%g", "6");
        }
        
        if (Count5 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%p", "5");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%f", "5");
        }
        
        if (Count4 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%o", "4");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%e", "4");
        }
        
        if (Count3 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%n", "3");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%d", "3");
        }
        
        if (Count2 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%m", "2");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%c", "2");
        }
        
        if (Count1 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%l", "1");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%b", "1");
        }
        
        if (Count0 != -1) {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%k", "0");
        } else {
            DataToDecrypt = DataToDecrypt.replaceAll("/%%a", "0");
        }
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000102","z");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000100","y");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000098","x");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000096","w");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000094","v");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000092","u");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000090","t");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000088","s");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000086","r");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000084","q");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000082","p");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000080","o");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000078","n");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000076","m");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000074","l");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000072","k");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000070","j");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000068","i");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000066","h");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000064","g");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000062","f");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000060","e");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000058","d");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000056","c");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000054","b");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000052","a");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000050","Z");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000048","Y");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000046","X");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000044","W");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000042","V");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000040","U");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000038","T");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000036","S");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000034","R");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000032","Q");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000030","P");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000028","O");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000026","N");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000024","M");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000022","L");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000020","K");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000018","J");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000016","I");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000014","H");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000012","G");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000010","F");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000008","E");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000006","D");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000004","C");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000002","B");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000000","A");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000131","я");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000129","ю");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000127","э");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000125","ь");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000123","ы");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000121","ъ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000119","щ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000117","ш");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000113","ц");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000115","ч");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000111","х");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000109","ф");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000107","у");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000105","т");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000103","с");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000101","р");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000099","п");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000097","о");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000095","н");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000093","м");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000091","л");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000089","к");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000087","й");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000085","и");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000083","з");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000081","ж");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000079","ё");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000077","е");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000075","д");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000073","г");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000071","в");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000069","б");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000067","а");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000065","Я");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000063","Ю");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000061","Э");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000059","Ь");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000057","Ы");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000055","Ъ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000053","Щ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000051","Ш");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000049","Ч");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000047","Ц");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000045","Х");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000043","Ф");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000041","У");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000039","Т");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000037","С");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000035","Р");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000033","П");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000031","О");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000029","Н");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000027","М");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000025","Л");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000023","К");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000021","Й");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000019","И");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000017","З");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000015","Ж");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000013","Ё");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000011","Е");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000009","Д");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000007","Г");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000005","В");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000003","Б");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000001","А");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000132","!");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000133","\\?");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000134","<");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000135",">");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000136","\\.");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000137",",");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000138","`");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000139","~");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000140","\\^");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000141",":");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000142","\\$");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000143",";");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000144","№");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000145","#");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000146","@");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000147","'");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000148","\\(");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000149","\\)");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000150","\\*");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000151","\\|");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000152","&");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000153","=");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000154","\\+");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000155","-");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000156","_");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000157","\\{");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000158","}");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000159","\\[");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000160","]");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000161","✿");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000162","•");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000163","●");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000164","†");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000165","ಠ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000166","≦");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000167","≧");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000168","ω");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000169","◐");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000170","◑");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000171","◕");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000172","‿");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000173","¬");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000174","◎");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000175","⊙");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000176","♥");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000177","❤");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000178","❤");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000179","｡");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000180","～");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000181","ಊ");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000182","╯");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000183","╰");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000184","⋌");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000185","⋋");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000186","✖");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000187","∫");
        
        DataToDecrypt = DataToDecrypt.replaceAll("/0000188","☺");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000189","☹");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000190","☻");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000191","😁");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000192","😂");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000193","😃");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000194","😄");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000195","😅");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000196","😆");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000197","😇");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000198","😈");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000199","😉");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000200","😊");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000201","😋");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000202","😌");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000203","😍");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000204","😎");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000205","😏");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000206","😐");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000207","😒");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000208","😓");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000209","😔");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000210","😖");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000211","😘");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000212","😚");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000213","😜");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000214","😝");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000215","😞");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000216","😠");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000217","😡");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000218","😢");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000219","😣");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000220","😤");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000221","😥");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000222","😨");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000223","😩");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000224","😪");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000225","😫");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000226","😭");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000227","😰");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000228","😱");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000229","😲");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000230","😳");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000231","😵");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000232","😶");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000233","😷");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000234","😸");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000235","😹");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000236","😺");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000237","😻");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000238","😼");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000239","😽");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000240","😾");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000241","😿");
        DataToDecrypt = DataToDecrypt.replaceAll("/0000242","🙀");
            
        DataToDecrypt = DataToDecrypt.replaceAll("/%%%"," ");
        
        return DataToDecrypt;
    }
    
    private static String geneKey(String Key, String Salt) throws NoSuchAlgorithmException {
        String TranslateKey = Key + Salt;
        String hashtext = GenHash(TranslateKey);
        return hashtext;
    }

    private static String GenHash(String Key) throws NoSuchAlgorithmException {
        String out = GenHashMD5(GenHashSHA256(GenHashSHA1(GenHashMD5(GenHashSHA256(Key)))));
        return out;
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
}
