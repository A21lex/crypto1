import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Created by aleksandrs on 2/12/17.
 */
public class DiffAnalysis {

    //S box
    private static HashMap<Integer, Integer> S = new HashMap<Integer, Integer>() {{
        put(0x0, 0x6);
        put(0x1, 0x4);
        put(0x2, 0xc);
        put(0x3, 0x5);
        put(0x4, 0x0);
        put(0x5, 0x7);
        put(0x6, 0x2);
        put(0x7, 0xe);
        put(0x8, 0x1);
        put(0x9, 0xf);
        put(0xa, 0x3);
        put(0xb, 0xd);
        put(0xc, 0x8);
        put(0xd, 0xa);
        put(0xe, 0x9);
        put(0xf, 0xb);
    }};

    //Reverse of the S box
    private static Map<Integer, Integer> reverseS =
            S.entrySet()
                    .stream()
                    .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

//   /* //Reverse permutation of the S box
//    static HashMap<Integer, Integer> R = new HashMap<Integer, Integer>() {{
//        put(0x0, 0x4);
//        put(0x1, 0x8);
//        put(0x2, 0x6);
//        put(0x3, 0xa);
//        put(0x4, 0x1);
//        put(0x5, 0x3);
//        put(0x6, 0x0);
//        put(0x7, 0x5);
//        put(0x8, 0xc);
//        put(0x9, 0xe);
//        put(0xa, 0xd);
//        put(0xb, 0xf);
//        put(0xc, 0x2);
//        put(0xd, 0xb);
//        put(0xe, 0x7);
//        put(0xf, 0x9);
//    }};*/

    /**
     * Given a u0, calculate v0^v1, assuming u0^u1=differential (Chosen plaintext attack)
     *
     * @param u0           Some message xored with the first key
     * @param differential Some differential
     * @return v0^v1
     */
    static int get_v0_XOR_v1(int u0, int differential) {
        int u1 = u0 ^ differential;
        int v0 = S.get(u0);
        int v1 = S.get(u1);
        return v0 ^ v1;
    }

    //static int maxxCount = 0;


    static HashMap<Integer, Integer> getFrequencies(HashMap<Integer, Integer> table) {
//        HashMap<Integer, Integer> frequencyMap = new HashMap<Integer, Integer>() {{
//            put(0, 0);
//            put(1, 0);
//            put(2, 0);
//            put(3, 0);
//            put(4, 0);
//            put(5, 0);
//            put(6, 0);
//            put(7, 0);
//            put(8, 0);
//            put(9, 0);
//            put(0xa, 0);
//            put(0xb, 0);
//            put(0xc, 0);
//            put(0xd, 0);
//            put(0xe, 0);
//            put(0xf, 0);
//        }};
        HashMap<Integer, Integer> frequencyMap = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            frequencyMap.put(i, 0);
        }
        //int maxCount = 0;

        for (Integer value : table.values()) {
            int count = 0;
            for (Integer value2 : table.values()) {
                if (value.equals(value2)) {
                    count++;
                }
            }
            //if (count > maxCount){
            //    maxCount = count;
            //}
            frequencyMap.put(value, count);
        }
        //maxxCount = maxCount;
        return frequencyMap;
    }

    static HashMap<Integer, HashMap<Integer, Integer>> getDifferenceTable() {

        //A table with all of them
        HashMap<Integer, HashMap<Integer, Integer>> differenceTable = new HashMap<>();
        //for all differentials do
        for (int differential = 0; differential <= 0xf; differential++) {
            //A table for one differential
            HashMap<Integer, Integer> tableForOne = new HashMap<>();
            for (int u0 = 0; u0 <= 0xf; u0++) {
                tableForOne.put(u0, get_v0_XOR_v1(u0, differential));
            }
            HashMap<Integer, Integer> frequencyMap = getFrequencies(tableForOne);
//DEBUGGING
//            System.out.println("Frequency map for differential d");
//            for (Integer value: getFrequencies(tableForOne).keySet()){
//                System.out.println(value + " : " + frequencyMap.get(value));
//            }

            differenceTable.put(differential, frequencyMap);

        }
        return differenceTable;
    }

    //List of tuples messages and corresponding ciphertexts
    private static ArrayList<Tuple> listMessCiphertexts =
            new ArrayList<Tuple>() {{
                add(new Tuple(1, 0xe));
                add(new Tuple(0xe, 9));
                add(new Tuple(2, 6));
                add(new Tuple(0xd, 0xa));
                add(new Tuple(3, 7));
                add(new Tuple(0xc, 0xb));
            }};

    //List of the given pairs of messages and corresponding cyphertexts
//    private static ArrayList<HashMap<Integer, Integer>> listMessCyphertexts =
//            new ArrayList<HashMap<Integer, Integer>>() {{
//                add(new HashMap<Integer, Integer>() {{
//                    put(1, 0xe);
//                }});
//                add(new HashMap<Integer, Integer>() {{
//                    put(0xe, 9);
//                }});
//                add(new HashMap<Integer, Integer>() {{
//                    put(2, 6);
//                }});
//                add(new HashMap<Integer, Integer>() {{
//                    put(0xd, 0xa);
//                }});
//                add(new HashMap<Integer, Integer>() {{
//                    put(3, 7);
//                }});
//                add(new HashMap<Integer, Integer>() {{
//                    put(0xc, 0xb);
//                }});
//            }};


    private static int breakIt(ArrayList<Tuple> listMessCyphertexts) {
        //initialize key guesses; make their corresponding counters 0
        HashMap<Integer, Integer> keyCounters = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            keyCounters.put(i, 0);
        }

        //Combine messages/cyphertexts into all possible pairs in a new List of Tuples of Tuples
        ArrayList<Tuple<Tuple, Tuple>> mcPairs = new ArrayList<>();
        for (int i = 0; i < listMessCyphertexts.size(); i++) {
            for (int j = i + 1; j < listMessCyphertexts.size(); j++) {
                //System.out.println("I am taking pair " + i + ":" + j);
                Tuple<Integer, Integer> a = listMessCyphertexts.get(i);
                Tuple<Integer, Integer> b = listMessCyphertexts.get(j);
                //System.out.println("Corresponding to values " + a + " " + b);
                mcPairs.add(new Tuple(a, b));
                //}
            }
        }
        System.out.println("Printing all the pairs: " + mcPairs);


        System.out.println("Initialized key counters:\n" + keyCounters);
        for (int i = 0; i < mcPairs.size(); i++) {
            for (Integer keyGuess : keyCounters.keySet()) {
                //cyphertext of the first pair
                int x0 = (Integer) mcPairs.get(i).get1().get2() ^ keyGuess;
                System.out.println("x0 = " + x0);
                //cyphertext of the second pair
                int x1 = (Integer) mcPairs.get(i).get2().get2() ^ keyGuess;
                System.out.println("x1 = " + x1);
                int w0 = reverseS.get(x0);
                int w1 = reverseS.get(x1);
                int v0xorv1 = w0^w1;
                System.out.println("v0xorv1 = " + v0xorv1);
                if (v0xorv1 == 0xd){
                    //keyCounters.put(keyGuess, currentCount);
                    keyCounters.merge(keyGuess, 1, (oldValue, one) -> oldValue + one);
                    System.out.println("Increasing counter for key number: " + keyGuess);
                }
            }
        }
        System.out.println("Key counters after the algorithm: \n" + keyCounters);

        return 0;
    }


    public static void main(String args[]) {
//        int differential = 0xf;
//
//        //A table for a specified differential
//        HashMap<Integer, Integer> table = new HashMap<>();
//        for (int u0 = 0; u0 <= 0xf; u0++) {
//            System.out.println(String.format("%x", u0) + " : " + String.format("%x", get_v0_XOR_v1(u0, differential)));
//            //populate the table
//            table.put(u0, get_v0_XOR_v1(u0, differential));
//        }
//
//
//        System.out.println("Frequency map for differential d");
//        for (Integer value : getFrequencies(table).keySet()) {
//            System.out.println(value + " : " + getFrequencies(table).get(value));
//        }

        System.out.println("PRINTING DIFFERENCE MAP ");

        HashMap<Integer, HashMap<Integer, Integer>> differenceTable = getDifferenceTable();
        System.out.print(" ");
        for (int i = 0; i <= 0xf; i++) {
            System.out.print(" " + String.format("%x", i));
        }

        for (Integer key : differenceTable.keySet()) {
            System.out.println();
            System.out.print(String.format("%x", key) + "|");

            for (int i = 0; i <= 0xf; i++) {
                System.out.print(differenceTable.get(key).get(i) + " ");
            }


        }


        breakIt(listMessCiphertexts);




        ArrayList<ArrayList<Integer>> guesses = getGuessesForK1(2);
        System.out.println("guesses = " + guesses);
        System.out.printf("Encrypted message %s with keys: %x, %x, %x is: ", 0xc, 2, 7, 2);
        System.out.println(encrypt(0xc, 2, 7, 2));

        /**
         * SOLUTION TO EXERCISE 1: k0=2, k1=7, k2=2.
         */

    }

    private static ArrayList<ArrayList<Integer>> getGuessesForK1(int key2){
        ArrayList<Tuple> listMessCiphertextsForCipherOne = listMessCiphertexts;
        //We have copied the list of given messages-ciphertexts. Now we need to change
        // the ciphertexts to w using the obtained k2, while leaving messages intact.
        for(int i = 0; i < listMessCiphertextsForCipherOne.size(); i++){

            listMessCiphertextsForCipherOne.set(i, new Tuple(listMessCiphertextsForCipherOne.get(i).get1(),
                    reverseS.get((Integer)listMessCiphertextsForCipherOne.get(i).get2()^key2)));

        }



        ArrayList<ArrayList<Integer>> potentialKeys = new ArrayList<>();

        ArrayList<Tuple<Tuple, Tuple>> mcPairs = new ArrayList<>();
        for (int i = 0; i < listMessCiphertextsForCipherOne.size(); i++) {
            for (int j = i + 1; j < listMessCiphertextsForCipherOne.size(); j++) {
                //System.out.println("I am taking pair " + i + ":" + j);
                Tuple<Integer, Integer> a = listMessCiphertextsForCipherOne.get(i);
                Tuple<Integer, Integer> b = listMessCiphertextsForCipherOne.get(j);
                //System.out.println("Corresponding to values " + a + " " + b);
                mcPairs.add(new Tuple(a, b));
                //}
            }
        }

        HashMap<Integer, Integer> tu = new HashMap<>();
        for (int i = 0; i < 0xf; i++){
            tu.put(i, 0);
        }

        for (int i = 0; i < mcPairs.size(); i++){
            ArrayList<Integer> guesses = new ArrayList<>();

           int u0xoru1 = (Integer) mcPairs.get(i).get1().get1() ^ (Integer) mcPairs.get(i).get2().get1();
            for (int t = 0; t < 0xf; t++){
                int u = reverseS.get(t ^ (Integer) mcPairs.get(i).get1().get2()) ^
                        reverseS.get(t ^ (Integer) mcPairs.get(i).get2().get2());
                if(u == u0xoru1){
                    guesses.add(t);
                }
                tu.put(t, u);
            }
            potentialKeys.add(guesses);
        }
        return potentialKeys;
    }

    private static int encrypt(int m, int k0, int k1, int k2){
        return S.get(S.get(m^k0)^k1)^k2;
    }
}
