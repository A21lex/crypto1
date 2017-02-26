import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by aleksandrs on 2/12/17.
 */
public class Exercise1 {

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


    //List of tuples of messages and corresponding ciphertexts for cipherTwo
    private static ArrayList<Tuple> listMessCiphertexts =
            new ArrayList<Tuple>() {{
                add(new Tuple(1, 0xe));
                add(new Tuple(0xe, 9));
                add(new Tuple(2, 6));
                add(new Tuple(0xd, 0xa));
                add(new Tuple(3, 7));
                add(new Tuple(0xc, 0xb));
            }};

    //get the difference table from DDT class
    static HashMap<Integer, HashMap<Integer, Integer>> differenceTable = DifferenceDistrTable.getDifferenceTable();

    //Since we have 6 pairs, it must follow that the counter for the correct key should be around 6*(10/16)=4,
    // while the counter for an incorrect key should be around 6*(1/16)=6/16 (0-1)

    /**
     * Break cipher 2
     *
     * @param listMessCyphertexts The list of plaintext-ciphertext tuples
     * @return HashMap with counters for each key guess:
     * the largest counter should correspond to the most probable key
     */
    public static HashMap<Integer, Integer> breakIt(ArrayList<Tuple> listMessCyphertexts) {
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
                //ciphertext of the first pair xor key guess
                int x0 = (Integer) mcPairs.get(i).get1().get2() ^ keyGuess;
                System.out.println("x0 = " + x0);
                //ciphertext of the second pair xor key guess
                int x1 = (Integer) mcPairs.get(i).get2().get2() ^ keyGuess;
                System.out.println("x1 = " + x1);
                int w0 = reverseS.get(x0);
                int w1 = reverseS.get(x1);
                int v0xorv1 = w0 ^ w1;
                System.out.println("v0xorv1 = " + v0xorv1);
                //plaintext of the first pair
                int p0 = (Integer) mcPairs.get(i).get1().get1();
                //plaintext of the second pair
                int p1 = (Integer) mcPairs.get(i).get2().get1();
                //find input differential for the pair of plaintexts
                int differential = p0 ^ p1;
                //find which of the corresponding entries in the difference table has
                // the highest probability for this differential
                int max = 0;
                HashMap<Integer, Integer> entryFrequency = differenceTable.get(differential);
                for (Integer frequency: entryFrequency.values()){
                    if (frequency > max) {
                        max = frequency;
                    }
                }
                System.out.println("max = " + max);
                int bestCharacteristic = 0;
                //determine the best characteristic according to the most frequent value in the
                //corresponding row of the difference table
                for (Integer entry: entryFrequency.keySet()){
                    if (entryFrequency.get(entry) == max){
                        bestCharacteristic = entry;
                        break;
                    }
                }
                System.out.println("Best characteristic = " + bestCharacteristic);
                //Check if v0xorv1 is equal to the best characteristic
                // (from the difference table)
                if (v0xorv1 == bestCharacteristic) {
                    //Increment counter for the key guess
                    keyCounters.merge(keyGuess, 1, (oldValue, one) -> oldValue + one);
                    System.out.println("Increasing counter for key: " + keyGuess);
                }
            }
        }
        return keyCounters;
    }


    public static void main(String args[]) {

        HashMap<Integer, Integer> keyCounts = breakIt(listMessCiphertexts);
        System.out.println("keyCounts = " + keyCounts);

        //Take k2 = 2 (largest counter)
        ArrayList<ArrayList<Integer>> guesses = getGuessesForK1(2);
        System.out.println("guesses = " + guesses);
        System.out.printf("Encrypted message %x with keys: %x, %x, %x is: ", 0xc, 2, 7, 2);
        System.out.println(String.format("%x", encryptCipher2(0xc, 2, 7, 2)));

        /**
         * SOLUTION TO EXERCISE 1: k0=2, k1=7, k2=2.
         */
    }

    @SuppressWarnings("unchecked") //check though

    /**
     * Get guesses for k1
     * @param key2 Our guess for k2 based on key counters
     * @return ArrayList of Lists of Integers of potential keys for k1:
     * the correct guess must be a part of every List
     */
    public static ArrayList<ArrayList<Integer>> getGuessesForK1(int key2) {
        ArrayList<Tuple> listMessCiphertextsForCipherOne = (ArrayList<Tuple>) listMessCiphertexts.clone();
        //We have copied the list of given messages-ciphertexts. Now we need to change
        // the ciphertexts to w using the obtained k2, while leaving messages intact.
        for (int i = 0; i < listMessCiphertextsForCipherOne.size(); i++) {

            listMessCiphertextsForCipherOne.set(i, new Tuple(listMessCiphertextsForCipherOne.get(i).get1(),
                    reverseS.get((Integer) listMessCiphertextsForCipherOne.get(i).get2() ^ key2)));

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
        for (int i = 0; i < 0xf; i++) {
            tu.put(i, 0);
        }

        for (int i = 0; i < mcPairs.size(); i++) {
            ArrayList<Integer> guesses = new ArrayList<>();

            int u0xoru1 = (Integer) mcPairs.get(i).get1().get1() ^ (Integer) mcPairs.get(i).get2().get1();
            for (int t = 0; t < 0xf; t++) {
                int u = reverseS.get(t ^ (Integer) mcPairs.get(i).get1().get2()) ^
                        reverseS.get(t ^ (Integer) mcPairs.get(i).get2().get2());
                if (u == u0xoru1) {
                    guesses.add(t);
                }
                tu.put(t, u);
            }
            potentialKeys.add(guesses);
        }
        return potentialKeys;
    }

    /**
     * Encrypt the message with Cipher Two
     *
     * @param m  The message
     * @param k0 Key 0
     * @param k1 Key 1
     * @param k2 Key 2
     * @return Encrypted message
     */
    private static int encryptCipher2(int m, int k0, int k1, int k2) {
        return S.get(S.get(m ^ k0) ^ k1) ^ k2;
    }
}
