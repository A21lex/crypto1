import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by aleksandrs on 2/12/17.
 */
public class Exercise1 extends Homework{

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
    static HashMap<Integer, HashMap<Integer, Integer>> differenceTable = DifferenceDistrTable.getDifferenceTable(S);


    /**
     * Break cipher 2
     *
     * @param listMessCiphertexts The list of plaintext-ciphertext tuples
     * @return HashMap with counters for each key guess:
     * the largest counter should correspond to the most probable key
     */
    public static HashMap<Integer, Integer> breakCipher2(ArrayList<Tuple> listMessCiphertexts) {
        //initialize key guesses; make their corresponding counters 0
        HashMap<Integer, Integer> keyCounters = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            keyCounters.put(i, 0);
        }

        //Combine messages/ciphertexts into all possible pairs in a new List of Tuples of Tuples
        ArrayList<Tuple<Tuple, Tuple>> mcPairs = new ArrayList<>();
        for (int i = 0; i < listMessCiphertexts.size(); i++) {
            for (int j = i + 1; j < listMessCiphertexts.size(); j++) {
                //System.out.println("I am taking pair " + i + ":" + j);
                Tuple<Integer, Integer> a = listMessCiphertexts.get(i);
                Tuple<Integer, Integer> b = listMessCiphertexts.get(j);
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
                for (Integer frequency : entryFrequency.values()) {
                    if (frequency > max) {
                        max = frequency;
                    }
                }
                System.out.println("max = " + max);
                int bestCharacteristic = 0;
                //determine the best characteristic according to the most frequent value in the
                //corresponding row of the difference table
                for (Integer entry : entryFrequency.keySet()) {
                    if (entryFrequency.get(entry) == max) {
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

        HashMap<Integer, Integer> keyCountsFork2 = breakCipher2(listMessCiphertexts);
        System.out.println("keyCountsFork2 = " + keyCountsFork2);

        //Take k2 = 2 (largest counter)
        HashMap<Integer, Integer> keyCountsFork1 = breakCipherOne(2, listMessCiphertexts);
        System.out.println("keyCountsFork1 = " + keyCountsFork1);
        System.out.printf("Encrypted message %x with keys: %x, %x, %x is: ", 0xc, 2, 7, 2);
        System.out.println(String.format("%x", encryptCipher2(0xc, 2, 7, 2)));

        /**
         * SOLUTION TO EXERCISE 1: k0=2, k1=7, k2=2.
         */

        Tuple<Integer, Integer> firstPair = listMessCiphertexts.get(0);
        Tuple<Integer, Integer> secondPair = listMessCiphertexts.get(1);
        System.out.println("firstPair = " + firstPair);
        System.out.println("secondPair = " + secondPair);
        int u = reverseS.get(reverseS.get(firstPair.get2() ^ 2) ^ 7);
        System.out.println("u = " + u);
        int k0 = firstPair.get1() ^ u;
        System.out.println("k0 guess = " + k0);

        System.out.println(
                decryptCipher2(9, 2, 7, 2)
        );
    }

    @SuppressWarnings("unchecked") //check though

    /**
     * Get guesses for k1
     * @param key2 Our guess for k2 based on key counters
     * @return ArrayList of Lists of Integers of potential keys for k1:
     * the correct guess must be a part of every List
     */
    public static HashMap<Integer, Integer> breakCipherOne(int key2, ArrayList<Tuple> plainsCiphers) {
        ArrayList<Tuple> listMessCiphertextsForCipherOne = (ArrayList<Tuple>) plainsCiphers.clone();
        //We have copied the list of given messages-ciphertexts. Now we need to change
        // the ciphertexts to w using the obtained k2, while leaving messages intact.
        for (int i = 0; i < listMessCiphertextsForCipherOne.size(); i++) {
            listMessCiphertextsForCipherOne.set(i, new Tuple(listMessCiphertextsForCipherOne.get(i).get1(),
                    reverseS.get((Integer) listMessCiphertextsForCipherOne.get(i).get2() ^ key2)));
        }

        //initialize key guesses; make their corresponding counters 0
        HashMap<Integer, Integer> keyCounters = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            keyCounters.put(i, 0);
        }

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

        for (int i = 0; i < mcPairs.size(); i++) {
            int u0xoru1 = (Integer) mcPairs.get(i).get1().get1() ^ (Integer) mcPairs.get(i).get2().get1();
            for (Integer keyGuess : keyCounters.keySet()) {
                int u = reverseS.get(keyGuess ^ (Integer) mcPairs.get(i).get1().get2()) ^
                        reverseS.get(keyGuess ^ (Integer) mcPairs.get(i).get2().get2());
                if (u == u0xoru1) {
                    keyCounters.merge(keyGuess, 1, (oldValue, one) -> oldValue + one);
                }
            }
        }
        System.out.println("PRINTING KEY COUNTERS FOR K1: " + keyCounters);
        return keyCounters;
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
    private static int decryptCipher2(int c, int k0, int k1, int k2) {
        return reverseS.get(reverseS.get(c ^ k2) ^ k1) ^ k0;
    }
}
