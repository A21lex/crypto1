import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by aleksandrs on 2/25/17.
 */
public class Exercise2 extends Homework{


    //List of tuples of messages and corresponding ciphertexts for cipherThree (Homework Exercise 2)
    private static ArrayList<Tuple> listMessCiphers =
            new ArrayList<Tuple>() {{
                add(new Tuple(0, 1));
                add(new Tuple(1, 0xd));
                add(new Tuple(2, 8));
                add(new Tuple(3, 0xa));
                add(new Tuple(4, 4));
                add(new Tuple(5, 3));
                add(new Tuple(6, 0));
                add(new Tuple(7, 2));
                add(new Tuple(8, 0xf));
                add(new Tuple(9, 6));
                add(new Tuple(0xa, 0xe));
                add(new Tuple(0xb, 0xc));
                add(new Tuple(0xc, 5));
                add(new Tuple(0xd, 0xb));
                add(new Tuple(0xe, 7));
                add(new Tuple(0xf, 9));
            }};

    //get the difference table from DDT class
    static HashMap<Integer, HashMap<Integer, Integer>> differenceTable = DifferenceDistrTable.getDifferenceTable(S);

    /**
     * Break cipher 3
     *
     * @param newListMessCiphers Another list of plaintext-ciphertext tuples
     * @return HashMap with counters for each key guess:
     * the largest counter should correspond to the most probable key
     */
    private static HashMap<Integer, Integer> breakCipher3(ArrayList<Tuple> newListMessCiphers) {
        //initialize key guesses; make their corresponding counters 0
        HashMap<Integer, Integer> keyCounters = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            keyCounters.put(i, 0);
        }

        //Combine messages/ciphertexts into all possible pairs in a new List of Tuples of Tuples
        ArrayList<Tuple<Tuple, Tuple>> mcPairs = new ArrayList<>();
        for (int i = 0; i < newListMessCiphers.size(); i++) {
            for (int j = i + 1; j < newListMessCiphers.size(); j++) {
                Tuple<Integer, Integer> a = newListMessCiphers.get(i);
                Tuple<Integer, Integer> b = newListMessCiphers.get(j);
                mcPairs.add(new Tuple(a, b));
            }
        }
        System.out.println("Printing all the pairs: " + mcPairs);
        System.out.println("Initialized key counters:\n" + keyCounters);

        for (int i = 0; i < mcPairs.size(); i++) {
            for (Integer keyGuess : keyCounters.keySet()) {
                //ciphertext of the first pair
                int z0 = (Integer) mcPairs.get(i).get1().get2() ^ keyGuess;
                //System.out.println("z0 = " + z0);
                //ciphertext of the second pair
                int z1 = (Integer) mcPairs.get(i).get2().get2() ^ keyGuess;
                //System.out.println("z1 = " + z1);
                int y0 = reverseS.get(z0);
                int y1 = reverseS.get(z1);
                int x0xorx1 = y0 ^ y1;
                //System.out.println("x0xorx1 = " + x0xorx1);

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
                //System.out.println("max = " + max);
                int bestCharacteristicRoundOne = 0;
                //determine the best characteristic according to the most frequent value in the
                //corresponding row of the difference table
                for (Integer entry : entryFrequency.keySet()) {
                    if (entryFrequency.get(entry) == max) {
                        bestCharacteristicRoundOne = entry;
                        break;
                    }
                }
                int bestCharacteristicRoundTwo = 0;
                int maxTwo = 0;
                //find the best second-round characteristic according to the difference distr table
                HashMap<Integer, Integer> entryFrequencyTwo = differenceTable.get(bestCharacteristicRoundOne);
                for (Integer frequency : entryFrequencyTwo.values()) {
                    if (frequency > maxTwo) {
                        maxTwo = frequency;
                    }
                }
                //System.out.println("maxTwo = " + maxTwo);
                //determine the best two-round characteristic
                for (Integer entry : entryFrequencyTwo.keySet()) {
                    if (entryFrequencyTwo.get(entry) == maxTwo) {
                        bestCharacteristicRoundTwo = entry;
                        break;
                    }
                }


                //Check if x0xorx1 is equal to the best two-round characteristic
                //(from the difference table)
                if (x0xorx1 == bestCharacteristicRoundTwo) {
                    //Increment a counter for the key guess
                    keyCounters.merge(keyGuess, 1, (oldValue, one) -> oldValue + one);
                    //System.out.println("Increasing counter for key: " + keyGuess);
                }
            }
        }
        return keyCounters;
    }

    public static void main(String[] args) {
        // System.out.println(listMessCiphers);

        System.out.println("key counts for k3 = " +
                breakCipher3(listMessCiphers)
        );

        //Now assume k3 = 6 (from the counters)
        int k3Guess = 6;

        //Transform the ciphertexts using the guess key to make cipher3 essentially cipher2
        ArrayList<Tuple> finalNewListMessCiphers = (ArrayList<Tuple>) listMessCiphers.clone();
        for (int i = 0; i < finalNewListMessCiphers.size(); i++) {
            Integer plaintext = (Integer) finalNewListMessCiphers.get(i).get1();
            Integer newCiphertext = reverseS.get((Integer) finalNewListMessCiphers.get(i).get2() ^ k3Guess);
            finalNewListMessCiphers.set(i, new Tuple(plaintext, newCiphertext));
        }
        System.out.println(listMessCiphers);
        System.out.println(finalNewListMessCiphers);
        //And try to find k2
        HashMap<Integer, Integer> keyCounts = Exercise1.breakCipher2(finalNewListMessCiphers);
        System.out.println("keyCounts for k2 = " + keyCounts);
        //Assume k2 = 3 (from the counters)
        int k2Guess = 3;
        //And try to get guesses for k1
        HashMap<Integer, Integer> guesses = Exercise1.breakCipherOne(k2Guess, finalNewListMessCiphers);
        System.out.println("guesses for k1 = " + guesses);
        //k1 = 4

        //k0 = 1

        //test
        System.out.println(encryptCipher3(6, 1, 4, 3, 6));

        Tuple<Integer, Integer> firstPair = listMessCiphers.get(0);
        Tuple<Integer, Integer> secondPair = listMessCiphers.get(1);
        System.out.println("firstPair = " + firstPair);
        System.out.println("secondPair = " + secondPair);
        int u = reverseS.get(reverseS.get(reverseS.get(firstPair.get2() ^ 6) ^ 3) ^ 4);
        System.out.println("u = " + u);
        int k0 = firstPair.get1() ^ u;
        System.out.println("k0 guess = " + k0);

        System.out.println(encryptCipher3(1, 1, 4, 3, 6));
        System.out.println(encryptCipher3(0xc, 1, 4, 3, 6));

        /**
         * SOLUTION TO EXERCISE 2: k0=1, k1=4, k2=3, k3=6.
         */
    }

    /**
     * Encrypt the message with Cipher Three
     *
     * @param m  The message
     * @param k0 Key 0
     * @param k1 Key 1
     * @param k2 Key 2
     * @param k3 Key 3
     * @return Encrypted message
     */
    private static int encryptCipher3(int m, int k0, int k1, int k2, int k3) {
        return S.get(S.get(S.get(m ^ k0) ^ k1) ^ k2) ^ k3;
    }
}