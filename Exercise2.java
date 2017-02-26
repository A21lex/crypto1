import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by aleksandrs on 2/25/17.
 */
public class Exercise2 {

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

    //List of tuples of messages and corresponding ciphertexts for cipherThree (Homework Exercise 2)
    private static ArrayList<Tuple> newListMessCiphers =
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
    static HashMap<Integer, HashMap<Integer, Integer>> differenceTable = DifferenceDistrTable.getDifferenceTable();

    /**
     * Break cipher 3
     *
     * @param newListMessCiphers Another list of plaintext-ciphertext tuples
     * @return HashMap with counters for each key guess:
     * the largest counter should correspond to the most probable key
     */
    private static HashMap<Integer, Integer> breakItToo(ArrayList<Tuple> newListMessCiphers) {
        //initialize key guesses; make their corresponding counters 0
        HashMap<Integer, Integer> keyCounters = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            keyCounters.put(i, 0);
        }

        //Combine messages/ciphertexts into all possible pairs in a new List of Tuples of Tuples
        ArrayList<Tuple<Tuple, Tuple>> mcPairs = new ArrayList<>();
        for (int i = 0; i < newListMessCiphers.size(); i++) {
            for (int j = i + 1; j < newListMessCiphers.size(); j++) {
                //System.out.println("I am taking pair " + i + ":" + j);
                Tuple<Integer, Integer> a = newListMessCiphers.get(i);
                Tuple<Integer, Integer> b = newListMessCiphers.get(j);
                //System.out.println("Corresponding to values " + a + " " + b);
                mcPairs.add(new Tuple(a, b));
                //}
            }
        }
        System.out.println("Printing all the pairs: " + mcPairs);
        System.out.println("Initialized key counters:\n" + keyCounters);

        for (int i = 0; i < mcPairs.size(); i++) {
            for (Integer keyGuess : keyCounters.keySet()) {
                //ciphertext of the first pair
                int z0 = (Integer) mcPairs.get(i).get1().get2() ^ keyGuess;
                System.out.println("z0 = " + z0);
                //ciphertext of the second pair
                int z1 = (Integer) mcPairs.get(i).get2().get2() ^ keyGuess;
                System.out.println("z1 = " + z1);
                int y0 = reverseS.get(z0);
                int y1 = reverseS.get(z1);
                int x0xorx1 = y0 ^ y1;
                System.out.println("x0xorx1 = " + x0xorx1);

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
                int bestCharacteristicRoundOne = 0;
                //determine the best characteristic according to the most frequent value in the
                //corresponding row of the difference table
                for (Integer entry: entryFrequency.keySet()){
                    if (entryFrequency.get(entry) == max){
                        bestCharacteristicRoundOne = entry;
                        break;
                    }
                }
                int bestCharacteristicRoundTwo = 0;
                int maxTwo = 0;
                //find the best second-round characteristic according to the difference distr table
                HashMap<Integer, Integer> entryFrequencyTwo = differenceTable.get(bestCharacteristicRoundOne);
                for (Integer frequency: entryFrequencyTwo.values()){
                    if (frequency > maxTwo) {
                        maxTwo = frequency;
                    }
                }
                System.out.println("maxTwo = " + maxTwo);
                //determine the best two-round characteristic
                for (Integer entry: entryFrequencyTwo.keySet()){
                    if (entryFrequencyTwo.get(entry) == maxTwo){
                        bestCharacteristicRoundTwo = entry;
                        break;
                    }
                }



                //Check if x0xorx1 is equal to the best two-round characteristic
                //(from the difference table)
                if (x0xorx1 == bestCharacteristicRoundTwo) {
                    //Increment a counter for the key guess
                    keyCounters.merge(keyGuess, 1, (oldValue, one) -> oldValue + one);
                    System.out.println("Increasing counter for key: " + keyGuess);
                }
            }
        }
        return keyCounters;
    }

    public static void main(String[] args) {
       // System.out.println(newListMessCiphers);

        System.out.println("key counts for k3 = " +
                breakItToo(newListMessCiphers)
        );

        //Now assume k3 = 6 (from the counters)
        int k3Guess = 6;

        //Transform the ciphertexts using the guess key to make cipher3 essentially cipher2
        ArrayList<Tuple> finalNewListMessCiphers = (ArrayList<Tuple>) newListMessCiphers.clone();
        for(int i = 0; i < finalNewListMessCiphers.size(); i++){
            Integer plaintext = (Integer) finalNewListMessCiphers.get(i).get1();
            Integer newCiphertext = reverseS.get( (Integer) finalNewListMessCiphers.get(i).get2()^k3Guess );
            finalNewListMessCiphers.set(i, new Tuple(plaintext, newCiphertext));
        }
        System.out.println(newListMessCiphers);
        System.out.println(finalNewListMessCiphers);
        //And try to find k2
        HashMap<Integer, Integer> keyCounts = Exercise1.breakIt(finalNewListMessCiphers);
        System.out.println("keyCounts for k2 = " + keyCounts);
        //Assume k2 = 3 (from the counters)
        int k2Guess = 3;
        //And try to get guesses for k1
        ArrayList<ArrayList<Integer>> guesses = getGuessesForK1(k2Guess, finalNewListMessCiphers);
        System.out.println("guesses for k1 = " + guesses);
        //k1 = 4


        //k0 = 1



        System.out.println(encryptCipher3(6, 1, 4, 3, 6));

        /**
         * SOLUTION TO EXERCISE 2: k0=1, k1=4, k2=3, k3=6.
         */
    }

    /**
     * Get guesses for k1
     * @param key2 Our guess for k2 based on key counters
     * @return ArrayList of Lists of Integers of potential keys for k1:
     * the correct guess must be a part of every List
     */
    public static ArrayList<ArrayList<Integer>> getGuessesForK1(int key2, ArrayList<Tuple> plainsCiphers) {
        ArrayList<Tuple> listMessCiphertextsForCipherOne = plainsCiphers;
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
