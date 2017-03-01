import java.util.HashMap;

/**
 * Created by aleksandrs on 2/26/17.
 */
public class DifferenceDistrTable extends Homework{

    /**
     * Given a u0, calculate v0^v1, assuming u0^u1=differential (Chosen plaintext attack)
     *
     * @param u0           Some message xored with the first key
     * @param differential Some differential
     * @param Sbox         A specified S box
     * @return v0^v1
     */
    static int get_v0_XOR_v1(int u0, int differential, HashMap<Integer, Integer> Sbox) {
        int u1 = u0 ^ differential;
        int v0 = Sbox.get(u0);
        int v1 = Sbox.get(u1);
        return v0 ^ v1;
    }

    /**
     * Count occurrences of every value for u0 - v0xorv1 type table (for a single differential)
     *
     * @param table Table of values for u0 - v0xorv1
     * @return HashMap with frequencies of every value
     */
    static HashMap<Integer, Integer> getFrequencies(HashMap<Integer, Integer> table) {
        HashMap<Integer, Integer> frequencyMap = new HashMap<>();
        for (int i = 0; i <= 0xf; i++) {
            frequencyMap.put(i, 0);
        }
        for (Integer value : table.values()) {
            int count = 0;
            for (Integer value2 : table.values()) {
                if (value.equals(value2)) {
                    count++;
                }
            }

            frequencyMap.put(value, count);
        }
        return frequencyMap;
    }

    /**
     * Get the difference distribution table for an S box
     *
     * @param Sbox Some S box
     * @return Difference distribution table
     */
    static HashMap<Integer, HashMap<Integer, Integer>> getDifferenceTable(HashMap<Integer, Integer> Sbox) {

        //A table with all the differentials
        HashMap<Integer, HashMap<Integer, Integer>> differenceTable = new HashMap<>();
        //for all differentials do
        for (int differential = 0; differential <= 0xf; differential++) {
            //A table for one differential
            HashMap<Integer, Integer> tableForOne = new HashMap<>();
            for (int u0 = 0; u0 <= 0xf; u0++) {
                tableForOne.put(u0, get_v0_XOR_v1(u0, differential, Sbox));
            }
            HashMap<Integer, Integer> frequencyMap = getFrequencies(tableForOne);
            differenceTable.put(differential, frequencyMap);
        }
        return differenceTable;
    }

//debugging (printing difference distribution table)
//    public static void main(String[] args) {
//        System.out.println("PRINTING DIFFERENCE MAP ");
//        HashMap<Integer, HashMap<Integer, Integer>> differenceTable = getDifferenceTable();
//        System.out.print(" ");
//        for (int i = 0; i <= 0xf; i++) {
//            System.out.print(" " + String.format("%x", i));
//        }
//        for (Integer key : differenceTable.keySet()) {
//            System.out.println();
//            System.out.print(String.format("%x", key) + "|");
//
//            for (int i = 0; i <= 0xf; i++) {
//                System.out.print(differenceTable.get(key).get(i) + " ");
//            }
//        }
//    }

}
