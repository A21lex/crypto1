import java.util.HashMap;

/**
 * Created by aleksandrs on 2/26/17.
 */
public class DifferenceDistrTable {

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
     * Get the difference table for an S box
     *
     * @return Difference table
     */
    static HashMap<Integer, HashMap<Integer, Integer>> getDifferenceTable() {

        //A table with all the differentials
        HashMap<Integer, HashMap<Integer, Integer>> differenceTable = new HashMap<>();
        //for all differentials do
        for (int differential = 0; differential <= 0xf; differential++) {
            //A table for one differential
            HashMap<Integer, Integer> tableForOne = new HashMap<>();
            for (int u0 = 0; u0 <= 0xf; u0++) {
                tableForOne.put(u0, get_v0_XOR_v1(u0, differential));
            }
            HashMap<Integer, Integer> frequencyMap = getFrequencies(tableForOne);
            differenceTable.put(differential, frequencyMap);

        }
        return differenceTable;
    }

    public static void main(String[] args) {
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
    }

}
