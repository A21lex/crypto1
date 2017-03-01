import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by aleksandrs on 3/1/17.
 *
 * Class for storing common information known about the first 2 exercises, namely the S box and
 * its inverse permutation
 */
public class Homework {
    //S box
    static HashMap<Integer, Integer> S = new HashMap<Integer, Integer>() {{
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
    static Map<Integer, Integer> reverseS =
            S.entrySet()
                    .stream()
                    .collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

}
