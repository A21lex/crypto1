public class Tuple<K, V> {

    private final K elem1;
    private final V elem2;


    public Tuple(K elem1, V elem2) {
        this.elem1 = elem1;
        this.elem2 = elem2;
    }

    public K get1() {
        return elem1;
    }

    public V get2() {
        return elem2;
    }

    public String toString() {
        return elem1.toString() + " " + elem2.toString();
    }

}