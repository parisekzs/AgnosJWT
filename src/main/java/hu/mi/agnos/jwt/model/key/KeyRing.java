/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.agnos.jwt.model.key;

import java.util.ArrayList;

/**
 *
 * @author parisek
 */
public class KeyRing extends ArrayList<Key> {

    private final int maxSize;

    public KeyRing(int maxSize) {
        super();
        this.maxSize = maxSize;
    }

    public KeyRing(int maxSize, String keyRingString) {
        this(maxSize);
        for (String key : keyRingString.split(",")) {
            this.add(new Key(key));
        }
    }

    public Key getFirstKey(){
        return this.get(0);
    }
    
    public void addKey(Key key) {
        this.add(0, key);
        if (this.size() > this.maxSize) {
            this.remove(this.size() - 1);
        }
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        for (Key key : this) {
            result
                    .append(key.toString())
                    .append(",");
        }
        return result.substring(0, result.length()-1);
    }

}
